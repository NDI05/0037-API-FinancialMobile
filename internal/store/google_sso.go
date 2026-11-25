package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"
)

// ErrGoogleIdentityNotLinked means the verified Google identity is not linked to any account yet.
// Direct SSO resolves it by auto-linking to the account that owns the same verified email or by
// provisioning a new USER account; the explicit /link route reports it as an unknown identity.
var ErrGoogleIdentityNotLinked = errors.New("google identity is not linked")

// ErrGoogleIdentityConflict means (issuer, subject) is already linked to another owner.
var ErrGoogleIdentityConflict = errors.New("google identity is linked to another account")

// ErrGoogleAlreadyLinked means the owner already linked a different Google identity.
var ErrGoogleAlreadyLinked = errors.New("account already has a google identity")

// ErrGoogleNonceInvalid covers unknown, expired and already-consumed nonces. The caller answers
// the same 401 as a bad token so a probe cannot tell the three cases apart.
var ErrGoogleNonceInvalid = errors.New("google sso nonce is invalid")

// GoogleIdentity is one verified Google account bound to a PAM owner.
type GoogleIdentity struct {
	Issuer      string
	Subject     string
	OwnerID     string
	Email       string
	CreatedAt   time.Time
	LastLoginAt time.Time
}

// CreateGoogleNonce stores a fresh login nonce. Expired rows are pruned first so the table stays
// bounded without a background sweeper; the insert itself is the only atomic requirement.
func (s *Store) CreateGoogleNonce(ctx context.Context, nonce string, expiresAt, now time.Time) error {
	if _, err := s.DB.ExecContext(ctx, `DELETE FROM google_sso_nonces WHERE expires_at <= ?`,
		nowString(now)); err != nil {
		return err
	}
	_, err := s.DB.ExecContext(ctx, `INSERT INTO google_sso_nonces (nonce, expires_at)
		VALUES (?, ?)`, nonce, nowString(expiresAt))
	return err
}

// ConsumeGoogleNonce marks a nonce used exactly once. The WHERE clause keeps the check and the
// write in one statement: concurrent requests can only ever see one row affected.
func (s *Store) ConsumeGoogleNonce(ctx context.Context, nonce string, now time.Time) error {
	result, err := s.DB.ExecContext(ctx, `UPDATE google_sso_nonces SET consumed_at = ?
		WHERE nonce = ? AND consumed_at IS NULL AND expires_at > ?`,
		nowString(now), nonce, nowString(now))
	if err != nil {
		return err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected != 1 {
		return ErrGoogleNonceInvalid
	}
	return nil
}

// FindGoogleIdentity resolves a verified identity to its owner. It returns ErrGoogleIdentityNotLinked
// when the identity was never linked, so login cannot fall back to email matching.
func (s *Store) FindGoogleIdentity(ctx context.Context, issuer, subject string) (GoogleIdentity, error) {
	row := s.DB.QueryRowContext(ctx, `SELECT issuer, subject, owner_id, COALESCE(email, ''),
		created_at, COALESCE(last_login_at, '') FROM google_identities
		WHERE issuer = ? AND subject = ?`, issuer, subject)
	return scanGoogleIdentity(row)
}

// GetGoogleIdentityByOwner returns the identity linked to an owner, or ErrGoogleIdentityNotLinked.
func (s *Store) GetGoogleIdentityByOwner(ctx context.Context, ownerID string) (GoogleIdentity, error) {
	row := s.DB.QueryRowContext(ctx, `SELECT issuer, subject, owner_id, COALESCE(email, ''),
		created_at, COALESCE(last_login_at, '') FROM google_identities WHERE owner_id = ?`, ownerID)
	return scanGoogleIdentity(row)
}

func scanGoogleIdentity(row *sql.Row) (GoogleIdentity, error) {
	var identity GoogleIdentity
	var createdAt, lastLoginAt string
	if err := row.Scan(&identity.Issuer, &identity.Subject, &identity.OwnerID, &identity.Email,
		&createdAt, &lastLoginAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return GoogleIdentity{}, ErrGoogleIdentityNotLinked
		}
		return GoogleIdentity{}, err
	}
	identity.CreatedAt = parseTime(createdAt)
	identity.LastLoginAt = parseTime(lastLoginAt)
	return identity, nil
}

// LinkGoogleIdentity binds a verified identity to the authenticated owner. It is idempotent when
// the same (issuer, subject) is already linked to that owner; a different identity for the same
// owner and an identity owned by someone else are both conflicts. The insert and its uniqueness
// checks run in one transaction so two concurrent links cannot both pass the pre-check.
func (s *Store) LinkGoogleIdentity(ctx context.Context, ownerID, issuer, subject, email string,
	now time.Time) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var linkedIssuer, linkedSubject string
	err = tx.QueryRowContext(ctx, `SELECT issuer, subject FROM google_identities WHERE owner_id = ?`,
		ownerID).Scan(&linkedIssuer, &linkedSubject)
	if err == nil {
		if linkedIssuer == issuer && linkedSubject == subject {
			return nil // idempotent relink of the same identity
		}
		return ErrGoogleAlreadyLinked
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO google_identities
		(issuer, subject, owner_id, email, created_at, last_login_at)
		VALUES (?, ?, ?, ?, ?, ?)`,
		issuer, subject, ownerID, nullString(email), nowString(now), nowString(now))
	if err != nil {
		ownerConflict, identityConflict := googleLinkUniqueViolation(err.Error())
		if !ownerConflict && !identityConflict {
			return err
		}
		// The transaction is aborted after a constraint failure on some engines; resolve the
		// loser from the committed winner instead of returning a 500.
		_ = tx.Rollback()
		existing, findErr := s.FindGoogleIdentity(ctx, issuer, subject)
		if findErr == nil && existing.OwnerID == ownerID {
			return nil // concurrent duplicate of the same idempotent link
		}
		if findErr != nil && !errors.Is(findErr, ErrGoogleIdentityNotLinked) {
			return findErr
		}
		// The PK conflict is checked first: if this identity belongs to another owner, that is the
		// more specific conflict even when our owner also raced a different identity in.
		if identityConflict {
			return ErrGoogleIdentityConflict
		}
		return ErrGoogleAlreadyLinked
	}
	return tx.Commit()
}

// googleLinkUniqueViolation classifies a link INSERT failure by the column named in the engine
// error. Both SQLite and libSQL name the offending columns, e.g.
// "UNIQUE constraint failed: google_identities.owner_id" for a second identity on one owner, or
// "UNIQUE constraint failed: google_identities.issuer, google_identities.subject" for a claimed
// identity. Matching the column avoids reporting the owner race as ErrGoogleIdentityNotLinked,
// which used to surface as a 500. When an engine omits the columns the error is not classified and
// returned to the caller unchanged.
func googleLinkUniqueViolation(errorString string) (ownerConflict, identityConflict bool) {
	if !isUnique(errorString) {
		return false, false
	}
	lower := strings.ToLower(errorString)
	return strings.Contains(lower, "google_identities.owner_id"),
		strings.Contains(lower, "google_identities.issuer") ||
			strings.Contains(lower, "google_identities.subject")
}

// TouchGoogleIdentity records a successful SSO login. It is best-effort bookkeeping; the caller
// must not fail an otherwise valid session when this write fails.
func (s *Store) TouchGoogleIdentity(ctx context.Context, issuer, subject string, now time.Time) error {
	_, err := s.DB.ExecContext(ctx, `UPDATE google_identities SET last_login_at = ?
		WHERE issuer = ? AND subject = ?`, nowString(now), issuer, subject)
	return err
}

// GoogleLinked reports whether the owner has a linked Google identity. /v1/me needs only the
// boolean, so it avoids decoding the row.
func (s *Store) GoogleLinked(ctx context.Context, ownerID string) (bool, error) {
	var exists int
	err := s.DB.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM google_identities WHERE owner_id = ?)`,
		ownerID).Scan(&exists)
	if err != nil {
		return false, err
	}
	return exists == 1, nil
}

// GoogleLoginResult is the outcome of a direct Google SSO login. Created reports that this login
// provisioned a brand-new USER account.
type GoogleLoginResult struct {
	Account Account
	Created bool
}

// FindOrCreateAccountForGoogle resolves a verified Google identity to its PAM account. When the
// identity is already linked the linked account is returned unchanged. Otherwise the identity is
// linked to the account that owns the same verified email, or a fresh USER account is provisioned
// when no account owns the email. The write paths are transactional so an account never exists
// without its identity, and the caller must pass the verified email (never a raw claim).
//
// The email owner is the only auto-link target. A PAM account that already has a different Google
// identity is a conflict, so a same-email Google login can never re-point an existing link.
// Concurrent first logins are resolved by re-reading after a unique violation: the winner's row is
// reused, so a Google identity can never create two accounts and a race can never mint an orphan.
func (s *Store) FindOrCreateAccountForGoogle(ctx context.Context, issuer, subject, email,
	displayName string, digest PasswordDigest, now time.Time) (GoogleLoginResult, error) {
	issuer = strings.TrimSpace(issuer)
	subject = strings.TrimSpace(subject)
	email = NormalizeEmail(email)
	displayName = strings.TrimSpace(displayName)
	if issuer == "" || subject == "" || email == "" {
		return GoogleLoginResult{}, errors.New("google issuer, subject and verified email are required")
	}
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		result, err := s.findOrCreateGoogleAccountTx(ctx, issuer, subject, email, displayName,
			digest, now)
		if err == nil {
			return result, nil
		}
		lastErr = err
		if !isUnique(err.Error()) && !errors.Is(err, ErrEmailExists) {
			return GoogleLoginResult{}, err
		}
		// Another writer won a unique constraint. If our identity is linked now, its account is the
		// answer; if only the email appeared, the next attempt links to it instead of re-inserting.
		identity, findErr := s.FindGoogleIdentity(ctx, issuer, subject)
		if findErr == nil {
			account, err := s.FindAccountByOwner(ctx, identity.OwnerID)
			if err != nil {
				return GoogleLoginResult{}, err
			}
			return GoogleLoginResult{Account: account}, nil
		}
		if !errors.Is(findErr, ErrGoogleIdentityNotLinked) {
			return GoogleLoginResult{}, findErr
		}
		if _, emailErr := s.FindAccountByEmail(ctx, email); emailErr != nil &&
			!errors.Is(emailErr, ErrNotFound) {
			return GoogleLoginResult{}, emailErr
		}
	}
	return GoogleLoginResult{}, lastErr
}

// findOrCreateGoogleAccountTx is one transactional attempt of FindOrCreateAccountForGoogle.
// Unique violations are returned raw (except the account INSERT, which maps its own) so the caller
// can classify the race and retry from committed state.
func (s *Store) findOrCreateGoogleAccountTx(ctx context.Context, issuer, subject, email,
	displayName string, digest PasswordDigest, now time.Time) (GoogleLoginResult, error) {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return GoogleLoginResult{}, err
	}
	defer func() { _ = tx.Rollback() }()

	var ownerID string
	err = tx.QueryRowContext(ctx, `SELECT owner_id FROM google_identities
		WHERE issuer = ? AND subject = ?`, issuer, subject).Scan(&ownerID)
	switch {
	case err == nil:
		account, err := scanAccount(tx.QueryRowContext(ctx,
			`SELECT `+accountSelectColumns+` FROM users WHERE owner_id = ?`, ownerID))
		if err != nil {
			return GoogleLoginResult{}, err
		}
		if err := tx.Commit(); err != nil {
			return GoogleLoginResult{}, err
		}
		return GoogleLoginResult{Account: account}, nil
	case !errors.Is(err, sql.ErrNoRows):
		return GoogleLoginResult{}, err
	}

	account, err := scanAccount(tx.QueryRowContext(ctx,
		`SELECT `+accountSelectColumns+` FROM users WHERE email = ?`, email))
	switch {
	case err == nil:
		var linkedIssuer, linkedSubject string
		err = tx.QueryRowContext(ctx, `SELECT issuer, subject FROM google_identities
			WHERE owner_id = ?`, account.OwnerID).Scan(&linkedIssuer, &linkedSubject)
		if err == nil {
			return GoogleLoginResult{}, ErrGoogleIdentityConflict
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return GoogleLoginResult{}, err
		}
		// An inactive account must not gain a link from a login the handler will refuse anyway.
		if account.Status != "ACTIVE" {
			return GoogleLoginResult{Account: account}, nil
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO google_identities
			(issuer, subject, owner_id, email, created_at, last_login_at)
			VALUES (?, ?, ?, ?, ?, ?)`,
			issuer, subject, account.OwnerID, email, nowString(now), nowString(now)); err != nil {
			return GoogleLoginResult{}, err
		}
	case errors.Is(err, ErrNotFound):
		ownerID, err := s.insertAccountTx(ctx, tx, email, displayName, digest, "USER", now)
		if err != nil {
			return GoogleLoginResult{}, err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO google_identities
			(issuer, subject, owner_id, email, created_at, last_login_at)
			VALUES (?, ?, ?, ?, ?, ?)`,
			issuer, subject, ownerID, email, nowString(now), nowString(now)); err != nil {
			return GoogleLoginResult{}, err
		}
		account, err = scanAccount(tx.QueryRowContext(ctx,
			`SELECT `+accountSelectColumns+` FROM users WHERE owner_id = ?`, ownerID))
		if err != nil {
			return GoogleLoginResult{}, err
		}
		if err := tx.Commit(); err != nil {
			return GoogleLoginResult{}, err
		}
		return GoogleLoginResult{Account: account, Created: true}, nil
	default:
		return GoogleLoginResult{}, err
	}
	if err := tx.Commit(); err != nil {
		return GoogleLoginResult{}, err
	}
	return GoogleLoginResult{Account: account}, nil
}
