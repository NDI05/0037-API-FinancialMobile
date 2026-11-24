package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"
)

// ErrGoogleIdentityNotLinked means the verified Google identity is not linked to any account. SSO
// never creates accounts: an unknown identity is a client error, not an invitation to register.
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
