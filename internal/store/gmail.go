package store

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/pam/recap/backend-go/internal/crypto"
)

// Gmail connection persistence.
//
// The mailbox address, refresh token, OAuth PKCE verifier, Pub/Sub payload and Gmail pagination
// token are all sealed with the same field format as the rest of the backend. The address also
// gets a keyed hash so the Pub/Sub push route can map an address to exactly one owner without a
// plaintext index.

var (
	ErrGmailStateInvalid = errors.New("gmail oauth state is invalid or already used")
	ErrGmailStateExpired = errors.New("gmail oauth state has expired")
	ErrGmailNotConnected = errors.New("gmail is not connected")
	ErrGmailMailboxTaken = errors.New("gmail mailbox is already linked to another account")
	ErrGmailJobExists    = errors.New("gmail sync job already exists")
	ErrGmailJobNotOpen   = errors.New("gmail sync job is not open")
)

const (
	gmailPurposeEmail       = "gmail_account_email"
	gmailPurposeRefresh     = "gmail_refresh_token"
	gmailPurposeVerifier    = "gmail_oauth_verifier"
	gmailPurposePush        = "gmail_push_payload"
	gmailPurposePageToken   = "gmail_page_token"
	gmailSyncStateIdle      = "idle"
	gmailSyncStateBackfill  = "backfill"
	gmailSyncStateDelta     = "delta"
	gmailSyncStateError     = "error"
	gmailConnectionActive   = "ACTIVE"
	gmailJobKindBackfill    = "BACKFILL"
	gmailJobKindDelta       = "DELTA"
	gmailPushEventPending   = "PENDING"
	gmailPushEventProcessed = "PROCESSED"
	gmailPushEventFailed    = "FAILED"
)

// GmailConnection is a decrypted server-side view. RefreshToken is never logged or serialized.
type GmailConnection struct {
	ID               string
	OwnerID          string
	AccountEmail     string
	AccountEmailHash string
	Scope            string
	State            string
	RefreshToken     string
	WatchExpiresAt   time.Time
	HistoryCursor    string
	SyncState        string
	LastSyncAt       time.Time
	LastErrorCode    string
	ConnectedAt      time.Time
	UpdatedAt        time.Time
}

type GmailConnectionInput struct {
	OwnerID        string
	AccountEmail   string
	Scope          string
	RefreshToken   string
	WatchExpiresAt time.Time
	HistoryCursor  string
	Now            time.Time
}

// GmailEmailHash is the keyed lookup index for the mailbox address.
func (s *Store) GmailEmailHash(email string) string {
	mac := hmac.New(sha256.New, s.DataKey)
	mac.Write([]byte("pam/gmail-email/v1"))
	mac.Write([]byte(NormalizeEmail(email)))
	return hex.EncodeToString(mac.Sum(nil))
}

func (s *Store) sealGmailValue(ownerID, purpose, plain string) (crypto.Sealed, error) {
	return crypto.Seal([]byte(plain), s.DataKey, s.KeyVersion, ownerID, purpose)
}

func (s *Store) openGmailValue(ownerID, purpose string, ciphertext, iv, tag []byte,
	keyVersion int64) (string, error) {
	plain, err := crypto.Open(crypto.Sealed{Ciphertext: ciphertext, IV: iv, Tag: tag,
		KeyVersion: int(keyVersion)}, s.DataKey, ownerID, purpose)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

// CreateGmailOAuthState stores a single-use state hash with the sealed PKCE verifier.
func (s *Store) CreateGmailOAuthState(ctx context.Context, ownerID, stateHash, codeVerifier,
	redirectURI string, expiresAt, now time.Time) error {
	if ownerID == "" || stateHash == "" || codeVerifier == "" || redirectURI == "" {
		return fmt.Errorf("gmail oauth state requires owner, state, verifier and redirect")
	}
	if !expiresAt.After(now) || expiresAt.Sub(now) > 10*time.Minute {
		return fmt.Errorf("gmail oauth state ttl must be at most 10 minutes")
	}
	sealed, err := s.sealGmailValue(ownerID, gmailPurposeVerifier, codeVerifier)
	if err != nil {
		return err
	}
	_, err = s.DB.ExecContext(ctx, `INSERT INTO gmail_oauth_states
		(id, state_hash, owner_id, code_verifier_ciphertext, code_verifier_iv, code_verifier_tag,
		 code_verifier_key_version, redirect_uri, created_at, expires_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		NewID("gos"), stateHash, ownerID, sealed.Ciphertext, sealed.IV, sealed.Tag,
		sealed.KeyVersion, redirectURI, nowString(now), nowString(expiresAt))
	return err
}

// ConsumeGmailOAuthState atomically marks the state used and returns the owner and PKCE
// verifier. Replays and expired states fail closed.
func (s *Store) ConsumeGmailOAuthState(ctx context.Context, stateHash string,
	now time.Time) (ownerID, codeVerifier, redirectURI string, err error) {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return "", "", "", err
	}
	defer func() { _ = tx.Rollback() }()
	var id, verifierCipher, verifierIV, verifierTag []byte
	var verifierVersion int64
	var expiresAt string
	var consumedAt sql.NullString
	err = tx.QueryRowContext(ctx, `SELECT id, owner_id, code_verifier_ciphertext,
		code_verifier_iv, code_verifier_tag, code_verifier_key_version, redirect_uri,
		expires_at, consumed_at FROM gmail_oauth_states WHERE state_hash = ?`, stateHash).Scan(
		&id, &ownerID, &verifierCipher, &verifierIV, &verifierTag, &verifierVersion,
		&redirectURI, &expiresAt, &consumedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return "", "", "", ErrGmailStateInvalid
	}
	if err != nil {
		return "", "", "", err
	}
	if consumedAt.Valid {
		return "", "", "", ErrGmailStateInvalid
	}
	if !parseTime(expiresAt).After(now) {
		return "", "", "", ErrGmailStateExpired
	}
	if _, err := tx.ExecContext(ctx, `UPDATE gmail_oauth_states SET consumed_at = ?
		WHERE state_hash = ? AND consumed_at IS NULL`, nowString(now), stateHash); err != nil {
		return "", "", "", err
	}
	verifier, err := s.openGmailValue(ownerID, gmailPurposeVerifier, verifierCipher, verifierIV,
		verifierTag, verifierVersion)
	if err != nil {
		return "", "", "", err
	}
	if err := tx.Commit(); err != nil {
		return "", "", "", err
	}
	return ownerID, verifier, redirectURI, nil
}

// SaveGmailConnection activates (or replaces) the single connection for an owner.
func (s *Store) SaveGmailConnection(ctx context.Context, input GmailConnectionInput) (GmailConnection, error) {
	emailHash := s.GmailEmailHash(input.AccountEmail)
	emailSealed, err := s.sealGmailValue(input.OwnerID, gmailPurposeEmail, input.AccountEmail)
	if err != nil {
		return GmailConnection{}, err
	}
	refreshSealed, err := s.sealGmailValue(input.OwnerID, gmailPurposeRefresh, input.RefreshToken)
	if err != nil {
		return GmailConnection{}, err
	}
	var taken int
	if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM gmail_connections
		WHERE account_email_hash = ? AND owner_id <> ?`, emailHash, input.OwnerID).Scan(&taken); err != nil {
		return GmailConnection{}, err
	}
	if taken > 0 {
		return GmailConnection{}, ErrGmailMailboxTaken
	}
	now := input.Now
	_, err = s.DB.ExecContext(ctx, `INSERT INTO gmail_connections
		(id, owner_id, account_email_hash, account_email_ciphertext, account_email_iv,
		 account_email_tag, account_email_key_version, scope, state, refresh_token_ciphertext,
		 refresh_token_iv, refresh_token_tag, refresh_token_key_version, watch_expires_at,
		 history_cursor, sync_state, connected_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'ACTIVE', ?, ?, ?, ?, ?, ?, 'idle', ?, ?)
		ON CONFLICT(owner_id) DO UPDATE SET
			account_email_hash = excluded.account_email_hash,
			account_email_ciphertext = excluded.account_email_ciphertext,
			account_email_iv = excluded.account_email_iv,
			account_email_tag = excluded.account_email_tag,
			account_email_key_version = excluded.account_email_key_version,
			scope = excluded.scope,
			state = 'ACTIVE',
			refresh_token_ciphertext = excluded.refresh_token_ciphertext,
			refresh_token_iv = excluded.refresh_token_iv,
			refresh_token_tag = excluded.refresh_token_tag,
			refresh_token_key_version = excluded.refresh_token_key_version,
			watch_expires_at = excluded.watch_expires_at,
			history_cursor = excluded.history_cursor,
			sync_state = 'idle',
			last_error_code = NULL,
			connected_at = excluded.connected_at,
			updated_at = excluded.updated_at,
			disconnected_at = NULL`,
		NewID("gmc"), input.OwnerID, emailHash, emailSealed.Ciphertext, emailSealed.IV,
		emailSealed.Tag, emailSealed.KeyVersion, input.Scope, refreshSealed.Ciphertext,
		refreshSealed.IV, refreshSealed.Tag, refreshSealed.KeyVersion,
		nullableTimeString(input.WatchExpiresAt), nullableString(input.HistoryCursor),
		nowString(now), nowString(now))
	if err != nil {
		return GmailConnection{}, err
	}
	return s.GetGmailConnection(ctx, input.OwnerID)
}

func (s *Store) GetGmailConnection(ctx context.Context, ownerID string) (GmailConnection, error) {
	row := s.DB.QueryRowContext(ctx, `SELECT id, owner_id, account_email_hash,
		account_email_ciphertext, account_email_iv, account_email_tag, account_email_key_version,
		scope, state, refresh_token_ciphertext, refresh_token_iv, refresh_token_tag,
		refresh_token_key_version, watch_expires_at, history_cursor, sync_state, last_sync_at,
		last_error_code, connected_at, updated_at
		FROM gmail_connections WHERE owner_id = ?`, ownerID)
	return s.scanGmailConnection(row)
}

// GmailConnectionByEmailHash resolves the owner for a Pub/Sub push. It only ever returns an
// ACTIVE connection, so a disconnected mailbox cannot reopen work.
func (s *Store) GmailConnectionByEmailHash(ctx context.Context, emailHash string) (GmailConnection, error) {
	row := s.DB.QueryRowContext(ctx, `SELECT id, owner_id, account_email_hash,
		account_email_ciphertext, account_email_iv, account_email_tag, account_email_key_version,
		scope, state, refresh_token_ciphertext, refresh_token_iv, refresh_token_tag,
		refresh_token_key_version, watch_expires_at, history_cursor, sync_state, last_sync_at,
		last_error_code, connected_at, updated_at
		FROM gmail_connections WHERE account_email_hash = ? AND state = 'ACTIVE'`, emailHash)
	return s.scanGmailConnection(row)
}

func (s *Store) scanGmailConnection(row *sql.Row) (GmailConnection, error) {
	var conn GmailConnection
	var emailCipher, emailIV, emailTag []byte
	var emailVersion int64
	var refreshCipher, refreshIV, refreshTag []byte
	var refreshVersion sql.NullInt64
	var watchExpires, lastSync sql.NullString
	var historyCursor, lastError sql.NullString
	var connectedAt, updatedAt string
	err := row.Scan(&conn.ID, &conn.OwnerID, &conn.AccountEmailHash, &emailCipher, &emailIV,
		&emailTag, &emailVersion, &conn.Scope, &conn.State, &refreshCipher, &refreshIV,
		&refreshTag, &refreshVersion, &watchExpires, &historyCursor, &conn.SyncState,
		&lastSync, &lastError, &connectedAt, &updatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return GmailConnection{}, ErrGmailNotConnected
	}
	if err != nil {
		return GmailConnection{}, err
	}
	conn.AccountEmail, err = s.openGmailValue(conn.OwnerID, gmailPurposeEmail, emailCipher,
		emailIV, emailTag, emailVersion)
	if err != nil {
		return GmailConnection{}, err
	}
	if refreshVersion.Valid && len(refreshCipher) > 0 {
		conn.RefreshToken, err = s.openGmailValue(conn.OwnerID, gmailPurposeRefresh,
			refreshCipher, refreshIV, refreshTag, refreshVersion.Int64)
		if err != nil {
			return GmailConnection{}, err
		}
	}
	if watchExpires.Valid {
		conn.WatchExpiresAt = parseTime(watchExpires.String)
	}
	if lastSync.Valid {
		conn.LastSyncAt = parseTime(lastSync.String)
	}
	conn.HistoryCursor = historyCursor.String
	conn.LastErrorCode = lastError.String
	conn.ConnectedAt = parseTime(connectedAt)
	conn.UpdatedAt = parseTime(updatedAt)
	return conn, nil
}

// UpdateGmailWatch stores the renewed watch deadline and, only when the cursor is still empty,
// the history cursor returned by users.watch.
func (s *Store) UpdateGmailWatch(ctx context.Context, ownerID string, expiresAt time.Time,
	historyID string, now time.Time) error {
	res, err := s.DB.ExecContext(ctx, `UPDATE gmail_connections
		SET watch_expires_at = ?, history_cursor = COALESCE(history_cursor, ?), updated_at = ?
		WHERE owner_id = ? AND state = 'ACTIVE'`,
		nullableTimeString(expiresAt), nullableString(historyID), nowString(now), ownerID)
	if err != nil {
		return err
	}
	if affected, _ := res.RowsAffected(); affected == 0 {
		return ErrGmailNotConnected
	}
	return nil
}

// UpdateGmailSyncState records the last sync outcome without leaking internal detail.
func (s *Store) UpdateGmailSyncState(ctx context.Context, ownerID, syncState, historyCursor,
	lastErrorCode string, lastSyncAt, now time.Time) error {
	if syncState != gmailSyncStateIdle && syncState != gmailSyncStateBackfill &&
		syncState != gmailSyncStateDelta && syncState != gmailSyncStateError {
		return fmt.Errorf("invalid gmail sync state")
	}
	_, err := s.DB.ExecContext(ctx, `UPDATE gmail_connections
		SET sync_state = ?, history_cursor = COALESCE(?, history_cursor),
			last_error_code = ?, last_sync_at = COALESCE(?, last_sync_at), updated_at = ?
		WHERE owner_id = ? AND state = 'ACTIVE'`,
		syncState, nullableString(historyCursor), nullableString(lastErrorCode),
		nullableTimeString(lastSyncAt), nowString(now), ownerID)
	return err
}

// DisconnectGmail clears credentials and stops future work. Transaction data is retained.
func (s *Store) DisconnectGmail(ctx context.Context, ownerID string, now time.Time) error {
	res, err := s.DB.ExecContext(ctx, `UPDATE gmail_connections
		SET state = 'DISCONNECTED', refresh_token_ciphertext = NULL, refresh_token_iv = NULL,
			refresh_token_tag = NULL, refresh_token_key_version = NULL, watch_expires_at = NULL,
			history_cursor = NULL, sync_state = 'idle', last_error_code = NULL,
			disconnected_at = ?, updated_at = ?
		WHERE owner_id = ? AND state = 'ACTIVE'`, nowString(now), nowString(now), ownerID)
	if err != nil {
		return err
	}
	if affected, _ := res.RowsAffected(); affected == 0 {
		return ErrGmailNotConnected
	}
	return nil
}

// ListActiveGmailConnections feeds the sync coordinator.
func (s *Store) ListActiveGmailConnections(ctx context.Context, limit int) ([]GmailConnection, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := s.DB.QueryContext(ctx, `SELECT id, owner_id, account_email_hash,
		account_email_ciphertext, account_email_iv, account_email_tag, account_email_key_version,
		scope, state, refresh_token_ciphertext, refresh_token_iv, refresh_token_tag,
		refresh_token_key_version, watch_expires_at, history_cursor, sync_state, last_sync_at,
		last_error_code, connected_at, updated_at
		FROM gmail_connections WHERE state = 'ACTIVE' ORDER BY updated_at ASC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	connections := make([]GmailConnection, 0, limit)
	for rows.Next() {
		var conn GmailConnection
		var emailCipher, emailIV, emailTag []byte
		var emailVersion int64
		var refreshCipher, refreshIV, refreshTag []byte
		var refreshVersion sql.NullInt64
		var watchExpires, lastSync sql.NullString
		var historyCursor, lastError sql.NullString
		var connectedAt, updatedAt string
		if err := rows.Scan(&conn.ID, &conn.OwnerID, &conn.AccountEmailHash, &emailCipher,
			&emailIV, &emailTag, &emailVersion, &conn.Scope, &conn.State, &refreshCipher,
			&refreshIV, &refreshTag, &refreshVersion, &watchExpires, &historyCursor,
			&conn.SyncState, &lastSync, &lastError, &connectedAt, &updatedAt); err != nil {
			return nil, err
		}
		conn.AccountEmail, err = s.openGmailValue(conn.OwnerID, gmailPurposeEmail, emailCipher,
			emailIV, emailTag, emailVersion)
		if err != nil {
			return nil, err
		}
		if refreshVersion.Valid && len(refreshCipher) > 0 {
			conn.RefreshToken, err = s.openGmailValue(conn.OwnerID, gmailPurposeRefresh,
				refreshCipher, refreshIV, refreshTag, refreshVersion.Int64)
			if err != nil {
				return nil, err
			}
		}
		if watchExpires.Valid {
			conn.WatchExpiresAt = parseTime(watchExpires.String)
		}
		if lastSync.Valid {
			conn.LastSyncAt = parseTime(lastSync.String)
		}
		conn.HistoryCursor = historyCursor.String
		conn.LastErrorCode = lastError.String
		conn.ConnectedAt = parseTime(connectedAt)
		conn.UpdatedAt = parseTime(updatedAt)
		connections = append(connections, conn)
	}
	return connections, rows.Err()
}

// GmailPushEvent is a durable record of one Pub/Sub notification.
type GmailPushEvent struct {
	ID            string
	OwnerID       string
	ConnectionID  string
	Payload       string
	PublishedAt   string
	State         string
	Attempts      int
	LastErrorCode string
}

// RecordGmailPushEvent stores one event; a duplicate event key is a no-op that reports false.
func (s *Store) RecordGmailPushEvent(ctx context.Context, ownerID, connectionID, eventKey,
	payload, publishedAt string, now time.Time) (bool, error) {
	sealed, err := s.sealGmailValue(ownerID, gmailPurposePush, payload)
	if err != nil {
		return false, err
	}
	res, err := s.DB.ExecContext(ctx, `INSERT INTO gmail_push_events
		(id, event_key, owner_id, connection_id, payload_ciphertext, payload_iv, payload_tag,
		 payload_key_version, published_at, state, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'PENDING', ?)
		ON CONFLICT(event_key) DO NOTHING`,
		NewID("gpe"), eventKey, ownerID, connectionID, sealed.Ciphertext, sealed.IV,
		sealed.Tag, sealed.KeyVersion, nullableString(publishedAt), nowString(now))
	if err != nil {
		return false, err
	}
	affected, _ := res.RowsAffected()
	return affected == 1, nil
}

// PendingGmailPushEvents returns events in arrival order for the coordinator.
func (s *Store) PendingGmailPushEvents(ctx context.Context, ownerID string, limit int) ([]GmailPushEvent, error) {
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	rows, err := s.DB.QueryContext(ctx, `SELECT id, owner_id, connection_id, payload_ciphertext,
		payload_iv, payload_tag, payload_key_version, published_at, state, attempts, last_error_code
		FROM gmail_push_events WHERE owner_id = ? AND state = 'PENDING'
		ORDER BY created_at ASC LIMIT ?`, ownerID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	events := make([]GmailPushEvent, 0, limit)
	for rows.Next() {
		var event GmailPushEvent
		var cipher, iv, tag []byte
		var keyVersion int64
		var published, lastError sql.NullString
		if err := rows.Scan(&event.ID, &event.OwnerID, &event.ConnectionID, &cipher, &iv, &tag,
			&keyVersion, &published, &event.State, &event.Attempts, &lastError); err != nil {
			return nil, err
		}
		event.PublishedAt = published.String
		event.LastErrorCode = lastError.String
		event.Payload, err = s.openGmailValue(event.OwnerID, gmailPurposePush, cipher, iv, tag,
			keyVersion)
		if err != nil {
			return nil, err
		}
		events = append(events, event)
	}
	return events, rows.Err()
}

// FinishGmailPushEvent marks an event processed or failed. It is idempotent.
func (s *Store) FinishGmailPushEvent(ctx context.Context, eventID, state, errorCode string,
	now time.Time) error {
	if state != gmailPushEventProcessed && state != gmailPushEventFailed {
		return fmt.Errorf("invalid gmail push event state")
	}
	_, err := s.DB.ExecContext(ctx, `UPDATE gmail_push_events
		SET state = ?, attempts = attempts + 1, last_error_code = ?, processed_at = ?
		WHERE id = ? AND state = 'PENDING'`,
		state, nullableString(errorCode), nowString(now), eventID)
	return err
}

// GmailSyncJob is one checkpointed backfill month or delta batch.
type GmailSyncJob struct {
	ID            string
	OwnerID       string
	Kind          string
	MonthID       string
	State         string
	PeriodStart   time.Time
	PeriodEnd     time.Time
	PageToken     string
	Seen          int
	Imported      int
	Duplicates    int
	Skipped       int
	Attempts      int
	LastErrorCode string
}

// EnsureGmailBackfillJob returns the existing job for the month or creates one.
func (s *Store) EnsureGmailBackfillJob(ctx context.Context, ownerID, monthID string,
	start, end, now time.Time) (GmailSyncJob, error) {
	job, err := s.gmailSyncJob(ctx, ownerID, gmailJobKindBackfill, monthID)
	if err == nil {
		// A failed or reauth-blocked month is retried with the same job row, keeping attempt counts.
		if job.State == "FAILED" || job.State == "NEEDS_REAUTH" {
			if _, resetErr := s.DB.ExecContext(ctx, `UPDATE gmail_sync_jobs
				SET state = 'CREATED', last_error_code = NULL, updated_at = ?
				WHERE owner_id = ? AND id = ?`, nowString(now), ownerID, job.ID); resetErr != nil {
				return GmailSyncJob{}, resetErr
			}
			return s.gmailSyncJob(ctx, ownerID, gmailJobKindBackfill, monthID)
		}
		return job, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return GmailSyncJob{}, err
	}
	_, err = s.DB.ExecContext(ctx, `INSERT INTO gmail_sync_jobs
		(id, owner_id, kind, month_id, state, period_start, period_end, created_at, updated_at)
		VALUES (?, ?, 'BACKFILL', ?, 'CREATED', ?, ?, ?, ?)`,
		NewID("gsj"), ownerID, monthID, nowString(start), nowString(end), nowString(now),
		nowString(now))
	if err != nil {
		if isUnique(err.Error()) {
			return s.gmailSyncJob(ctx, ownerID, gmailJobKindBackfill, monthID)
		}
		return GmailSyncJob{}, err
	}
	return s.gmailSyncJob(ctx, ownerID, gmailJobKindBackfill, monthID)
}

// OpenGmailDeltaJob returns the in-flight delta job, if any.
func (s *Store) OpenGmailDeltaJob(ctx context.Context, ownerID string) (GmailSyncJob, bool, error) {
	row := s.DB.QueryRowContext(ctx, `SELECT id, owner_id, kind, COALESCE(month_id, ''), state,
		period_start, period_end, page_token_ciphertext, page_token_iv, page_token_tag,
		page_token_key_version, seen_count, imported_count, duplicate_count, skipped_count,
		attempts, last_error_code FROM gmail_sync_jobs
		WHERE owner_id = ? AND kind = 'DELTA' AND state IN ('CREATED', 'RUNNING')
		ORDER BY created_at DESC LIMIT 1`, ownerID)
	job, err := s.scanGmailSyncJob(row)
	if errors.Is(err, sql.ErrNoRows) {
		return GmailSyncJob{}, false, nil
	}
	if err != nil {
		return GmailSyncJob{}, false, err
	}
	return job, true, nil
}

// EnsureGmailDeltaJob reuses one open delta job per owner, or creates one starting at cursor.
func (s *Store) EnsureGmailDeltaJob(ctx context.Context, ownerID string, start, end time.Time,
	now time.Time) (GmailSyncJob, error) {
	row := s.DB.QueryRowContext(ctx, `SELECT id, owner_id, kind, COALESCE(month_id, ''), state,
		period_start, period_end, page_token_ciphertext, page_token_iv, page_token_tag,
		page_token_key_version, seen_count, imported_count, duplicate_count, skipped_count,
		attempts, last_error_code FROM gmail_sync_jobs
		WHERE owner_id = ? AND kind = 'DELTA' AND state IN ('CREATED', 'RUNNING')
		ORDER BY created_at DESC LIMIT 1`, ownerID)
	job, err := s.scanGmailSyncJob(row)
	if err == nil {
		return job, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return GmailSyncJob{}, err
	}
	_, err = s.DB.ExecContext(ctx, `INSERT INTO gmail_sync_jobs
		(id, owner_id, kind, state, period_start, period_end, created_at, updated_at)
		VALUES (?, ?, 'DELTA', 'CREATED', ?, ?, ?, ?)`,
		NewID("gsj"), ownerID, nowString(start), nowString(end), nowString(now), nowString(now))
	if err != nil {
		return GmailSyncJob{}, err
	}
	row = s.DB.QueryRowContext(ctx, `SELECT id, owner_id, kind, COALESCE(month_id, ''), state,
		period_start, period_end, page_token_ciphertext, page_token_iv, page_token_tag,
		page_token_key_version, seen_count, imported_count, duplicate_count, skipped_count,
		attempts, last_error_code FROM gmail_sync_jobs
		WHERE owner_id = ? AND kind = 'DELTA' AND state IN ('CREATED', 'RUNNING')
		ORDER BY created_at DESC LIMIT 1`, ownerID)
	return s.scanGmailSyncJob(row)
}

func (s *Store) gmailSyncJob(ctx context.Context, ownerID, kind, monthID string) (GmailSyncJob, error) {
	row := s.DB.QueryRowContext(ctx, `SELECT id, owner_id, kind, COALESCE(month_id, ''), state,
		period_start, period_end, page_token_ciphertext, page_token_iv, page_token_tag,
		page_token_key_version, seen_count, imported_count, duplicate_count, skipped_count,
		attempts, last_error_code FROM gmail_sync_jobs
		WHERE owner_id = ? AND kind = ? AND COALESCE(month_id, '') = ?`,
		ownerID, kind, monthID)
	return s.scanGmailSyncJob(row)
}

func (s *Store) scanGmailSyncJob(row *sql.Row) (GmailSyncJob, error) {
	var job GmailSyncJob
	var periodStart, periodEnd string
	var pageCipher, pageIV, pageTag []byte
	var pageVersion sql.NullInt64
	var lastError sql.NullString
	err := row.Scan(&job.ID, &job.OwnerID, &job.Kind, &job.MonthID, &job.State, &periodStart,
		&periodEnd, &pageCipher, &pageIV, &pageTag, &pageVersion, &job.Seen, &job.Imported,
		&job.Duplicates, &job.Skipped, &job.Attempts, &lastError)
	if err != nil {
		return GmailSyncJob{}, err
	}
	job.PeriodStart = parseTime(periodStart)
	job.PeriodEnd = parseTime(periodEnd)
	job.LastErrorCode = lastError.String
	if pageVersion.Valid && len(pageCipher) > 0 {
		token, err := s.openGmailValue(job.OwnerID, gmailPurposePageToken, pageCipher, pageIV,
			pageTag, pageVersion.Int64)
		if err != nil {
			return GmailSyncJob{}, err
		}
		job.PageToken = token
	}
	return job, nil
}

// StartGmailSyncJob moves a job to RUNNING and bumps its attempt counter.
func (s *Store) StartGmailSyncJob(ctx context.Context, ownerID, jobID string, now time.Time) (GmailSyncJob, error) {
	res, err := s.DB.ExecContext(ctx, `UPDATE gmail_sync_jobs
		SET state = 'RUNNING', attempts = attempts + 1, updated_at = ?
		WHERE owner_id = ? AND id = ? AND state IN ('CREATED', 'RUNNING')`,
		nowString(now), ownerID, jobID)
	if err != nil {
		return GmailSyncJob{}, err
	}
	if affected, _ := res.RowsAffected(); affected == 0 {
		return GmailSyncJob{}, ErrGmailJobNotOpen
	}
	row := s.DB.QueryRowContext(ctx, `SELECT id, owner_id, kind, COALESCE(month_id, ''), state,
		period_start, period_end, page_token_ciphertext, page_token_iv, page_token_tag,
		page_token_key_version, seen_count, imported_count, duplicate_count, skipped_count,
		attempts, last_error_code FROM gmail_sync_jobs WHERE owner_id = ? AND id = ?`,
		ownerID, jobID)
	return s.scanGmailSyncJob(row)
}

// CheckpointGmailSyncJob persists the next page token only after the page was acknowledged by
// the ingest layer, so a crash mid-page re-reads rather than skips notifications.
func (s *Store) CheckpointGmailSyncJob(ctx context.Context, ownerID, jobID, pageToken string,
	seen, imported, duplicates, skipped int, now time.Time) error {
	var sealed crypto.Sealed
	var err error
	if pageToken != "" {
		sealed, err = s.sealGmailValue(ownerID, gmailPurposePageToken, pageToken)
		if err != nil {
			return err
		}
	}
	_, err = s.DB.ExecContext(ctx, `UPDATE gmail_sync_jobs SET
		page_token_ciphertext = ?, page_token_iv = ?, page_token_tag = ?,
		page_token_key_version = ?, seen_count = ?, imported_count = ?, duplicate_count = ?,
		skipped_count = ?, updated_at = ?
		WHERE owner_id = ? AND id = ? AND state = 'RUNNING'`,
		nullableBytes(sealed.Ciphertext), nullableBytes(sealed.IV), nullableBytes(sealed.Tag),
		nullableKeyVersion(sealed.KeyVersion), seen, imported, duplicates, skipped,
		nowString(now), ownerID, jobID)
	return err
}

// FinishGmailSyncJob closes a job; a failed job keeps its page token for retry.
func (s *Store) FinishGmailSyncJob(ctx context.Context, ownerID, jobID, state, errorCode string,
	now time.Time) error {
	switch state {
	case "COMPLETE", "FAILED", "NEEDS_REAUTH":
	default:
		return fmt.Errorf("invalid gmail sync job state")
	}
	_, err := s.DB.ExecContext(ctx, `UPDATE gmail_sync_jobs
		SET state = ?, last_error_code = ?, finished_at = ?, updated_at = ?
		WHERE owner_id = ? AND id = ?`, state, nullableString(errorCode), nowString(now),
		nowString(now), ownerID, jobID)
	return err
}

// CompletedGmailBackfillMonths reports which rolling-window months already finished cleanly.
func (s *Store) CompletedGmailBackfillMonths(ctx context.Context, ownerID string,
	since time.Time) (map[string]bool, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT month_id FROM gmail_sync_jobs
		WHERE owner_id = ? AND kind = 'BACKFILL' AND state = 'COMPLETE' AND month_id >= ?`,
		ownerID, monthIDFor(since))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	done := map[string]bool{}
	for rows.Next() {
		var month string
		if err := rows.Scan(&month); err != nil {
			return nil, err
		}
		done[month] = true
	}
	return done, rows.Err()
}

// IngestFingerprint exposes the server-side fingerprint for a server-parsed notification. The
// Gmail path never has a device fingerprint, so the coordinator derives the same keyed form from
// the mailbox reference and the parsed fields; re-import is still deduped by source_ref_hash.
func (s *Store) IngestFingerprint(sourceRef, merchantLabel, direction string, amountMinor int64,
	eventAt time.Time) string {
	return s.transactionFingerprint(sourceRef, amountMinor, eventAt.UnixMilli(), direction,
		merchantLabel)
}

// GmailSourceRef builds the opaque mailbox reference stored sealed for a Gmail API message:
// g:<mailbox hash prefix>:<message id>. The raw message id is never indexed in clear.
func GmailSourceRef(mailboxHash, messageID string) string {
	prefix := mailboxHash
	if len(prefix) > 16 {
		prefix = prefix[:16]
	}
	return "g:" + prefix + ":" + messageID
}

func nullableBytes(raw []byte) any {
	if len(raw) == 0 {
		return nil
	}
	return raw
}

func nullableKeyVersion(version int) any {
	if version == 0 {
		return nil
	}
	return version
}

func nullableTimeString(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return nowString(t)
}

// MarshalGmailPushPayload is a small helper so the coordinator and tests agree on the durable
// event encoding (it never reaches a log line).
func MarshalGmailPushPayload(payload map[string]string) (string, error) {
	raw, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	return string(raw), nil
}
