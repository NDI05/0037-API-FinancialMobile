-- Gmail API connection, OAuth state, Pub/Sub push events and backfill/delta jobs.
--
-- The raw mailbox address, refresh token and pagination cursor never live in a plaintext column:
-- each is sealed with internal/crypto (AES-256-GCM, AAD purpose|owner|version). The address is
-- additionally indexed by a keyed hash so a Pub/Sub push (which only carries the mailbox address)
-- can be resolved to exactly one owner without storing the address in the clear.

CREATE TABLE gmail_connections (
  id                        TEXT PRIMARY KEY,
  owner_id                  TEXT NOT NULL UNIQUE REFERENCES users(owner_id) ON DELETE CASCADE,
  account_email_hash        TEXT NOT NULL UNIQUE,
  account_email_ciphertext  BLOB NOT NULL,
  account_email_iv          BLOB NOT NULL,
  account_email_tag         BLOB NOT NULL,
  account_email_key_version INTEGER NOT NULL,
  scope                     TEXT NOT NULL,
  state                     TEXT NOT NULL CHECK (state IN ('ACTIVE', 'DISCONNECTED', 'REVOKED')),
  refresh_token_ciphertext  BLOB,
  refresh_token_iv          BLOB,
  refresh_token_tag         BLOB,
  refresh_token_key_version INTEGER,
  watch_expires_at          TEXT,
  history_cursor            TEXT,
  sync_state                TEXT NOT NULL DEFAULT 'idle'
                            CHECK (sync_state IN ('idle', 'backfill', 'delta', 'error')),
  last_sync_at              TEXT,
  last_error_code           TEXT,
  connected_at              TEXT NOT NULL,
  updated_at                TEXT NOT NULL,
  disconnected_at           TEXT
);

CREATE INDEX idx_gmail_connections_state ON gmail_connections(state, updated_at);

CREATE TABLE gmail_oauth_states (
  id                      TEXT PRIMARY KEY,
  state_hash              TEXT NOT NULL UNIQUE,
  owner_id                TEXT NOT NULL REFERENCES users(owner_id) ON DELETE CASCADE,
  code_verifier_ciphertext BLOB NOT NULL,
  code_verifier_iv        BLOB NOT NULL,
  code_verifier_tag       BLOB NOT NULL,
  code_verifier_key_version INTEGER NOT NULL,
  redirect_uri            TEXT NOT NULL,
  created_at              TEXT NOT NULL,
  expires_at              TEXT NOT NULL,
  consumed_at             TEXT
);

CREATE INDEX idx_gmail_oauth_states_expiry ON gmail_oauth_states(expires_at);

CREATE TABLE gmail_push_events (
  id                 TEXT PRIMARY KEY,
  event_key          TEXT NOT NULL UNIQUE,
  owner_id           TEXT NOT NULL REFERENCES users(owner_id) ON DELETE CASCADE,
  connection_id      TEXT NOT NULL REFERENCES gmail_connections(id) ON DELETE CASCADE,
  payload_ciphertext BLOB NOT NULL,
  payload_iv         BLOB NOT NULL,
  payload_tag        BLOB NOT NULL,
  payload_key_version INTEGER NOT NULL,
  published_at       TEXT,
  state              TEXT NOT NULL DEFAULT 'PENDING'
                     CHECK (state IN ('PENDING', 'PROCESSED', 'FAILED')),
  attempts           INTEGER NOT NULL DEFAULT 0,
  last_error_code    TEXT,
  created_at         TEXT NOT NULL,
  processed_at       TEXT
);

CREATE INDEX idx_gmail_push_events_pending ON gmail_push_events(state, created_at);

CREATE TABLE gmail_sync_jobs (
  id                      TEXT PRIMARY KEY,
  owner_id                TEXT NOT NULL REFERENCES users(owner_id) ON DELETE CASCADE,
  kind                    TEXT NOT NULL CHECK (kind IN ('BACKFILL', 'DELTA')),
  month_id                TEXT,
  state                   TEXT NOT NULL DEFAULT 'CREATED'
                          CHECK (state IN ('CREATED', 'RUNNING', 'COMPLETE', 'FAILED', 'NEEDS_REAUTH')),
  period_start            TEXT NOT NULL,
  period_end              TEXT NOT NULL,
  page_token_ciphertext   BLOB,
  page_token_iv           BLOB,
  page_token_tag          BLOB,
  page_token_key_version  INTEGER,
  seen_count              INTEGER NOT NULL DEFAULT 0,
  imported_count          INTEGER NOT NULL DEFAULT 0,
  duplicate_count         INTEGER NOT NULL DEFAULT 0,
  skipped_count           INTEGER NOT NULL DEFAULT 0,
  attempts                INTEGER NOT NULL DEFAULT 0,
  last_error_code         TEXT,
  created_at              TEXT NOT NULL,
  updated_at              TEXT NOT NULL,
  finished_at             TEXT
);

CREATE UNIQUE INDEX idx_gmail_sync_jobs_backfill_month
  ON gmail_sync_jobs(owner_id, month_id) WHERE kind = 'BACKFILL';

CREATE INDEX idx_gmail_sync_jobs_open ON gmail_sync_jobs(owner_id, kind, state, created_at);
