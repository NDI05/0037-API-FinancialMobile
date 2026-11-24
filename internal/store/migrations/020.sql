-- Gmail API v2 (polling mode, manual sync queue, status progress).
--
-- Additive only: every column is nullable or has a default, so a database upgraded from 019 keeps
-- its connections, cursors and jobs. The sealed access token lets the worker reuse one Google
-- token until shortly before expiry instead of refreshing on every provider call; the raw token is
-- never stored in plaintext. The observability columns drive GET /v1/gmail/status without inventing
-- a second state machine: last_attempt_at/last_success_at stay derived facts, sync_requested_at is
-- the durable manual-sync queue marker and pages_done counts acknowledged messages.list pages.
ALTER TABLE gmail_connections ADD COLUMN access_token_ciphertext BLOB;
ALTER TABLE gmail_connections ADD COLUMN access_token_iv BLOB;
ALTER TABLE gmail_connections ADD COLUMN access_token_tag BLOB;
ALTER TABLE gmail_connections ADD COLUMN access_token_key_version INTEGER;
ALTER TABLE gmail_connections ADD COLUMN access_token_expires_at TEXT;
ALTER TABLE gmail_connections ADD COLUMN last_attempt_at TEXT;
ALTER TABLE gmail_connections ADD COLUMN last_success_at TEXT;
ALTER TABLE gmail_connections ADD COLUMN sync_requested_at TEXT;

ALTER TABLE gmail_sync_jobs ADD COLUMN pages_done INTEGER NOT NULL DEFAULT 0;
