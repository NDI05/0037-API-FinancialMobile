-- Google SSO: linked identities and single-use login nonces.
--
-- The legacy users.google_sub column was dropped in 002 when Google Sign-In was removed, so
-- re-introducing SSO needs an explicit link table. (issuer, subject) is the natural Google
-- identity; UNIQUE(owner_id) keeps one Google account per PAM account. Deleting a user cascades
-- to its identity so a deleted account can never be resurrected by an old Google token.
CREATE TABLE google_identities (
  issuer        TEXT NOT NULL,
  subject       TEXT NOT NULL,
  owner_id      TEXT NOT NULL REFERENCES users(owner_id) ON DELETE CASCADE,
  email         TEXT,
  created_at    TEXT NOT NULL,
  last_login_at TEXT,
  PRIMARY KEY (issuer, subject),
  UNIQUE (owner_id)
);

-- Nonces are pre-login material: they are not owner-scoped, expire quickly and are consumed by
-- the first successful redemption. Rows are kept after consumption so a replay is rejected
-- deterministically instead of depending on deletion timing.
CREATE TABLE google_sso_nonces (
  nonce       TEXT PRIMARY KEY,
  expires_at  TEXT NOT NULL,
  consumed_at TEXT
);
CREATE INDEX idx_google_sso_nonces_expires ON google_sso_nonces(expires_at);
