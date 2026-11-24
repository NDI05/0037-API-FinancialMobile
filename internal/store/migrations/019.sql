-- Migration 019 (018 is reserved by the retention lane). One open DELTA job per owner.
-- Push bursts and the periodic worker can race between EnsureGmailDeltaJob's SELECT and
-- INSERT; the partial unique index makes the database the arbiter so two writers never
-- contend over the same history cursor.
UPDATE gmail_sync_jobs SET state = 'FAILED', last_error_code = 'superseded'
  WHERE kind = 'DELTA' AND state IN ('CREATED', 'RUNNING')
    AND rowid NOT IN (
      SELECT MAX(rowid) FROM gmail_sync_jobs
      WHERE kind = 'DELTA' AND state IN ('CREATED', 'RUNNING')
      GROUP BY owner_id
    );
CREATE UNIQUE INDEX IF NOT EXISTS idx_gmail_sync_jobs_open_delta
  ON gmail_sync_jobs(owner_id) WHERE kind = 'DELTA' AND state IN ('CREATED', 'RUNNING');
