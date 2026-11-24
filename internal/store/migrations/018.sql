-- Retention sweep audit (CR-005).
--
-- One row per eligible-check run, whether it is report-only or actually deleting. The row stores
-- aggregate counts only: no owner ids, transaction ids, merchant labels, amounts, emails, tokens or
-- attachment paths. That keeps the audit useful for operations without widening the PII/PAN scope,
-- and it means a report-only run is safe evidence that the schedule is alive.
CREATE TABLE retention_sweeps (
  id            TEXT PRIMARY KEY,
  mode          TEXT NOT NULL CHECK (mode IN ('REPORT_ONLY', 'DELETE')),
  window_start  TEXT NOT NULL,
  window_end    TEXT NOT NULL,
  started_at    TEXT NOT NULL,
  completed_at  TEXT NOT NULL,
  status        TEXT NOT NULL CHECK (status IN ('COMPLETED', 'FAILED')),
  counts_json   TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(counts_json)),
  error_code    TEXT
);

CREATE INDEX idx_retention_sweeps_started_at ON retention_sweeps(started_at DESC);
