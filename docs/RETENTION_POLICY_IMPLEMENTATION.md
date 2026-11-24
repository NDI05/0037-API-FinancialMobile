# Retention Policy Implementation (CR-005)

Financial data is retained for a rolling **one-year** window. Everything newer than the window is
served normally; anything older is **outside the retention policy** and is either rejected with a safe
`400 outside_retention` (for date-scoped requests) or removed by the scheduled cleanup. The policy is
implemented once and shared by every financial endpoint.

## 1. Window definition

| Rule | Value |
| --- | --- |
| Time zone | `Asia/Jakarta` (WIB, fixed UTC+7) |
| Start | `now - 1 calendar year`, at **WIB start of day** (`00:00:00 WIB`) |
| End | `now` (the exact request/sweep instant) |
| Leap day | A start date of Feb 29 clamps to Feb 28 in a non-leap target year |
| Inclusive | A row exactly at `start` is retained; one millisecond before it is outside |
| Month ids | `YYYY-MM` in WIB; the boundary month is **partially** retained |

Single implementation: [`internal/retention/policy.go`](../internal/retention/policy.go)
(`NewWindow`, `Contains`, `ValidateEventAt`, `ValidateMonth`, `Expired`, `ValidateNotExpired`,
`ClampMonthStart`, `StartMonthID`, `ExpiredBeforeMonthID`, `StartMillis`). Store and HTTP layers both
use it, so the time zone and boundary arithmetic cannot drift apart.

Boundary-month behavior: a request for the month that contains `start` is accepted (not a 4xx), and
store reads clamp their lower bound to `start`. Rows earlier than `start` inside that month are
excluded from lists/aggregates but are **not** deleted until the whole month has expired
(`month_id < startMonthId`).

## 2. Guarded endpoints

Date/period-scoped requests are rejected with `400 outside_retention` when the requested period is
fully outside the window or starts in the future:

- `GET /v1/transactions?month=YYYY-MM`
- `GET|PUT /v1/summaries/{month}`
- `GET|POST /v1/analyses` (analysis month)
- `POST /v1/import-jobs` (job month) and `POST /v1/import-jobs/{id}/batches` (job month and each
  `PARSED` candidate's `eventAt`)
- `POST /v1/transactions` when `eventAt` is older than the window (import/backfill is bounded)
- Lampiran transaksi (`/v1/attachments*`) **dipensiunkan CR-008**: route tidak terdaftar dan
  menjawab `404`, sehingga guard HTTP untuk metadata lampiran tidak lagi berlaku. Baris
  `attachments` lama tetap disimpan tanpa dihapus; guard retensi untuk data transaksi turunannya
  tetap berlaku di jalur yang masih aktif.
- `GET /v1/import-jobs/{id}` when the job's month is outside the window

The error uses the standard envelope with `retryable:false` and an extra `retention` object
(`windowStart`, `windowEnd`, `startMonthId`, `endMonthId`, `timezone`, `months`). The window is also
discoverable through `GET /v1/retention` (authenticated, owner-scoped, no financial rows).

Deliberate exemptions and decisions:

- **Budget plan / FR-42 is not touched.** `budget_plans`/`budget_limits` are never guarded by
  retention checks and never deleted by the sweep; budget behavior is unchanged.
- Future-dated **manual** entries keep their previous behavior for create/read: the direct
  transaction read path only enforces the **lower** bound (`eventAt < windowStart`), so a future
  event date that already existed keeps working. Period endpoints still reject future months.
- Direct transaction reads (`GET /v1/transactions/{id}`) only enforce the lower bound, because
  cleanup is what actually removes fully expired rows. Attachment metadata resolved by id enforces
  the same one-year window as its list/create paths; an attachment whose transaction is already
  gone is treated as expired metadata (`404`). The helper also has a defensive branch for an
  attachment without a transaction, but the current schema makes that state unreachable
  (`attachments.transaction_id` is `NOT NULL`, migration 015); the branch is kept only so a future
  device-only attachment type cannot silently bypass the window.
- Device-side attachment blobs are never deleted server-side; the sweep only removes metadata rows.
- Any DB failure remains a 5xx; retention checks never mask an infrastructure error as 4xx.

## 3. Eligible check and cleanup

Store operations: [`internal/store/retention.go`](../internal/store/retention.go)

- `PlanRetention(ctx, now)` — read-only counts in a rolled-back transaction (used by tests/operators).
- `SweepRetention(ctx, now, mode)` — counts in one transaction, deletes only in `DELETE` mode, then
  writes one audit row to `retention_sweeps`.

Eligible rows:

| Table | Eligibility |
| --- | --- |
| `transactions` | `event_at_ms < startMillis` |
| `attachments` | attached to an expired transaction |
| `summaries`, `analyses`, `import_jobs`, `import_batches`, `import_skipped` | `month_id < startMonthId` |
| `category_jobs` | attached to an expired transaction, or orphaned (no matching owner transaction) |
| `category_cache` | `updated_at` older than the window start |

Deletion order protects foreign keys (attachments → category jobs → import children → import jobs →
analyses → summaries → cache), then unlinks retained refunds that reference an expired original, and
creates the audit row in the same transaction. Rows exactly at the boundary are retained.

Audit table: [`internal/store/migrations/018.sql`](../internal/store/migrations/018.sql)
(`retention_sweeps`; mode `REPORT_ONLY|DELETE`, status, window, timestamps, `counts_json`, error code).
It stores **aggregate counts only** — no owner ids, transaction ids, labels, amounts, emails, tokens or
attachment paths. The migration is additive and numbered after the Gmail API migration `017`.

### Dry run vs execution

- **Default is report-only.** `RETENTION_SWEEP_ENABLED=true` only schedules report-only runs; a
  completed run writes an audit row and deletes nothing. An aborted run writes a best-effort
  `FAILED` audit row (mode/window/timestamps/status and a safe error code, no counts and no PII);
  the `COMPLETED` row still shares the deletion transaction, so a failure cannot leave partial
  deletes behind.
- Deletion requires **all** of: `RETENTION_DELETE_ENABLED=true`, `INTERNAL_SWEEP_TOKEN` configured
  (`config.Load` fails closed otherwise), and for the manual endpoint an explicit
  `?mode=delete&confirm=RETENTION_DELETE`.
- Manual endpoint: `POST /v1/internal/retention-sweep` (`x-internal-token`). No token configured → 404;
  wrong token → 401; delete disabled → 403 `retention_delete_disabled`; missing confirmation → 400
  `confirmation_required`; unknown mode → 400. Report-only accepts an empty mode or
  `mode=report|report-only|dry-run`. Response counts/`eligible` are aggregates; the header
  `X-Retention-Mode` reports the executed mode.
- Scheduled worker runs at startup and then on an interval; it selects `DELETE` only when deletion is
  enabled **and** a token is configured, otherwise report-only. Logs include counts/error codes only,
  never PII/PAN/email/owner ids/tokens.

## 4. Environment variables

| Variable | Default | Meaning |
| --- | --- | --- |
| `RETENTION_SWEEP_ENABLED` | `false` | Schedule the eligible check (report-only unless delete is enabled) |
| `RETENTION_DELETE_ENABLED` | `false` | Allow `DELETE` sweeps; requires `INTERNAL_SWEEP_TOKEN`, implies sweep enabled |
| `RETENTION_SWEEP_INTERVAL_HOURS` | `24` | Schedule interval; must be an integer `1..168` (malformed values fail startup) |
| `INTERNAL_SWEEP_TOKEN` | empty | Shared secret for `/v1/internal/sweep` and `/v1/internal/retention-sweep`; empty disables the endpoints (404) |

## 5. Tests

- `internal/retention/policy_test.go` — day/month/year boundaries, leap-day clamps (2024/2028/2004),
  exact window start/end in/out, future month rejection, month clamping.
- `internal/store/retention_test.go` — report-only deletes nothing but writes an audit row; delete
  removes only expired rows across all tables and keeps boundary rows, orphan cleanup, owner data stays
  owner-isolated, unknown mode rejected.
- `internal/httpapi/retention_guard_test.go` — expired/future periods return `400 outside_retention`
  (not 500) on list/summary/analysis/import/attachment paths; by-id and unfiltered-list attachment
  guards; expired import-job read; `GET /v1/retention`; internal sweep
  404/401/report-only/delete-gate/confirmation behavior.
- `internal/config/retention_test.go` — opt-in defaults, interval validation, delete-without-token
  fails closed, delete implies sweep.

## 6. Known limits / not done in this change

- **The cleanup has not been executed against real UAT data.** All verification used temporary
  `file:` SQLite databases; no real data was deleted. Enabling `RETENTION_SWEEP_ENABLED` (and
  especially `RETENTION_DELETE_ENABLED`) in UAT must be an explicit operator decision.
- No retention window applies to budgets (FR-42) or to account/session/audit rows.
- Soft-deleted rows within the window still exist; deletion is month/window based, not soft-delete
  purging.
- The sweep is global (all owners) and transactional, but there is no long-running chunking/backfill
  job: a very large first delete may take longer than one request; the scheduled worker has a 60s
  context bound.
- `retention_sweeps` has no automatic audit pruning; operational retention of audit rows is out of
  scope here.
