package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/pam/recap/backend-go/internal/retention"
)

// RetentionMode selects what a retention sweep run is allowed to do. REPORT_ONLY is the default:
// it counts eligible rows and writes the audit row without deleting anything.
type RetentionMode string

const (
	RetentionReportOnly RetentionMode = "REPORT_ONLY"
	RetentionDelete     RetentionMode = "DELETE"
)

func (m RetentionMode) Valid() bool {
	return m == RetentionReportOnly || m == RetentionDelete
}

func (m RetentionMode) Deletes() bool { return m == RetentionDelete }

// RetentionCounts is the eligibility picture for one sweep run. Counts are aggregate only and are
// safe to log or persist: they never include owner ids, transaction ids, amounts or labels.
type RetentionCounts struct {
	Transactions  int `json:"transactions"`
	Attachments   int `json:"attachments"`
	Summaries     int `json:"summaries"`
	Analyses      int `json:"analyses"`
	CategoryJobs  int `json:"categoryJobs"`
	CategoryCache int `json:"categoryCache"`
	ImportJobs    int `json:"importJobs"`
	ImportBatches int `json:"importBatches"`
	ImportSkipped int `json:"importSkipped"`
}

// Total is the number of rows across every eligible table.
func (c RetentionCounts) Total() int {
	return c.Transactions + c.Attachments + c.Summaries + c.Analyses + c.CategoryJobs +
		c.CategoryCache + c.ImportJobs + c.ImportBatches + c.ImportSkipped
}

// RetentionSweepResult is what the scheduled worker and the internal endpoint report.
type RetentionSweepResult struct {
	ID          string
	Mode        RetentionMode
	WindowStart time.Time
	WindowEnd   time.Time
	Counts      RetentionCounts
	StartedAt   time.Time
	CompletedAt time.Time
}

// PlanRetention counts the financial rows currently outside the one-year policy without writing
// anything. It is a read-only check, useful for tests and for an operator dry run.
func (s *Store) PlanRetention(ctx context.Context, now time.Time) (RetentionCounts, error) {
	window := retention.NewWindow(now)
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return RetentionCounts{}, err
	}
	defer func() { _ = tx.Rollback() }()
	return queryRetentionCounts(ctx, tx, window)
}

// SweepRetention runs one eligible check and records the outcome in retention_sweeps.
//
// Report-only is the default and never deletes financial rows. DELETE removes only rows that are
// fully outside the one-year window; the boundary month and transactions exactly on the window
// start are retained. The caller is responsible for the authorization gate (internal token plus an
// explicit operator flag), because the store has no request context.
func (s *Store) SweepRetention(ctx context.Context, now time.Time, mode RetentionMode) (RetentionSweepResult, error) {
	if !mode.Valid() {
		return RetentionSweepResult{}, fmt.Errorf("invalid retention mode %q", mode)
	}
	window := retention.NewWindow(now)
	startedAt := s.clock()
	result := RetentionSweepResult{
		Mode:        mode,
		WindowStart: window.Start,
		WindowEnd:   window.End,
		StartedAt:   startedAt,
	}

	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return RetentionSweepResult{}, err
	}
	defer func() { _ = tx.Rollback() }()

	counts, err := queryRetentionCounts(ctx, tx, window)
	if err != nil {
		return RetentionSweepResult{}, err
	}
	result.Counts = counts
	if mode.Deletes() {
		if err := deleteExpired(ctx, tx, window); err != nil {
			return RetentionSweepResult{}, err
		}
	}

	result.CompletedAt = s.clock()
	result.ID = NewID("rsweep")
	countsJSON, err := json.Marshal(counts)
	if err != nil {
		return RetentionSweepResult{}, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO retention_sweeps
		(id, mode, window_start, window_end, started_at, completed_at, status, counts_json)
		VALUES (?, ?, ?, ?, ?, ?, 'COMPLETED', ?)`,
		result.ID, string(mode), nowString(window.Start), nowString(window.End),
		nowString(startedAt), nowString(result.CompletedAt), string(countsJSON)); err != nil {
		return RetentionSweepResult{}, err
	}
	if err := tx.Commit(); err != nil {
		return RetentionSweepResult{}, err
	}
	return result, nil
}

type retentionQuerier interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// Retention below is deliberately month-based for derivative tables. Every month_id strictly
// smaller than the WIB month of the window start is fully outside the window; the boundary month
// itself is partially retained and must survive.
func queryRetentionCounts(ctx context.Context, queryer retentionQuerier, window retention.Window) (RetentionCounts, error) {
	var counts RetentionCounts
	cutoffMillis := window.StartMillis()
	cutoffMonth := window.ExpiredBeforeMonthID()
	cutoffTime := nowString(window.Start)

	count := func(query string, args ...any) (int, error) {
		var value int
		err := queryer.QueryRowContext(ctx, query, args...).Scan(&value)
		return value, err
	}

	steps := []struct {
		value *int
		query string
		args  []any
	}{
		{&counts.Transactions,
			`SELECT COUNT(*) FROM transactions WHERE event_at_ms < ?`, []any{cutoffMillis}},
		{&counts.Attachments,
			`SELECT COUNT(*) FROM attachments WHERE transaction_id IN
			   (SELECT id FROM transactions WHERE event_at_ms < ?)`, []any{cutoffMillis}},
		{&counts.Summaries,
			`SELECT COUNT(*) FROM summaries WHERE month_id < ?`, []any{cutoffMonth}},
		{&counts.Analyses,
			`SELECT COUNT(*) FROM analyses WHERE month_id < ?`, []any{cutoffMonth}},
		{&counts.CategoryJobs,
			`SELECT COUNT(*) FROM category_jobs
			 WHERE transaction_id IN (SELECT id FROM transactions WHERE event_at_ms < ?)
			    OR NOT EXISTS (SELECT 1 FROM transactions t
			                   WHERE t.id = category_jobs.transaction_id
			                     AND t.owner_id = category_jobs.owner_id)`, []any{cutoffMillis}},
		{&counts.CategoryCache,
			`SELECT COUNT(*) FROM category_cache WHERE julianday(updated_at) < julianday(?)`,
			[]any{cutoffTime}},
		{&counts.ImportJobs,
			`SELECT COUNT(*) FROM import_jobs WHERE month_id < ?`, []any{cutoffMonth}},
		{&counts.ImportBatches,
			`SELECT COUNT(*) FROM import_batches WHERE job_id IN
			   (SELECT id FROM import_jobs WHERE month_id < ?)`, []any{cutoffMonth}},
		{&counts.ImportSkipped,
			`SELECT COUNT(*) FROM import_skipped WHERE job_id IN
			   (SELECT id FROM import_jobs WHERE month_id < ?)`, []any{cutoffMonth}},
	}
	for _, step := range steps {
		value, err := count(step.query, step.args...)
		if err != nil {
			return RetentionCounts{}, err
		}
		*step.value = value
	}
	return counts, nil
}

// deleteExpired removes only fully-expired rows. The order honours foreign keys: attachments and
// derived rows go before the transactions they describe, and a retained transaction that points at
// an expired refund is unlinked before the refund row disappears.
func deleteExpired(ctx context.Context, tx *sql.Tx, window retention.Window) error {
	cutoffMillis := window.StartMillis()
	cutoffMonth := window.ExpiredBeforeMonthID()
	cutoffTime := nowString(window.Start)

	statements := []struct {
		text string
		args []any
	}{
		{`DELETE FROM attachments WHERE transaction_id IN
		    (SELECT id FROM transactions WHERE event_at_ms < ?)`, []any{cutoffMillis}},
		{`DELETE FROM category_jobs
		  WHERE transaction_id IN (SELECT id FROM transactions WHERE event_at_ms < ?)
		     OR NOT EXISTS (SELECT 1 FROM transactions t
		                    WHERE t.id = category_jobs.transaction_id
		                      AND t.owner_id = category_jobs.owner_id)`, []any{cutoffMillis}},
		{`DELETE FROM import_skipped WHERE job_id IN
		    (SELECT id FROM import_jobs WHERE month_id < ?)`, []any{cutoffMonth}},
		{`DELETE FROM import_batches WHERE job_id IN
		    (SELECT id FROM import_jobs WHERE month_id < ?)`, []any{cutoffMonth}},
		{`DELETE FROM import_jobs WHERE month_id < ?`, []any{cutoffMonth}},
		{`DELETE FROM analyses WHERE month_id < ?`, []any{cutoffMonth}},
		{`DELETE FROM summaries WHERE month_id < ?`, []any{cutoffMonth}},
		{`DELETE FROM category_cache WHERE julianday(updated_at) < julianday(?)`, []any{cutoffTime}},
		// A retained refund may reference an expired original; unlinking keeps the self-referencing
		// foreign key satisfiable without deleting retained data.
		{`UPDATE transactions SET linked_refund_of = NULL
		   WHERE linked_refund_of IN (SELECT id FROM transactions WHERE event_at_ms < ?)`,
			[]any{cutoffMillis}},
		{`DELETE FROM transactions WHERE event_at_ms < ?`, []any{cutoffMillis}},
	}
	for _, statement := range statements {
		if _, err := tx.ExecContext(ctx, statement.text, statement.args...); err != nil {
			return err
		}
	}
	return nil
}

// TransactionEventAt returns only the event timestamp of an owner-scoped live row. Retention guard
// checks must not decrypt sensitive columns, so an expired row whose ciphertext is unreadable still
// receives a policy decision (400 outside_retention) instead of an internal error.
func (s *Store) TransactionEventAt(ctx context.Context, ownerID, id string) (time.Time, error) {
	var ms int64
	err := s.DB.QueryRowContext(ctx, `SELECT event_at_ms FROM transactions
		WHERE owner_id = ? AND id = ? AND deleted_at IS NULL`, ownerID, id).Scan(&ms)
	if errors.Is(err, sql.ErrNoRows) {
		return time.Time{}, ErrNotFound
	}
	if err != nil {
		return time.Time{}, err
	}
	return time.UnixMilli(ms).UTC(), nil
}

// RecordRetentionSweepFailure writes a FAILED audit row when a sweep aborts before its deletion
// transaction commits. It runs in its own statement (best effort) so the original error path is
// unchanged; only mode/window/timestamps/status and a safe error code are stored, never PII.
func (s *Store) RecordRetentionSweepFailure(ctx context.Context, now time.Time, mode RetentionMode, errorCode string) error {
	window := retention.NewWindow(now)
	_, err := s.DB.ExecContext(ctx, `INSERT INTO retention_sweeps
		(id, mode, window_start, window_end, started_at, completed_at, status, counts_json, error_code)
		VALUES (?, ?, ?, ?, ?, ?, 'FAILED', '{}', ?)`,
		NewID("rsweep"), string(mode), nowString(window.Start), nowString(window.End),
		nowString(now), nowString(now), errorCode)
	return err
}
