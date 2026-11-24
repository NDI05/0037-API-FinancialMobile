package store

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pam/recap/backend-go/internal/config"
	"github.com/pam/recap/backend-go/internal/retention"
)

func testRetentionStore(t *testing.T) *Store {
	t.Helper()
	db, err := Open(context.Background(), config.Database{
		URL: "file:" + filepath.Join(t.TempDir(), "retention.db"),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := Migrate(context.Background(), db, time.Now); err != nil {
		t.Fatal(err)
	}
	return New(db, make([]byte, 32), 1)
}

type retentionFixture struct {
	s        *Store
	ownerA   string
	ownerB   string
	window   retention.Window
	txRecent string
}

func setupRetentionFixture(t *testing.T) retentionFixture {
	t.Helper()
	ctx := context.Background()
	s := testRetentionStore(t)
	now := time.Date(2026, 11, 24, 6, 0, 0, 0, time.UTC) // 13:00 WIB
	window := retention.NewWindow(now)
	digest := PasswordDigest{Salt: []byte("s"), Hash: []byte("h"), KDF: "test"}
	ownerA, err := s.CreateAccount(ctx, "retention-a@example.test", "A", digest, now)
	if err != nil {
		t.Fatal(err)
	}
	ownerB, err := s.CreateAccount(ctx, "retention-b@example.test", "B", digest, now)
	if err != nil {
		t.Fatal(err)
	}
	f := retentionFixture{s: s, ownerA: ownerA.OwnerID, ownerB: ownerB.OwnerID, window: window}

	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := s.DB.ExecContext(ctx, query, args...); err != nil {
			t.Fatalf("fixture exec: %v\n%s", err, query)
		}
	}
	insertTransaction := func(owner, id, fingerprint string, eventAt time.Time) {
		exec(`INSERT INTO transactions
			(id, owner_id, direction, source, amount_minor, currency, event_at_ms, month_id,
			 fingerprint, category_origin, sensitive_ciphertext, sensitive_iv, sensitive_tag,
			 key_version, created_at, updated_at)
			VALUES (?, ?, 'DEBIT', 'MANUAL', 1000, 'IDR', ?, ?, ?, 'USER', x'01', x'02', x'03',
			        1, ?, ?)`,
			id, owner, eventAt.UnixMilli(), monthIDFor(eventAt), fingerprint,
			nowString(now), nowString(now))
	}

	// A: one expired transaction, one exactly on the window start (retained), one recent.
	insertTransaction(f.ownerA, "tx_expired_a", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		time.Date(2025, 3, 1, 0, 0, 0, 0, time.UTC))
	insertTransaction(f.ownerA, "tx_boundary_a", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", window.Start)
	insertTransaction(f.ownerA, "tx_recent_a", "cccccccccccccccccccccccccccccccc",
		time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC))
	// B: expired + retained, to prove the sweep is not owner-filtered but never over-deletes.
	insertTransaction(f.ownerB, "tx_expired_b", "dddddddddddddddddddddddddddddddd",
		time.Date(2025, 4, 1, 0, 0, 0, 0, time.UTC))
	insertTransaction(f.ownerB, "tx_recent_b", "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
		time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC))
	f.txRecent = "tx_recent_a"

	// Attachment metadata on an expired transaction and on a retained one.
	insertAttachment := func(id, owner, transactionID string) {
		exec(`INSERT INTO attachments
			(id, owner_id, transaction_id, mime, size_bytes, sha256, storage_ref,
			 sensitive_ciphertext, sensitive_iv, sensitive_tag, key_version,
			 created_at_ms, created_at, updated_at)
			VALUES (?, ?, ?, 'image/jpeg', 1024, ?, ?, x'01', x'02', x'03', 1, ?, ?, ?)`,
			id, owner, transactionID, "1111111111111111111111111111111111111111111111111111111111111111",
			"files/"+id+".jpg", now.UnixMilli(), nowString(now), nowString(now))
	}
	insertAttachment("att_expired", f.ownerA, "tx_expired_a")
	insertAttachment("att_retained", f.ownerA, "tx_recent_a")

	// Stored aggregates: the boundary month itself is retained, the previous month is expired.
	insertSummary := func(id, owner, monthID string) {
		exec(`INSERT INTO summaries
			(id, owner_id, month_id, input_revision, coverage, ciphertext, iv, tag, key_version,
			 created_at, updated_at)
			VALUES (?, ?, ?, 1, 'FULL', x'01', x'02', x'03', 1, ?, ?)`,
			id, owner, monthID, nowString(now), nowString(now))
	}
	insertSummary("sum_expired_a", f.ownerA, "2025-10")
	insertSummary("sum_boundary_a", f.ownerA, "2025-11")
	insertSummary("sum_expired_b", f.ownerB, "2024-12")

	insertAnalysis := func(id, owner, monthID, summaryID string) {
		exec(`INSERT INTO analyses
			(id, owner_id, month_id, summary_id, input_revision, provider, model, prompt_version,
			 ciphertext, iv, tag, key_version, status, idempotency_key, request_hash, created_at)
			VALUES (?, ?, ?, ?, 1, 'fake', 'fake', 'v1', x'01', x'02', x'03', 1, 'AVAILABLE',
			        ?, 'hash', ?)`,
			id, owner, monthID, summaryID, "idem-"+id, nowString(now))
	}
	insertAnalysis("an_expired_a", f.ownerA, "2025-09", "sum_expired_a")
	insertAnalysis("an_boundary_a", f.ownerA, "2025-11", "sum_boundary_a")

	// Category jobs: one tied to an expired transaction, one orphan, one on retained data.
	insertCategoryJob := func(id, owner, transactionID string) {
		exec(`INSERT INTO category_jobs
			(id, owner_id, transaction_id, expected_revision, state, created_at, updated_at)
			VALUES (?, ?, ?, 0, 'PENDING', ?, ?)`,
			id, owner, transactionID, nowString(now), nowString(now))
	}
	insertCategoryJob("job_expired", f.ownerA, "tx_expired_a")
	insertCategoryJob("job_orphan", f.ownerA, "tx_does_not_exist")
	insertCategoryJob("job_recent", f.ownerA, "tx_recent_a")

	// Category cache: old rows expire, rows at/after the window start are retained.
	insertCategoryCache := func(cacheKey, updatedAt string) {
		exec(`INSERT INTO category_cache
			(owner_id, cache_key, direction, method, taxonomy_version, model, prompt_version,
			 category_code, needs_review, reason_code, updated_at)
			VALUES (?, ?, 'DEBIT', 'RULE', 't1', 'm1', 'p1', 'food', 0, 'r', ?)`,
			f.ownerA, cacheKey, updatedAt)
	}
	insertCategoryCache("old", nowString(window.Start.Add(-time.Hour)))
	insertCategoryCache("boundary", nowString(window.Start))
	insertCategoryCache("fresh", nowString(now))

	// Import history: expired job with batch/skipped rows, plus a retained boundary-month job.
	insertImportJob := func(id, owner, monthID string) {
		exec(`INSERT INTO import_jobs
			(id, owner_id, month_id, state, template_version, started_at)
			VALUES (?, ?, ?, 'CREATED', 'v1', ?)`,
			id, owner, monthID, nowString(now))
	}
	insertImportJob("imp_expired_a", f.ownerA, "2025-10")
	insertImportJob("imp_boundary_a", f.ownerA, "2025-11")
	insertImportJob("imp_expired_b", f.ownerB, "2024-12")
	insertImportBatch := func(id, owner, jobID string) {
		exec(`INSERT INTO import_batches (id, owner_id, job_id, batch_key, request_hash, counts_json, created_at)
			VALUES (?, ?, ?, ?, 'hash', '{}', ?)`, id, owner, jobID, "batch-"+id, nowString(now))
	}
	insertImportBatch("batch_expired", f.ownerA, "imp_expired_a")
	insertImportBatch("batch_boundary", f.ownerA, "imp_boundary_a")
	insertSkipped := func(id, owner, jobID string) {
		exec(`INSERT INTO import_skipped
			(id, owner_id, job_id, reason_code, page_ordinal, candidate_ordinal, created_at)
			VALUES (?, ?, ?, 'not_a_transaction', 0, 0, ?)`, id, owner, jobID, nowString(now))
	}
	insertSkipped("skip_expired", f.ownerA, "imp_expired_a")
	insertSkipped("skip_boundary", f.ownerA, "imp_boundary_a")

	return f
}

func (f retentionFixture) rowExists(t *testing.T, query string, args ...any) bool {
	t.Helper()
	var count int
	if err := f.s.DB.QueryRowContext(context.Background(), query, args...).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count > 0
}

func TestRetentionPlanIsReadOnlyAndCountsOnlyEligibleRows(t *testing.T) {
	ctx := context.Background()
	f := setupRetentionFixture(t)

	counts, err := f.s.PlanRetention(ctx, f.window.End)
	if err != nil {
		t.Fatal(err)
	}
	expected := RetentionCounts{
		Transactions: 2, Attachments: 1, Summaries: 2, Analyses: 1,
		CategoryJobs: 2, CategoryCache: 1, ImportJobs: 2, ImportBatches: 1, ImportSkipped: 1,
	}
	if counts != expected {
		t.Fatalf("plan counts = %+v, want %+v", counts, expected)
	}
	// Report-only is a true dry run: every expired row is still present.
	for _, query := range []string{
		`SELECT COUNT(*) FROM transactions WHERE id = 'tx_expired_a'`,
		`SELECT COUNT(*) FROM summaries WHERE id = 'sum_expired_a'`,
		`SELECT COUNT(*) FROM import_jobs WHERE id = 'imp_expired_b'`,
	} {
		if !f.rowExists(t, query) {
			t.Fatalf("plan must not delete: %s returned no row", query)
		}
	}
	var auditRows int
	if err := f.s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM retention_sweeps`).Scan(&auditRows); err != nil {
		t.Fatal(err)
	}
	if auditRows != 0 {
		t.Fatalf("PlanRetention must not write audit rows, got %d", auditRows)
	}
}

func TestRetentionReportOnlySweepWritesAuditAndDeletesNothing(t *testing.T) {
	ctx := context.Background()
	f := setupRetentionFixture(t)

	result, err := f.s.SweepRetention(ctx, f.window.End, RetentionReportOnly)
	if err != nil {
		t.Fatal(err)
	}
	if result.Mode != RetentionReportOnly || result.Counts.Total() != 13 {
		t.Fatalf("report-only result = %+v", result)
	}
	if !f.rowExists(t, `SELECT COUNT(*) FROM transactions WHERE id = 'tx_expired_a'`) ||
		!f.rowExists(t, `SELECT COUNT(*) FROM summaries WHERE id = 'sum_expired_a'`) {
		t.Fatal("report-only sweep must not delete rows")
	}
	var mode, status, countsJSON string
	if err := f.s.DB.QueryRowContext(ctx, `SELECT mode, status, counts_json FROM retention_sweeps
		WHERE id = ?`, result.ID).Scan(&mode, &status, &countsJSON); err != nil {
		t.Fatal(err)
	}
	if mode != "REPORT_ONLY" || status != "COMPLETED" || countsJSON == "" {
		t.Fatalf("audit row = mode %q status %q counts %q", mode, status, countsJSON)
	}
}

func TestRetentionDeleteSweepRemovesOnlyExpiredRowsAndKeepsBoundary(t *testing.T) {
	ctx := context.Background()
	f := setupRetentionFixture(t)

	result, err := f.s.SweepRetention(ctx, f.window.End, RetentionDelete)
	if err != nil {
		t.Fatal(err)
	}
	if result.Mode != RetentionDelete || result.Counts.Total() != 13 {
		t.Fatalf("delete result = %+v", result)
	}
	for _, id := range []string{"tx_expired_a", "tx_expired_b"} {
		if f.rowExists(t, `SELECT COUNT(*) FROM transactions WHERE id = ?`, id) {
			t.Fatalf("expired transaction %s must be deleted", id)
		}
	}
	for _, id := range []string{"tx_boundary_a", "tx_recent_a", "tx_recent_b"} {
		if !f.rowExists(t, `SELECT COUNT(*) FROM transactions WHERE id = ?`, id) {
			t.Fatalf("retained transaction %s must survive the sweep", id)
		}
	}
	// Rows exactly on the window start are retained; rows just before it are not.
	if !f.rowExists(t, `SELECT COUNT(*) FROM category_cache WHERE cache_key = 'boundary'`) ||
		!f.rowExists(t, `SELECT COUNT(*) FROM category_cache WHERE cache_key = 'fresh'`) {
		t.Fatal("category cache at/after the window start must be retained")
	}
	if f.rowExists(t, `SELECT COUNT(*) FROM category_cache WHERE cache_key = 'old'`) {
		t.Fatal("category cache older than the window must be deleted")
	}
	if !f.rowExists(t, `SELECT COUNT(*) FROM summaries WHERE id = 'sum_boundary_a'`) ||
		!f.rowExists(t, `SELECT COUNT(*) FROM analyses WHERE id = 'an_boundary_a'`) ||
		!f.rowExists(t, `SELECT COUNT(*) FROM import_jobs WHERE id = 'imp_boundary_a'`) ||
		!f.rowExists(t, `SELECT COUNT(*) FROM import_batches WHERE id = 'batch_boundary'`) ||
		!f.rowExists(t, `SELECT COUNT(*) FROM import_skipped WHERE id = 'skip_boundary'`) {
		t.Fatal("boundary-month derivative rows must be retained")
	}
	for _, id := range []string{"sum_expired_a", "sum_expired_b", "an_expired_a",
		"imp_expired_a", "imp_expired_b", "batch_expired", "skip_expired", "att_expired"} {
		var table string
		switch {
		case strings.HasPrefix(id, "sum_"):
			table = "summaries"
		case strings.HasPrefix(id, "an_"):
			table = "analyses"
		case strings.HasPrefix(id, "imp_"):
			table = "import_jobs"
		case strings.HasPrefix(id, "batch_"):
			table = "import_batches"
		case strings.HasPrefix(id, "skip_"):
			table = "import_skipped"
		case strings.HasPrefix(id, "att_"):
			table = "attachments"
		default:
			t.Fatalf("unknown fixture id %q", id)
		}
		if f.rowExists(t, `SELECT COUNT(*) FROM `+table+` WHERE id = ?`, id) {
			t.Fatalf("expired %s row %s must be deleted", table, id)
		}
	}
	for _, id := range []string{"job_expired", "job_orphan"} {
		if f.rowExists(t, `SELECT COUNT(*) FROM category_jobs WHERE id = ?`, id) {
			t.Fatalf("expired/orphan category job %s must be deleted", id)
		}
	}
	if !f.rowExists(t, `SELECT COUNT(*) FROM category_jobs WHERE id = 'job_recent'`) {
		t.Fatal("category job on retained data must survive")
	}
	if !f.rowExists(t, `SELECT COUNT(*) FROM attachments WHERE id = 'att_retained'`) {
		t.Fatal("attachment on retained data must survive")
	}
	var auditRows int
	if err := f.s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM retention_sweeps
		WHERE mode = 'DELETE' AND status = 'COMPLETED'`).Scan(&auditRows); err != nil {
		t.Fatal(err)
	}
	if auditRows != 1 {
		t.Fatalf("want exactly one DELETE audit row, got %d", auditRows)
	}
}

func TestSweepRetentionRejectsUnknownMode(t *testing.T) {
	ctx := context.Background()
	s := testRetentionStore(t)
	if _, err := s.SweepRetention(ctx, time.Now(), RetentionMode("PURGE")); err == nil {
		t.Fatal("unknown retention mode must be rejected")
	}
}
