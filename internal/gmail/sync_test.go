package gmail

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pam/recap/backend-go/internal/config"
	"github.com/pam/recap/backend-go/internal/store"
)

var syncNow = time.Date(2026, 11, 24, 6, 0, 0, 0, time.UTC)

// fakeCategories records the server-side category hook calls made by the Gmail worker.
type fakeCategories struct {
	mu        sync.Mutex
	enqueued  [][]string
	enqueueOK int
	drains    int
	err       error
}

func (f *fakeCategories) EnqueueImported(_ context.Context, _ string, ids []string) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return 0, f.err
	}
	f.enqueued = append(f.enqueued, append([]string(nil), ids...))
	f.enqueueOK += len(ids)
	return len(ids), nil
}

func (f *fakeCategories) DrainOwner(context.Context, string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.drains++
	return nil
}

func (f *fakeCategories) snapshot() (enqueued [][]string, drains int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([][]string(nil), f.enqueued...), f.drains
}

type syncFixture struct {
	Service    *Service
	Store      *store.Store
	Provider   *FakeProvider
	OAuth      *FakeExchanger
	Categories *fakeCategories
	Owner      string
	Now        time.Time
}

func newSyncFixture(t *testing.T) *syncFixture {
	t.Helper()
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "pam.db")
	db, err := store.Open(ctx, config.Database{URL: "file:" + path})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	data := store.New(db, []byte("0123456789abcdef0123456789abcdef"), 1)
	now := syncNow
	if _, err := data.CreateAccount(ctx, "gmail-sync@example.test", "Uji",
		store.PasswordDigest{Salt: []byte("salt"), Hash: []byte("hash"),
			KDF: "scrypt:N=32768,r=8,p=1"}, now); err != nil {
		t.Fatal(err)
	}
	provider := &FakeProvider{ProfileValue: Profile{EmailAddress: "user@gmail.test", HistoryID: "900"}}
	exchanger := &FakeExchanger{
		ByRefresh: map[string]TokenSet{
			"refresh-1": {AccessToken: "access-1", RefreshToken: "refresh-1",
				Expiry: now.Add(time.Hour), Scope: "https://www.googleapis.com/auth/gmail.readonly"},
		},
	}
	categories := &fakeCategories{}
	service := NewService(data, provider, exchanger, Settings{
		RedirectURI: "https://api.example.test/v1/gmail/connect/callback",
		TopicName:   "projects/pam/topics/gmail", BackfillMonths: 1, PageSize: 10,
		MaxPagesPerRun: 5, WatchRenewBefore: 24 * time.Hour,
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	service.Now = func() time.Time { return now }
	service.Categories = categories
	return &syncFixture{Service: service, Store: data, Provider: provider, OAuth: exchanger,
		Categories: categories, Owner: store.OwnerIDForEmail("gmail-sync@example.test"), Now: now}
}

func (f *syncFixture) connect(t *testing.T, cursor string) store.GmailConnection {
	t.Helper()
	connection, err := f.Store.SaveGmailConnection(context.Background(), store.GmailConnectionInput{
		OwnerID: f.Owner, AccountEmail: "user@gmail.test",
		Scope:        "https://www.googleapis.com/auth/gmail.readonly",
		RefreshToken: "refresh-1", WatchExpiresAt: f.Now.Add(6 * 24 * time.Hour),
		HistoryCursor: cursor, Now: f.Now,
	})
	if err != nil {
		t.Fatal(err)
	}
	return connection
}

func (f *syncFixture) jobCounts(t *testing.T, month string) (seen, imported, duplicates, skipped int, state string) {
	t.Helper()
	if err := f.Store.DB.QueryRow(`SELECT seen_count, imported_count, duplicate_count,
		skipped_count, state FROM gmail_sync_jobs WHERE owner_id = ? AND month_id = ?`,
		f.Owner, month).Scan(&seen, &imported, &duplicates, &skipped, &state); err != nil {
		t.Fatal(err)
	}
	return
}

func (f *syncFixture) transactionCount(t *testing.T) int {
	t.Helper()
	var count int
	if err := f.Store.DB.QueryRow(`SELECT COUNT(*) FROM transactions WHERE owner_id = ?`,
		f.Owner).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

func livinBodyFor(date string) string {
	return `Pembayaran Berhasil
Penerima: KOPI KENANGAN
Merchant PAN: 936009110000123456
Customer PAN: 936000110000654321
No. Referensi: 202611100001234
Jumlah: Rp 25.000
Tanggal: ` + date + "\n"
}

func TestBackfillFiltersOutsideMonthAndDedupes(t *testing.T) {
	ctx := context.Background()
	f := newSyncFixture(t)
	f.connect(t, "100")
	f.Provider.RawByID = map[string]RawMessage{
		"m1": {ID: "m1", Raw: rawEmail("Pembayaran Berhasil!", livinBodyFor("10 Nov 2026 09:30:45"))},
		"m2": {ID: "m2", Raw: rawEmail("Pembayaran Berhasil!", livinBodyFor("05 Jan 2026 10:00:00"))},
	}
	pages := []MessageList{
		{Messages: []MessageRef{{ID: "m1"}, {ID: "m2"}}, NextPageToken: "page-2"},
		{Messages: []MessageRef{{ID: "m1"}}},
	}
	f.Provider.Pages = pages

	report, err := f.Service.RunOnce(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if report.Backfills != 1 || report.Failures != 0 {
		t.Fatalf("unexpected report: %+v", report)
	}
	if got := f.transactionCount(t); got != 1 {
		t.Fatalf("imported transactions = %d, want 1", got)
	}
	seen, imported, duplicates, skipped, state := f.jobCounts(t, "2026-11")
	if state != "COMPLETE" || seen != 3 || imported != 1 || duplicates != 1 || skipped != 1 {
		t.Fatalf("month job = %s seen=%d imported=%d dup=%d skipped=%d", state, seen, imported,
			duplicates, skipped)
	}
	var leaked int
	if err := f.Store.DB.QueryRow(`SELECT COUNT(*) FROM transactions WHERE owner_id = ?
		AND (CAST(sensitive_ciphertext AS TEXT) LIKE '%9360%'
		OR CAST(sensitive_iv AS TEXT) LIKE '%9360%')`, f.Owner).Scan(&leaked); err != nil {
		t.Fatal(err)
	}
	if leaked != 0 {
		t.Fatal("merchant/customer PAN leaked into a stored transaction")
	}

	// A replayed month must not duplicate rows: same source refs come back as duplicates.
	if _, err := f.Store.DB.Exec(`UPDATE gmail_sync_jobs SET state = 'CREATED', page_token_ciphertext = NULL,
		page_token_iv = NULL, page_token_tag = NULL, page_token_key_version = NULL
		WHERE owner_id = ? AND month_id = '2026-11'`, f.Owner); err != nil {
		t.Fatal(err)
	}
	f.Provider.Pages = append(f.Provider.Pages, pages...)
	if _, err := f.Service.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if got := f.transactionCount(t); got != 1 {
		t.Fatalf("replay created duplicates: %d transactions", got)
	}
	seen, secondImported, secondDuplicates, secondSkipped, state := f.jobCounts(t, "2026-11")
	// Both pages of the replay resolve to an already imported row, hence two duplicates.
	if state != "COMPLETE" || secondImported != 0 || secondDuplicates != 2 || secondSkipped != 1 {
		t.Fatalf("replayed run must only count duplicates: seen=%d imported=%d dup=%d skipped=%d state=%s",
			seen, secondImported, secondDuplicates, secondSkipped, state)
	}
}

func TestDeltaExpiredCursorRecoversWithFreshHistory(t *testing.T) {
	ctx := context.Background()
	f := newSyncFixture(t)
	connection := f.connect(t, "100")
	f.Provider.HistoryErr = &APIError{Status: 404, Code: "not_found", Expired: true}
	f.Provider.RawByID = map[string]RawMessage{
		"m3": {ID: "m3", Raw: rawEmail("Transaksi Berhasil", livinBodyFor("20 Nov 2026 14:05:00"))},
	}
	f.Provider.Pages = []MessageList{{Messages: []MessageRef{{ID: "m3"}}}}
	f.Provider.ProfileValue = Profile{EmailAddress: "user@gmail.test", HistoryID: "900"}

	if err := f.Service.runDelta(ctx, connection, "access-1"); err != nil {
		t.Fatalf("expired cursor must recover: %v", err)
	}
	recovered, err := f.Store.GetGmailConnection(ctx, f.Owner)
	if err != nil {
		t.Fatal(err)
	}
	if recovered.HistoryCursor != "900" {
		t.Fatalf("history cursor = %q, want fresh 900", recovered.HistoryCursor)
	}
	var jobState, jobError string
	if err := f.Store.DB.QueryRow(`SELECT state, COALESCE(last_error_code, '')
		FROM gmail_sync_jobs WHERE owner_id = ? AND kind = 'DELTA'`, f.Owner).Scan(&jobState, &jobError); err != nil {
		t.Fatal(err)
	}
	if jobState != "COMPLETE" || jobError != "history_expired" {
		t.Fatalf("delta job = %s/%s", jobState, jobError)
	}
	if got := f.transactionCount(t); got != 1 {
		t.Fatalf("recovery scan imported %d transactions, want 1", got)
	}
}

func TestFailedPageRetriesWithoutLosingCheckpoint(t *testing.T) {
	ctx := context.Background()
	f := newSyncFixture(t)
	f.connect(t, "")
	f.Provider.ListErr = errors.New("connection reset")
	report, err := f.Service.RunOnce(ctx)
	if err == nil && report.Failures == 0 {
		t.Fatalf("provider failure must be reported: %+v", report)
	}
	connection, err := f.Store.GetGmailConnection(ctx, f.Owner)
	if err != nil {
		t.Fatal(err)
	}
	if connection.SyncState != "error" || connection.LastErrorCode != "provider_error" {
		t.Fatalf("failure must be recorded: state=%s code=%s", connection.SyncState,
			connection.LastErrorCode)
	}
	var failedState string
	if err := f.Store.DB.QueryRow(`SELECT state FROM gmail_sync_jobs WHERE owner_id = ?
		AND kind = 'BACKFILL'`, f.Owner).Scan(&failedState); err != nil {
		t.Fatal(err)
	}
	if failedState != "FAILED" {
		t.Fatalf("job state = %s, want FAILED", failedState)
	}

	// The next tick retries the same month and completes.
	f.Provider.ListErr = nil
	f.Provider.RawByID = map[string]RawMessage{
		"m1": {ID: "m1", Raw: rawEmail("Pembayaran Berhasil!", livinBodyFor("10 Nov 2026 09:30:45"))},
	}
	f.Provider.Pages = []MessageList{{Messages: []MessageRef{{ID: "m1"}}}}
	f.Provider.ListCalls = 0
	if _, err := f.Service.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if got := f.transactionCount(t); got != 1 {
		t.Fatalf("retry did not import: %d", got)
	}
	if _, _, _, _, state := f.jobCounts(t, "2026-11"); state != "COMPLETE" {
		t.Fatalf("retried job state = %s", state)
	}
}

func TestWatchRenewalIsScheduledBeforeExpiry(t *testing.T) {
	ctx := context.Background()
	f := newSyncFixture(t)
	connection, err := f.Store.SaveGmailConnection(ctx, store.GmailConnectionInput{
		OwnerID: f.Owner, AccountEmail: "user@gmail.test", Scope: "scope",
		RefreshToken: "refresh-1", WatchExpiresAt: f.Now.Add(time.Hour), Now: f.Now,
	})
	if err != nil {
		t.Fatal(err)
	}
	f.Provider.WatchState = WatchState{Expiration: f.Now.Add(7 * 24 * time.Hour), HistoryID: "777"}
	f.Provider.Pages = []MessageList{{}}
	if _, err := f.Service.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if f.Provider.WatchCalls != 1 {
		t.Fatalf("watch renewals = %d, want 1", f.Provider.WatchCalls)
	}
	renewed, err := f.Store.GetGmailConnection(ctx, f.Owner)
	if err != nil {
		t.Fatal(err)
	}
	if renewed.WatchExpiresAt.Before(connection.WatchExpiresAt) {
		t.Fatalf("watch expiry not extended: %s", renewed.WatchExpiresAt)
	}
}

func TestServiceRejectsPlaintextSecretsAndMasksEmail(t *testing.T) {
	ctx := context.Background()
	f := newSyncFixture(t)
	f.connect(t, "100")
	view, err := f.Service.Status(ctx, f.Owner)
	if err != nil {
		t.Fatal(err)
	}
	if !view.Connected {
		t.Fatal("connection not visible in status")
	}
	if view.AccountEmail == "user@gmail.test" || !strings.Contains(view.AccountEmail, "***") {
		t.Fatalf("status must mask the mailbox: %q", view.AccountEmail)
	}
	if err := f.Service.Disconnect(ctx, f.Owner); err != nil {
		t.Fatal(err)
	}
	if f.Provider.StopCalls != 1 || f.OAuth.Revokes != 1 {
		t.Fatalf("disconnect must stop watch and revoke: stop=%d revoke=%d", f.Provider.StopCalls,
			f.OAuth.Revokes)
	}
	if f.OAuth.Revoked[0] != "refresh-1" {
		t.Fatal("disconnect must revoke the refresh token")
	}
	view, err = f.Service.Status(ctx, f.Owner)
	if err != nil || view.Connected {
		t.Fatalf("status after disconnect: %+v %v", view, err)
	}
	disconnected, err := f.Store.GetGmailConnection(ctx, f.Owner)
	if err != nil || disconnected.State != "DISCONNECTED" || disconnected.RefreshToken != "" {
		t.Fatalf("disconnect must clear credentials: %+v %v", disconnected, err)
	}
}

// Imported pages must start the server-side category window: only newly inserted transaction ids
// are handed to the hook, a replayed page hands over nothing, and a hook failure never fails an
// import that the store already acknowledged.
func TestImportedPagesTriggerCategoryEnqueueOnce(t *testing.T) {
	ctx := context.Background()
	f := newSyncFixture(t)
	f.connect(t, "100")
	f.Provider.RawByID = map[string]RawMessage{
		"m1": {ID: "m1", Raw: rawEmail("Pembayaran Berhasil!", livinBodyFor("10 Nov 2026 09:30:45"))},
		"m2": {ID: "m2", Raw: rawEmail("Pembayaran Berhasil!", livinBodyFor("05 Jan 2026 10:00:00"))},
	}
	pages := []MessageList{
		{Messages: []MessageRef{{ID: "m1"}, {ID: "m2"}}, NextPageToken: "page-2"},
		{Messages: []MessageRef{{ID: "m1"}}},
	}
	f.Provider.Pages = pages
	if _, err := f.Service.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	enqueued, drains := f.Categories.snapshot()
	// Page 1 imports m1 (m2 is outside the month); page 2 is a duplicate and enqueues nothing.
	if len(enqueued) != 1 || len(enqueued[0]) != 1 {
		t.Fatalf("enqueue calls = %v, want exactly one imported id", enqueued)
	}
	var importedID string
	if err := f.Store.DB.QueryRow(`SELECT id FROM transactions WHERE owner_id = ?`,
		f.Owner).Scan(&importedID); err != nil {
		t.Fatal(err)
	}
	if enqueued[0][0] != importedID {
		t.Fatalf("enqueued id = %q, want stored transaction %q", enqueued[0][0], importedID)
	}
	if drains != 1 {
		t.Fatalf("drain calls = %d, want 1", drains)
	}

	// Replay the same month: no new transaction, hence no new enqueue and no new drain.
	if _, err := f.Store.DB.Exec(`UPDATE gmail_sync_jobs SET state = 'CREATED',
		page_token_ciphertext = NULL, page_token_iv = NULL, page_token_tag = NULL,
		page_token_key_version = NULL
		WHERE owner_id = ? AND month_id = '2026-11'`, f.Owner); err != nil {
		t.Fatal(err)
	}
	f.Provider.Pages = append(f.Provider.Pages, pages...)
	if _, err := f.Service.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	enqueued, drains = f.Categories.snapshot()
	if len(enqueued) != 1 || drains != 1 {
		t.Fatalf("replayed import enqueued=%v drains=%d, want no new work", enqueued, drains)
	}
	if got := f.transactionCount(t); got != 1 {
		t.Fatalf("replay doubled transactions: %d", got)
	}
}

// A category-hook failure is logged and left to the durable category worker; it must not turn an
// acknowledged import into a sync failure or drop the imported rows.
func TestCategoryHookFailureDoesNotFailImport(t *testing.T) {
	ctx := context.Background()
	f := newSyncFixture(t)
	f.connect(t, "100")
	f.Categories.err = errors.New("category store unavailable")
	f.Provider.RawByID = map[string]RawMessage{
		"m1": {ID: "m1", Raw: rawEmail("Pembayaran Berhasil!", livinBodyFor("10 Nov 2026 09:30:45"))},
	}
	f.Provider.Pages = []MessageList{{Messages: []MessageRef{{ID: "m1"}}}}
	report, err := f.Service.RunOnce(ctx)
	if err != nil {
		t.Fatalf("hook failure must not fail the sync run: %v", err)
	}
	if report.Failures != 0 {
		t.Fatalf("hook failure must not count as a sync failure: %+v", report)
	}
	if got := f.transactionCount(t); got != 1 {
		t.Fatalf("imported rows = %d, want 1", got)
	}
	if _, drains := f.Categories.snapshot(); drains != 0 {
		t.Fatalf("drain must not run when enqueue failed: %d", drains)
	}
}
