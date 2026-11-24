package gmail

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pam/recap/backend-go/internal/config"
	"github.com/pam/recap/backend-go/internal/crypto"
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
	return newSyncFixtureMonths(t, 1)
}

func newSyncFixtureMonths(t *testing.T, backfillMonths int) *syncFixture {
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
		ByCode: map[string]TokenSet{},
		ByRefresh: map[string]TokenSet{
			"refresh-1": {AccessToken: "access-1", RefreshToken: "refresh-1",
				Expiry: now.Add(time.Hour), Scope: "https://www.googleapis.com/auth/gmail.readonly"},
		},
	}
	categories := &fakeCategories{}
	service := NewService(data, provider, exchanger, Settings{
		RedirectURI: "https://api.example.test/v1/gmail/connect/callback",
		TopicName:   "projects/pam/topics/gmail", BackfillMonths: backfillMonths, PageSize: 10,
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

func stateFromAuthURL(t *testing.T, authURL string) string {
	t.Helper()
	parsed, err := url.Parse(authURL)
	if err != nil {
		t.Fatal(err)
	}
	state := parsed.Query().Get("state")
	if state == "" {
		t.Fatalf("no state in %s", authURL)
	}
	return state
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

// An email that arrives after the month boundary must be imported into the month of its
// transaction date, not dropped as outside_period and not booked into the arrival month.
func TestLateEmailImportsIntoTransactionMonth(t *testing.T) {
	ctx := context.Background()
	f := newSyncFixtureMonths(t, 12)
	connection := f.connect(t, "100")
	f.Provider.RawByID = map[string]RawMessage{
		"late-nov": {ID: "late-nov", Raw: rawEmail("Pembayaran Berhasil!", livinBodyFor("30 Nov 2026 20:15:00"))},
	}
	f.Provider.Pages = []MessageList{{Messages: []MessageRef{{ID: "late-nov"}}}}
	if _, err := f.Service.importMonthPages(ctx, connection, "access-1", "2026-12", "", "late", func(pageProgress) error { return nil }); err != nil {
		t.Fatalf("december scan: %v", err)
	}
	var monthID string
	var seen, skipped int
	if err := f.Store.DB.QueryRow(`SELECT month_id FROM transactions WHERE owner_id = ?`,
		f.Owner).Scan(&monthID); err != nil {
		t.Fatal(err)
	}
	if monthID != "2026-11" {
		t.Fatalf("late email transaction month = %s, want 2026-11", monthID)
	}
	if err := f.Store.DB.QueryRow(`SELECT COUNT(*) FROM import_skipped WHERE owner_id = ?`,
		f.Owner).Scan(&skipped); err != nil {
		t.Fatal(err)
	}
	if skipped != 0 {
		t.Fatalf("in-window late email was skipped: %d", skipped)
	}
	if err := f.Store.DB.QueryRow(`SELECT COUNT(*) FROM import_jobs WHERE owner_id = ? AND month_id = '2026-11'`,
		f.Owner).Scan(&seen); err != nil {
		t.Fatal(err)
	}
	if seen == 0 {
		t.Fatal("late arrival must be written into a November import job")
	}
	// A replay of the same arrival scan must not duplicate the row.
	f.Provider.Pages = []MessageList{{Messages: []MessageRef{{ID: "late-nov"}}}}
	if _, err := f.Service.importMonthPages(ctx, connection, "access-1", "2026-12", "", "late2", func(pageProgress) error { return nil }); err != nil {
		t.Fatalf("replay scan: %v", err)
	}
	if got := f.transactionCount(t); got != 1 {
		t.Fatalf("replay created %d transactions, want 1", got)
	}
}

// A notification whose transaction date is older than the retention window must be rejected with
// an explicit reason, not silently discarded.
func TestOutOfRetentionTransactionIsExplicitlySkipped(t *testing.T) {
	ctx := context.Background()
	f := newSyncFixture(t) // one-month retention window ending 2026-11
	connection := f.connect(t, "100")
	f.Provider.RawByID = map[string]RawMessage{
		"old": {ID: "old", Raw: rawEmail("Pembayaran Berhasil!", livinBodyFor("05 Jan 2026 10:00:00"))},
	}
	f.Provider.Pages = []MessageList{{Messages: []MessageRef{{ID: "old"}}}}
	if _, err := f.Service.importMonthPages(ctx, connection, "access-1", "2026-11", "", "retention", func(pageProgress) error { return nil }); err != nil {
		t.Fatalf("scan: %v", err)
	}
	var reason string
	if err := f.Store.DB.QueryRow(`SELECT reason_code FROM import_skipped WHERE owner_id = ?`,
		f.Owner).Scan(&reason); err != nil {
		t.Fatal(err)
	}
	if reason != "outside_retention" {
		t.Fatalf("reason = %q, want outside_retention", reason)
	}
	if got := f.transactionCount(t); got != 0 {
		t.Fatalf("out-of-retention row imported: %d", got)
	}
}

// Reconnecting to a different mailbox must retire the old mailbox completely: its watch and token
// are stopped/revoked, its sync jobs are gone so the new mailbox re-backfills the rolling window,
// and a replayed OAuth state cannot reactivate the old connection.
func TestReconnectToDifferentMailboxResetsSyncState(t *testing.T) {
	ctx := context.Background()
	f := newSyncFixture(t)
	f.connect(t, "100")

	// Materialise one backfill job for the old mailbox.
	f.Provider.Pages = []MessageList{{}}
	if _, err := f.Service.RunOnce(ctx); err != nil {
		t.Fatalf("initial sync: %v", err)
	}
	var oldJobs int
	if err := f.Store.DB.QueryRow(`SELECT COUNT(*) FROM gmail_sync_jobs WHERE owner_id = ?`,
		f.Owner).Scan(&oldJobs); err != nil {
		t.Fatal(err)
	}
	if oldJobs == 0 {
		t.Fatal("expected a backfill job for the first mailbox")
	}
	oldHash := f.Store.GmailEmailHash("user@gmail.test")

	start, err := f.Service.Start(ctx, f.Owner, true)
	if err != nil {
		t.Fatalf("reconnect start: %v", err)
	}
	state := stateFromAuthURL(t, start.AuthorizationURL)
	f.OAuth.ByCode["code-second"] = TokenSet{AccessToken: "access-second",
		RefreshToken: "refresh-second", Expiry: f.Now.Add(time.Hour),
		Scope: "https://www.googleapis.com/auth/gmail.readonly"}
	f.OAuth.ByRefresh["refresh-second"] = TokenSet{AccessToken: "access-second",
		RefreshToken: "refresh-second", Expiry: f.Now.Add(time.Hour),
		Scope: "https://www.googleapis.com/auth/gmail.readonly"}
	f.Provider.ProfileValue = Profile{EmailAddress: "second@gmail.test", HistoryID: "500"}
	f.Provider.WatchState = WatchState{HistoryID: "500", Expiration: f.Now.Add(6 * 24 * time.Hour)}
	result := f.Service.Callback(ctx, "code-second", state)
	if result.Status != "success" {
		t.Fatalf("reconnect callback = %+v", result)
	}
	if f.Provider.StopCalls != 1 {
		t.Fatalf("old watch stop calls = %d, want 1", f.Provider.StopCalls)
	}
	f.OAuth.mu.Lock()
	revoked := append([]string(nil), f.OAuth.Revoked...)
	f.OAuth.mu.Unlock()
	found := false
	for _, token := range revoked {
		if token == "refresh-1" {
			found = true
		}
	}
	if !found {
		t.Fatalf("old refresh token not revoked: %v", revoked)
	}

	connection, err := f.Store.GetGmailConnection(ctx, f.Owner)
	if err != nil {
		t.Fatal(err)
	}
	if connection.AccountEmailHash != f.Store.GmailEmailHash("second@gmail.test") {
		t.Fatal("connection still points at the old mailbox")
	}
	var jobs int
	var month string
	if err := f.Store.DB.QueryRow(`SELECT COUNT(*), COALESCE(MAX(month_id), '')
		FROM gmail_sync_jobs WHERE owner_id = ?`, f.Owner).Scan(&jobs, &month); err != nil {
		t.Fatal(err)
	}
	if jobs != 1 || month != "2026-11" {
		t.Fatalf("sync jobs after reconnect = %d for %s, want only the new current-month backfill", jobs, month)
	}
	// Stale jobs from the old mailbox must not exist under the new one.
	var stale int
	if err := f.Store.DB.QueryRow(`SELECT COUNT(*) FROM gmail_sync_jobs
		WHERE owner_id = ? AND COALESCE(month_id, '') <> '2026-11'`, f.Owner).Scan(&stale); err != nil {
		t.Fatal(err)
	}
	if stale != 0 {
		t.Fatalf("stale old-mailbox jobs remain: %d", stale)
	}

	// A replayed OAuth state must not bring the old connection back.
	replay := f.Service.Callback(ctx, "code-second", state)
	if replay.Status != "error" ||
		(replay.Reason != "state_invalid" && replay.Reason != "state_expired") {
		t.Fatalf("replayed state result = %+v", replay)
	}
	if _, err := f.Store.GmailConnectionByEmailHash(ctx, oldHash); !errors.Is(err, store.ErrGmailNotConnected) {
		t.Fatalf("old mailbox is still resolvable for push: %v", err)
	}

	// The new mailbox backfill runs for real.
	f.Provider.ListCalls = 0
	f.Provider.Pages = []MessageList{{Messages: []MessageRef{{ID: "second-1"}}}}
	f.Provider.RawByID = map[string]RawMessage{
		"second-1": {ID: "second-1", Raw: rawEmail("Pembayaran Berhasil!", livinBodyFor("20 Nov 2026 09:00:00"))},
	}
	if _, err := f.Service.RunOnce(ctx); err != nil {
		t.Fatalf("new mailbox sync: %v", err)
	}
	if got := f.transactionCount(t); got != 1 {
		t.Fatalf("new mailbox imported %d transactions, want 1", got)
	}
	var sourceRef string
	var cipher, iv, tag []byte
	var version int64
	if err := f.Store.DB.QueryRow(`SELECT source_ref_ciphertext, source_ref_iv, source_ref_tag,
		source_ref_key_version FROM transactions WHERE owner_id = ?`, f.Owner).
		Scan(&cipher, &iv, &tag, &version); err != nil {
		t.Fatal(err)
	}
	plain, err := crypto.Open(crypto.Sealed{Ciphertext: cipher, IV: iv, Tag: tag,
		KeyVersion: int(version)}, f.Store.DataKey, f.Owner, "source_ref")
	if err != nil {
		t.Fatal(err)
	}
	sourceRef = string(plain)
	if !strings.HasPrefix(sourceRef, "g:"+f.Store.GmailEmailHash("second@gmail.test")[:16]+":") {
		t.Fatal("transaction was not imported from the new mailbox")
	}
}

// A transaction already imported through the legacy IMAP/device path must not be imported a second
// time when the Gmail API backfills the same notification with a different source identity.
func TestGmailBackfillMergesExistingIMAPRow(t *testing.T) {
	ctx := context.Background()
	f := newSyncFixture(t)
	f.connect(t, "100")
	eventAt := time.Date(2026, 11, 20, 2, 0, 0, 0, time.UTC) // 09:00 WIB
	job, err := f.Store.CreateImportJob(ctx, f.Owner, "2026-11", "livin-v1", f.Now)
	if err != nil {
		t.Fatal(err)
	}
	imapCandidate := store.ImportCandidate{
		Fingerprint:   f.Store.IngestFingerprint("1234:42", "KOPI KENANGAN", "DEBIT", 25000, eventAt),
		SourceRef:     "1234:42",
		Status:        "PARSED",
		Direction:     "DEBIT",
		AmountMinor:   25000,
		EventAt:       eventAt,
		ParserVersion: "livin-v1",
		Confidence:    1,
		Description:   "Pembayaran Berhasil",
		MerchantLabel: "KOPI KENANGAN",
	}
	if _, _, _, err := f.Store.ImportBatch(ctx, f.Owner, job.ID, "p0", "hash-imap", 0,
		[]store.ImportCandidate{imapCandidate}, f.Now); err != nil {
		t.Fatal(err)
	}
	if got := f.transactionCount(t); got != 1 {
		t.Fatalf("legacy import rows = %d", got)
	}

	f.Provider.Pages = []MessageList{{Messages: []MessageRef{{ID: "same-tx"}}}}
	f.Provider.RawByID = map[string]RawMessage{
		"same-tx": {ID: "same-tx", Raw: rawEmail("Pembayaran Berhasil", livinBodyFor("20 Nov 2026 09:00:00"))},
	}
	if _, err := f.Service.RunOnce(ctx); err != nil {
		t.Fatalf("gmail backfill: %v", err)
	}
	if got := f.transactionCount(t); got != 1 {
		t.Fatalf("gmail backfill duplicated the IMAP row: %d transactions", got)
	}
	// The Gmail import job has its own row counts; the merged notification is a duplicate.
	var gmailImported int
	if err := f.Store.DB.QueryRow(`SELECT imported_count FROM import_jobs
		WHERE owner_id = ? AND month_id = '2026-11' AND id <> ? ORDER BY started_at DESC LIMIT 1`,
		f.Owner, job.ID).Scan(&gmailImported); err != nil {
		t.Fatal(err)
	}
	if gmailImported != 0 {
		t.Fatalf("cross-source merge inserted %d rows, want 0", gmailImported)
	}
}

// A revoked/expired token must stop automatic sync instead of being retried on every tick; only a
// reconnect (which resets the connection row) makes the coordinator try again.
func TestNeedsReauthStopsAutomaticRetry(t *testing.T) {
	ctx := context.Background()
	f := newSyncFixture(t)
	f.connect(t, "100")
	f.OAuth.RefreshErr = ErrUnauthorized
	report, _ := f.Service.RunOnce(ctx)
	if report.Failures == 0 {
		t.Fatalf("refresh failure must be reported: %+v", report)
	}
	connection, err := f.Store.GetGmailConnection(ctx, f.Owner)
	if err != nil {
		t.Fatal(err)
	}
	if connection.LastErrorCode != "needs_reauth" {
		t.Fatalf("last error code = %q, want needs_reauth", connection.LastErrorCode)
	}
	f.OAuth.RefreshErr = nil
	report, err = f.Service.RunOnce(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if report.Failures != 1 || f.Provider.ListCalls != 0 {
		t.Fatalf("needs_reauth retried automatically: report=%+v listCalls=%d", report,
			f.Provider.ListCalls)
	}
	// Reconnecting resets the state and clears the backoff.
	if _, err := f.Store.SaveGmailConnection(ctx, store.GmailConnectionInput{
		OwnerID: f.Owner, AccountEmail: "user@gmail.test",
		Scope:        "https://www.googleapis.com/auth/gmail.readonly",
		RefreshToken: "refresh-1", WatchExpiresAt: f.Now.Add(6 * 24 * time.Hour),
		HistoryCursor: "100", Now: f.Now,
	}); err != nil {
		t.Fatal(err)
	}
	f.Provider.Pages = []MessageList{{Messages: []MessageRef{{ID: "m1"}}}}
	f.Provider.RawByID = map[string]RawMessage{
		"m1": {ID: "m1", Raw: rawEmail("Pembayaran Berhasil!", livinBodyFor("10 Nov 2026 09:30:45"))},
	}
	f.Provider.ListCalls = 0
	if _, err := f.Service.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if got := f.transactionCount(t); got != 1 {
		t.Fatalf("reconnect did not resume sync: %d", got)
	}
}

// Concurrent delta schedulers must converge on a single open job instead of two writers.
func TestEnsureDeltaJobIsSingleFlight(t *testing.T) {
	ctx := context.Background()
	f := newSyncFixture(t)
	f.connect(t, "100")
	ids := make([]string, 8)
	var wg sync.WaitGroup
	for index := range ids {
		wg.Add(1)
		go func(slot int) {
			defer wg.Done()
			job, err := f.Store.EnsureGmailDeltaJob(ctx, f.Owner, f.Now.Add(-48*time.Hour), f.Now, f.Now)
			if err != nil {
				t.Errorf("ensure delta: %v", err)
				return
			}
			ids[slot] = job.ID
		}(index)
	}
	wg.Wait()
	for _, id := range ids {
		if id != ids[0] {
			t.Fatalf("delta jobs diverged: %v", ids)
		}
	}
	var open int
	if err := f.Store.DB.QueryRow(`SELECT COUNT(*) FROM gmail_sync_jobs
		WHERE owner_id = ? AND kind = 'DELTA' AND state IN ('CREATED','RUNNING')`,
		f.Owner).Scan(&open); err != nil {
		t.Fatal(err)
	}
	if open != 1 {
		t.Fatalf("open delta jobs = %d, want 1", open)
	}
}

// An expired cursor recovery that hits the per-tick page bound must resume from its checkpoint on
// the next tick; the fresh cursor may only be stored after the whole re-scan is durably imported.
func TestRecoveryResumesFromCheckpoint(t *testing.T) {
	ctx := context.Background()
	f := newSyncFixture(t)
	f.Service.Settings.MaxPagesPerRun = 1
	connection := f.connect(t, "100")
	f.Provider.HistoryErr = &APIError{Status: 404, Code: "not_found", Expired: true}
	f.Provider.RawByID = map[string]RawMessage{
		"m1": {ID: "m1", Raw: rawEmail("Transaksi Berhasil", livinBodyFor("10 Nov 2026 09:00:00"))},
		"m2": {ID: "m2", Raw: rawEmail("Transaksi Berhasil", livinBodyFor("11 Nov 2026 10:00:00"))},
	}
	f.Provider.Pages = []MessageList{
		{Messages: []MessageRef{{ID: "m1"}}, NextPageToken: "page-2"},
		{Messages: []MessageRef{{ID: "m2"}}},
	}
	f.Provider.ProfileValue = Profile{EmailAddress: "user@gmail.test", HistoryID: "900"}
	if err := f.Service.runDelta(ctx, connection, "access-1"); err != nil {
		t.Fatalf("first recovery tick: %v", err)
	}
	mid, err := f.Store.GetGmailConnection(ctx, f.Owner)
	if err != nil {
		t.Fatal(err)
	}
	if mid.HistoryCursor != "100" {
		t.Fatalf("cursor advanced before the recovery finished: %q", mid.HistoryCursor)
	}
	var jobState string
	if err := f.Store.DB.QueryRow(`SELECT state FROM gmail_sync_jobs
		WHERE owner_id = ? AND kind = 'DELTA'`, f.Owner).Scan(&jobState); err != nil {
		t.Fatal(err)
	}
	if jobState != "RUNNING" {
		t.Fatalf("bounded recovery job state = %s, want RUNNING", jobState)
	}
	connection, err = f.Store.GetGmailConnection(ctx, f.Owner)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Service.runDelta(ctx, connection, "access-1"); err != nil {
		t.Fatalf("second recovery tick: %v", err)
	}
	recovered, err := f.Store.GetGmailConnection(ctx, f.Owner)
	if err != nil {
		t.Fatal(err)
	}
	if recovered.HistoryCursor != "900" {
		t.Fatalf("cursor = %q, want fresh 900 after resume", recovered.HistoryCursor)
	}
	if got := f.transactionCount(t); got != 2 {
		t.Fatalf("recovery imported %d rows, want 2", got)
	}
}
