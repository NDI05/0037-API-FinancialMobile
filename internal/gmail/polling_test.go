package gmail

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pam/recap/backend-go/internal/config"
	"github.com/pam/recap/backend-go/internal/store"
)

// newPollingFixture builds the same deterministic store as the push fixtures but with the polling
// transport (the default), a 15 minute delta cadence and a 60 second manual-sync cooldown.
func newPollingFixture(t *testing.T, backfillMonths int) *syncFixture {
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
	if _, err := data.CreateAccount(ctx, "gmail-poll@example.test", "Uji",
		store.PasswordDigest{Salt: []byte("salt"), Hash: []byte("hash"),
			KDF: "scrypt:N=32768,r=8,p=1"}, now); err != nil {
		t.Fatal(err)
	}
	provider := &FakeProvider{ProfileValue: Profile{EmailAddress: "user@gmail.test", HistoryID: "900"}}
	exchanger := &FakeExchanger{ByRefresh: map[string]TokenSet{
		"refresh-1": {AccessToken: "access-1", RefreshToken: "refresh-1",
			Expiry: now.Add(time.Hour), Scope: "https://www.googleapis.com/auth/gmail.readonly"},
	}}
	service := NewService(data, provider, exchanger, Settings{
		RedirectURI:    "https://api.example.test/v1/gmail/connect/callback",
		Mode:           "polling",
		BackfillMonths: backfillMonths, PageSize: 10, MaxPagesPerRun: 5,
		DeltaInterval: 15 * time.Minute, SyncCooldown: 60 * time.Second,
		WatchRenewBefore: 24 * time.Hour,
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	service.Now = func() time.Time { return now }
	service.Categories = &fakeCategories{}
	return &syncFixture{Service: service, Store: data, Provider: provider, OAuth: exchanger,
		Categories: service.Categories.(*fakeCategories), Owner: store.OwnerIDForEmail("gmail-poll@example.test"),
		Now: now}
}

// completeBackfill marks every rolling-window month complete so tests can exercise delta/heartbeat
// behaviour without the staged backfill also running.
func (f *syncFixture) completeBackfill(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	for _, month := range rollingMonths(f.Now, f.Service.Settings.BackfillMonths) {
		start, end := monthWindow(month)
		job, err := f.Store.EnsureGmailBackfillJob(ctx, f.Owner, month, start, end, f.Now)
		if err != nil {
			t.Fatal(err)
		}
		if err := f.Store.FinishGmailSyncJob(ctx, f.Owner, job.ID, "COMPLETE", "", f.Now); err != nil {
			t.Fatal(err)
		}
	}
}

func (f *syncFixture) connection(t *testing.T) store.GmailConnection {
	t.Helper()
	connection, err := f.Store.GetGmailConnection(context.Background(), f.Owner)
	if err != nil {
		t.Fatal(err)
	}
	return connection
}

func TestPollingConnectNeverCallsWatchOrStop(t *testing.T) {
	ctx := context.Background()
	f := newPollingFixture(t, 1)
	f.connect(t, "100")
	f.Provider.Pages = []MessageList{{}}
	if _, err := f.Service.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if f.Provider.WatchCalls != 0 {
		t.Fatalf("polling registered a watch: %d", f.Provider.WatchCalls)
	}
	if err := f.Service.Disconnect(ctx, f.Owner); err != nil {
		t.Fatal(err)
	}
	if f.Provider.StopCalls != 0 || f.Provider.WatchCalls != 0 {
		t.Fatalf("polling disconnect touched watch endpoints: watch=%d stop=%d",
			f.Provider.WatchCalls, f.Provider.StopCalls)
	}
	if f.OAuth.Revokes != 1 {
		t.Fatalf("disconnect must still revoke the grant: %d", f.OAuth.Revokes)
	}
}

func TestPollingIdleOwnerMakesZeroProviderCalls(t *testing.T) {
	ctx := context.Background()
	f := newPollingFixture(t, 12)
	f.connect(t, "100")
	f.completeBackfill(t)
	if err := f.Store.RecordGmailAttempt(ctx, f.Owner, f.Now); err != nil {
		t.Fatal(err)
	}
	before := f.Provider.ListCalls + f.Provider.HistoryCalls + f.OAuth.Refreshes
	if _, err := f.Service.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if got := f.Provider.ListCalls + f.Provider.HistoryCalls + f.OAuth.Refreshes; got != before {
		t.Fatalf("idle connection made provider calls: %d", got-before)
	}
	status, err := f.Service.Status(ctx, f.Owner)
	if err != nil {
		t.Fatal(err)
	}
	if status.SyncState != "idle" || status.Progress.MonthsDone != 12 ||
		status.Progress.MonthsTotal != 12 || status.NextSyncAt.IsZero() {
		t.Fatalf("idle status = %#v", status)
	}
}

func TestPollingDeltaRunsAfterInterval(t *testing.T) {
	ctx := context.Background()
	f := newPollingFixture(t, 12)
	f.connect(t, "100")
	f.completeBackfill(t)
	if err := f.Store.RecordGmailAttempt(ctx, f.Owner, f.Now.Add(-16*time.Minute)); err != nil {
		t.Fatal(err)
	}
	f.Provider.HistoryPages = []HistoryPage{{MessageIDs: []string{"m1"}, LatestHistoryID: "950"}}
	f.Provider.RawByID = map[string]RawMessage{"m1": {ID: "m1", Raw: rawEmail(
		"Pembayaran Berhasil!", livinBodyFor("24 Nov 2026 09:00:00"))}}
	if _, err := f.Service.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if f.Provider.HistoryCalls != 1 || f.transactionCount(t) != 1 {
		t.Fatalf("delta did not run: history=%d transactions=%d", f.Provider.HistoryCalls,
			f.transactionCount(t))
	}
	if cursor := f.connection(t).HistoryCursor; cursor != "950" {
		t.Fatalf("cursor = %q", cursor)
	}
}

func TestManualSyncCooldownThenCoalesces(t *testing.T) {
	ctx := context.Background()
	f := newPollingFixture(t, 12)
	f.connect(t, "100")
	f.completeBackfill(t)
	now := f.Now
	f.Service.Now = func() time.Time { return now }

	first, err := f.Service.RequestSync(ctx, f.Owner)
	if err != nil {
		t.Fatal(err)
	}
	if first.Coalesced || first.NextAllowedAt.Sub(first.RequestedAt) != time.Minute {
		t.Fatalf("first sync = %#v", first)
	}
	if _, err := f.Service.RequestSync(ctx, f.Owner); !errors.Is(err, ErrSyncCooldown) {
		t.Fatalf("second sync error = %v", err)
	}
	now = now.Add(61 * time.Second)
	coalesced, err := f.Service.RequestSync(ctx, f.Owner)
	if err != nil {
		t.Fatal(err)
	}
	if !coalesced.Coalesced {
		t.Fatalf("open delta job must coalesce: %#v", coalesced)
	}
}

func TestManualSyncSurvivesRestartWithoutDuplicates(t *testing.T) {
	ctx := context.Background()
	f := newPollingFixture(t, 12)
	f.connect(t, "100")
	f.completeBackfill(t)

	// Queue the delta, then abandon this service instance: the restart below keeps only the
	// store (same encryption key) and the provider, exactly like a process restart.
	if _, err := f.Service.RequestSync(ctx, f.Owner); err != nil {
		t.Fatal(err)
	}
	if status, err := f.Service.Status(ctx, f.Owner); err != nil || status.SyncState != "delta" {
		t.Fatalf("queued status = %#v err=%v", status, err)
	}
	restarted := NewService(f.Store, f.Provider, f.OAuth, f.Service.Settings,
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	restarted.Now = f.Service.Now
	restarted.Categories = f.Categories

	f.Provider.HistoryPages = []HistoryPage{{MessageIDs: []string{"restart-1"}, LatestHistoryID: "950"}}
	f.Provider.RawByID = map[string]RawMessage{"restart-1": {ID: "restart-1", Raw: rawEmail(
		"Pembayaran Berhasil!", livinBodyFor("24 Nov 2026 09:00:00"))}}
	report, err := restarted.RunOnce(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if report.Deltas != 1 || f.transactionCount(t) != 1 {
		t.Fatalf("restart delta report=%#v transactions=%d", report, f.transactionCount(t))
	}
	status, err := restarted.Status(ctx, f.Owner)
	if err != nil || status.SyncState != "idle" {
		t.Fatalf("post-delta status = %#v err=%v", status, err)
	}
	// A replay of the same history page must not duplicate the transaction.
	f.Provider.HistoryPages = []HistoryPage{{MessageIDs: []string{"restart-1"}, LatestHistoryID: "950"}}
	if _, err := restarted.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if f.transactionCount(t) != 1 {
		t.Fatalf("replay duplicated transactions: %d", f.transactionCount(t))
	}
}

func TestRecoveryAfterHistoryExpiryCoversDowntimeAndNewMail(t *testing.T) {
	ctx := context.Background()
	f := newPollingFixture(t, 12)
	f.connect(t, "100")
	f.completeBackfill(t)
	if _, err := f.Store.DB.Exec(`UPDATE gmail_connections SET last_success_at = ?
		WHERE owner_id = ?`, "2026-09-20T00:00:00Z", f.Owner); err != nil {
		t.Fatal(err)
	}
	if err := f.Store.RecordGmailAttempt(ctx, f.Owner, f.Now.Add(-16*time.Minute)); err != nil {
		t.Fatal(err)
	}

	var mu sync.Mutex
	order := []string{}
	queries := []string{}
	f.Provider.OnProfile = func(context.Context) (Profile, error) {
		mu.Lock()
		order = append(order, "profile")
		mu.Unlock()
		return Profile{EmailAddress: "user@gmail.test", HistoryID: "900"}, nil
	}
	f.Provider.OnList = func(_ context.Context, query, _ string) (MessageList, error) {
		mu.Lock()
		order = append(order, "list")
		queries = append(queries, query)
		mu.Unlock()
		month := ""
		if index := strings.Index(query, "after:"); index >= 0 {
			rest := strings.TrimPrefix(query[index:], "after:")
			if space := strings.IndexByte(rest, ' '); space >= 0 {
				rest = rest[:space]
			}
			if seconds, parseErr := strconv.ParseInt(rest, 10, 64); parseErr == nil {
				month = time.Unix(seconds, 0).In(jakarta).Format("2006-01")
			}
		}
		switch month {
		case "2026-09":
			return MessageList{Messages: []MessageRef{{ID: "sep-1"}}}, nil
		case "2026-10":
			return MessageList{Messages: []MessageRef{{ID: "oct-1"}}}, nil
		default:
			return MessageList{Messages: []MessageRef{{ID: "nov-1"}}}, nil
		}
	}
	f.Provider.RawByID = map[string]RawMessage{
		"sep-1": {ID: "sep-1", Raw: rawEmail("Pembayaran Berhasil!", livinBodyFor("21 Sep 2026 08:00:00"))},
		"oct-1": {ID: "oct-1", Raw: rawEmail("Pembayaran Berhasil!", livinBodyFor("02 Oct 2026 08:00:00"))},
		"nov-1": {ID: "nov-1", Raw: rawEmail("Pembayaran Berhasil!", livinBodyFor("01 Nov 2026 08:00:00"))},
		"new-1": {ID: "new-1", Raw: rawEmail("Pembayaran Berhasil!", livinBodyFor("24 Nov 2026 09:30:00"))},
	}
	historyCalls := 0
	f.Provider.OnHistory = func(context.Context, string, string) (HistoryPage, error) {
		mu.Lock()
		defer mu.Unlock()
		historyCalls++
		if historyCalls == 1 {
			return HistoryPage{}, &APIError{Status: 404, Code: "not_found", Expired: true}
		}
		return HistoryPage{MessageIDs: []string{"new-1"}, LatestHistoryID: "1100"}, nil
	}

	if _, err := f.Service.RunOnce(ctx); err != nil {
		t.Fatalf("recovery run failed: %v", err)
	}
	if got := f.transactionCount(t); got != 4 {
		t.Fatalf("recovered transactions = %d, want 4", got)
	}
	connection := f.connection(t)
	if connection.HistoryCursor != "1100" {
		t.Fatalf("cursor after replay = %q", connection.HistoryCursor)
	}
	if connection.SyncState != "idle" || connection.LastErrorCode != "" {
		t.Fatalf("state after recovery = %q %q", connection.SyncState, connection.LastErrorCode)
	}
	mu.Lock()
	firstProfile := len(order) > 0 && order[0] == "profile"
	hadUnixQuery := false
	for _, query := range queries {
		if strings.Contains(query, "after:") && strings.Contains(query, "before:") &&
			!strings.Contains(query, "after:2026/") {
			hadUnixQuery = true
		}
	}
	mu.Unlock()
	if !firstProfile {
		t.Fatalf("baseline profile must be captured before the scan: %v", order)
	}
	if !hadUnixQuery {
		t.Fatalf("recovery queries missing unix bounds: %v", queries)
	}

	// A later tick must not lose or duplicate anything.
	if _, err := f.Service.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if got := f.transactionCount(t); got != 4 {
		t.Fatalf("replay duplicated transactions: %d", got)
	}
}

func TestRateLimitRetriesThenRequeuesWithoutReauth(t *testing.T) {
	ctx := context.Background()
	f := newPollingFixture(t, 12)
	f.connect(t, "100")
	f.completeBackfill(t)
	if err := f.Store.RecordGmailAttempt(ctx, f.Owner, f.Now.Add(-16*time.Minute)); err != nil {
		t.Fatal(err)
	}
	calls := 0
	f.Provider.OnHistory = func(context.Context, string, string) (HistoryPage, error) {
		calls++
		if calls <= 3 {
			return HistoryPage{}, &APIError{Status: 403, Code: "rate_limited"}
		}
		return HistoryPage{LatestHistoryID: "100"}, nil
	}
	report, err := f.Service.RunOnce(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if report.Failures == 0 {
		t.Fatal("exhausted retries must be reported as a failure")
	}
	connection := f.connection(t)
	status, statusErr := f.Service.Status(ctx, f.Owner)
	if statusErr != nil {
		t.Fatal(statusErr)
	}
	if connection.LastErrorCode != "rate_limited" || status.NeedsReauth ||
		connection.SyncState == "error" || connection.State != "ACTIVE" {
		t.Fatalf("rate limit treated as permanent: state=%q code=%q reauth=%v",
			connection.SyncState, connection.LastErrorCode, status.NeedsReauth)
	}
	if _, open, err := f.Store.OpenGmailDeltaJob(ctx, f.Owner); err != nil || !open {
		t.Fatalf("delta job not requeued: open=%v err=%v", open, err)
	}
	if _, err := f.Service.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	connection = f.connection(t)
	if connection.SyncState != "idle" || connection.LastErrorCode != "" {
		t.Fatalf("retry did not clear the transient failure: %#v", connection)
	}
}

func TestAccessTokenIsReusedUntilNearExpiry(t *testing.T) {
	ctx := context.Background()
	f := newPollingFixture(t, 1)
	connection := f.connect(t, "100")
	if _, err := f.Service.accessToken(ctx, connection); err != nil {
		t.Fatal(err)
	}
	if f.OAuth.Refreshes != 1 {
		t.Fatalf("first use refresh = %d", f.OAuth.Refreshes)
	}
	connection = f.connection(t)
	if _, err := f.Service.accessToken(ctx, connection); err != nil {
		t.Fatal(err)
	}
	if f.OAuth.Refreshes != 1 {
		t.Fatalf("cached token was refreshed again: %d", f.OAuth.Refreshes)
	}
	if err := f.Store.UpdateGmailAccessToken(ctx, f.Owner, "access-old",
		f.Now.Add(time.Minute), f.Now); err != nil {
		t.Fatal(err)
	}
	connection = f.connection(t)
	if _, err := f.Service.accessToken(ctx, connection); err != nil {
		t.Fatal(err)
	}
	if f.OAuth.Refreshes != 2 {
		t.Fatalf("near-expiry token was not refreshed: %d", f.OAuth.Refreshes)
	}
}

func TestDevFakeFixtureServesParsedLivinAndScenarios(t *testing.T) {
	fixture := `{"profile":{"emailAddress":"pilot@pam.test","historyId":"1000"},` +
		`"messages":[{"id":"fx-1","eventAt":"2026-11-20T04:30:00Z","amountMinor":25000,` +
		`"direction":"DEBIT","merchantLabel":"QA MERCHANT"}],` +
		`"messagesByMonth":{"2026-11":{"pages":[["fx-1"]]}},` +
		`"historyPages":[{"messageIds":["fx-delta-1"],"latestHistoryId":"1010"}]}`
	path := filepath.Join(t.TempDir(), "fixture.json")
	if err := os.WriteFile(path, []byte(fixture), 0o600); err != nil {
		t.Fatal(err)
	}
	provider, err := LoadDevFixture(path, DevScenarioNormal)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	page, err := provider.ListMessages(ctx, "", "after:2026/11/01 before:2026/12/01", "", 10)
	if err != nil || len(page.Messages) != 1 || page.Messages[0].ID != "fx-1" {
		t.Fatalf("list = %#v err=%v", page, err)
	}
	raw, err := provider.GetMessage(ctx, "", "fx-1")
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeMessage(raw.Raw)
	if err != nil {
		t.Fatalf("fixture raw is not a valid RFC 822 message: %v", err)
	}
	parsed := ParseLivinNotification(decoded)
	if parsed.AmountMinor != 25000 || parsed.Direction != "DEBIT" || parsed.MerchantLabel != "QA MERCHANT" {
		t.Fatalf("parsed fixture = %#v", parsed)
	}

	expired, err := LoadDevFixture(path, DevScenarioHistoryExpired)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := expired.History(ctx, "", "900", "", 10); !IsHistoryExpired(err) {
		t.Fatalf("history_expired scenario = %v", err)
	}
	if _, err := expired.History(ctx, "", "900", "", 10); err != nil {
		t.Fatalf("second history call must recover: %v", err)
	}

	limited, err := LoadDevFixture(path, DevScenarioRateLimit)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := limited.ListMessages(ctx, "", "after:2026/11/01", "", 10); !IsRateLimited(err) {
		t.Fatalf("rate_limit scenario = %v", err)
	}
	if _, err := limited.ListMessages(ctx, "", "after:2026/11/01", "", 10); err != nil {
		t.Fatalf("rate limit must recover: %v", err)
	}
	if !DevScenarioValid(DevScenarioNormal) || DevScenarioValid("bogus") {
		t.Fatal("scenario validation")
	}
}
