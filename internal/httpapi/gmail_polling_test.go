package httpapi

import (
	"context"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/pam/recap/backend-go/internal/gmail"
	"github.com/pam/recap/backend-go/internal/store"
)

// newGmailPollingHarness attaches a polling-mode Gmail service. With devFake it also enables the
// fixture provider/exchanger and the backend-served consent page used for physical UAT.
func newGmailPollingHarness(t *testing.T, devFake bool) *gmailHarness {
	t.Helper()
	h := newHarness(t)
	var provider gmail.Provider
	provider = &gmail.FakeProvider{
		ProfileValue: gmail.Profile{EmailAddress: "user@gmail.test", HistoryID: "900"},
		Pages:        []gmail.MessageList{{}},
	}
	oauth := &gmail.FakeExchanger{
		ByCode: map[string]gmail.TokenSet{
			"code-good": {AccessToken: "access-1", RefreshToken: "refresh-1",
				Expiry: time.Now().Add(time.Hour),
				Scope:  "https://www.googleapis.com/auth/gmail.readonly"},
		},
		ByRefresh: map[string]gmail.TokenSet{
			"refresh-1": {AccessToken: "access-1", RefreshToken: "refresh-1",
				Expiry: time.Now().Add(time.Hour),
				Scope:  "https://www.googleapis.com/auth/gmail.readonly"},
		},
	}
	fixturePath := ""
	if devFake {
		path := t.TempDir() + "/gmail-fake-fixture.json"
		writeDevFixture(t, path)
		fake, err := gmail.LoadDevFixture(path, gmail.DevScenarioNormal)
		if err != nil {
			t.Fatal(err)
		}
		provider = fake
		fixturePath = path
		_ = fixturePath
		oauth = &gmail.FakeExchanger{AcceptAnyCode: true, DefaultTokens: gmail.TokenSet{
			AccessToken: "dev-access", RefreshToken: "dev-refresh",
			Expiry: time.Now().Add(time.Hour),
			Scope:  "https://www.googleapis.com/auth/gmail.readonly"}}
	}
	service := gmail.NewService(h.store, provider, oauth, gmail.Settings{
		RedirectURI:    "http://127.0.0.1:18090/v1/gmail/connect/callback",
		Mode:           "polling",
		AppDeepLink:    "pam://gmail/connected",
		BackfillMonths: 12, PageSize: 2, MaxPagesPerRun: 2,
		DeltaInterval: 15 * time.Minute, SyncCooldown: time.Minute,
		DevFake: devFake, DevScenario: gmail.DevScenarioNormal,
	}, testLogger())
	// The internal push verifier stays nil: polling must expose a 404 on that route.
	h.api.SetGmail(service, nil)
	fakeProvider, _ := provider.(*gmail.FakeProvider)
	return &gmailHarness{harness: h, service: service, provider: fakeProvider, oauth: oauth}
}

func writeDevFixture(t *testing.T, path string) {
	t.Helper()
	fixture := `{"profile":{"emailAddress":"pilot@pam.test","historyId":"1000"},` +
		`"messages":[{"id":"fx-1","eventAt":"2026-11-20T04:30:00Z","amountMinor":25000,` +
		`"direction":"DEBIT","merchantLabel":"QA MERCHANT"}],` +
		`"messagesByMonth":{"2026-11":{"pages":[["fx-1"]]}},` +
		`"historyPages":[{"messageIds":[],"latestHistoryId":"1000"}]}`
	if err := writeFile(path, fixture); err != nil {
		t.Fatal(err)
	}
}

func TestGmailPollingSyncQueueStatusAndPushAbsence(t *testing.T) {
	h := newGmailPollingHarness(t, false)
	h.register("polling@example.test")
	token, _ := h.login("polling@example.test")

	status, body := h.request("GET", "/v1/gmail/status", token, nil)
	if status != 200 || body["connected"] != false {
		t.Fatalf("initial polling status = %d %#v", status, body)
	}
	if _, ok := body["needs_reauth"]; !ok {
		t.Fatalf("status must expose needs_reauth: %#v", body)
	}
	if body["progress"] != nil {
		t.Fatalf("disconnected status must not have progress: %#v", body["progress"])
	}

	startStatus, start := h.request("POST", "/v1/gmail/connect/start", token, map[string]any{})
	if startStatus != 200 {
		t.Fatalf("start = %d %#v", startStatus, start)
	}
	authorization := start["authorization_url"].(string)
	parsed, err := url.Parse(authorization)
	if err != nil || parsed.Query().Get("state") == "" {
		t.Fatalf("authorization url = %q", authorization)
	}
	callback, _ := h.rawRoundTrip("GET", "/v1/gmail/connect/callback?code=code-good&state="+
		url.QueryEscape(parsed.Query().Get("state")), nil, nil)
	if callback.StatusCode != 302 || !strings.Contains(callback.Header.Get("Location"), "status=success") {
		t.Fatalf("callback = %d %s", callback.StatusCode, callback.Header.Get("Location"))
	}

	status, body = h.request("GET", "/v1/gmail/status", token, nil)
	if status != 200 || body["connected"] != true || body["needs_reauth"] != false {
		t.Fatalf("connected polling status = %d %#v", status, body)
	}
	progress, ok := body["progress"].(map[string]any)
	if !ok || progress["months_total"].(float64) != 12 {
		t.Fatalf("progress = %#v", body["progress"])
	}
	for _, field := range []string{"last_attempt_at", "last_success_at", "next_sync_at",
		"sync_requested_at"} {
		if _, ok := body[field]; !ok {
			t.Fatalf("status missing %s: %#v", field, body)
		}
	}

	if status, _ := h.request("POST", "/v1/gmail/sync", "", nil); status != 401 {
		t.Fatalf("anonymous sync = %d", status)
	}
	status, syncBody := h.request("POST", "/v1/gmail/sync", token, nil)
	if status != 202 || syncBody["queued"] != true || syncBody["coalesced"] != false {
		t.Fatalf("first sync = %d %#v", status, syncBody)
	}
	status, cooldown := h.request("POST", "/v1/gmail/sync", token, nil)
	if status != 429 || cooldown["code"] != "sync_cooldown" {
		t.Fatalf("second sync = %d %#v", status, cooldown)
	}
	if cooldown["retryable"] != true {
		t.Fatalf("cooldown retryable = %#v", cooldown["retryable"])
	}
	if retry, _ := cooldown["retryAfterSeconds"].(float64); retry <= 0 {
		t.Fatalf("cooldown retryAfterSeconds = %#v", cooldown["retryAfterSeconds"])
	}
	if _, ok := cooldown["retry_after_seconds"]; ok {
		t.Fatalf("cooldown must use contract camelCase: %#v", cooldown)
	}
	if status, queuedStatus := h.request("GET", "/v1/gmail/status", token, nil); status != 200 ||
		queuedStatus["sync_state"] != "delta" || queuedStatus["sync_requested_at"] == nil {
		t.Fatalf("queued status = %d %#v", status, queuedStatus)
	}
	// The worker drains the durable job; the pending marker must disappear with it.
	if _, err := h.service.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if status, drained := h.request("GET", "/v1/gmail/status", token, nil); status != 200 ||
		drained["sync_state"] != "idle" || drained["sync_requested_at"] != nil {
		t.Fatalf("drained status = %d %#v", status, drained)
	}

	h.register("polling-other@example.test")
	other, _ := h.login("polling-other@example.test")
	if status, otherBody := h.request("POST", "/v1/gmail/sync", other, nil); status != 409 ||
		otherBody["code"] != "gmail_not_connected" {
		t.Fatalf("not-connected sync = %d %#v", status, otherBody)
	}

	response, _ := h.rawRoundTrip("POST", "/v1/internal/gmail/push", nil, []byte("{}"))
	if response.StatusCode != 404 {
		t.Fatalf("polling push route = %d, want 404", response.StatusCode)
	}
	if status, _ := h.request("GET", "/v1/gmail/dev/stats", token, nil); status != 404 {
		t.Fatalf("dev stats without fake = %d, want 404", status)
	}
}

func TestGmailDevFakeConsentFlow(t *testing.T) {
	h := newGmailPollingHarness(t, true)
	h.register("devfake@example.test")
	token, _ := h.login("devfake@example.test")

	status, start := h.request("POST", "/v1/gmail/connect/start", token, map[string]any{})
	if status != 200 {
		t.Fatalf("start = %d %#v", status, start)
	}
	authorization := start["authorization_url"].(string)
	// The URL is built from the request host, never a hardcoded port.
	if !strings.HasPrefix(authorization, h.server.URL+"/v1/gmail/connect/dev/authorize?") {
		t.Fatalf("dev authorization url = %q", authorization)
	}
	parsed, err := url.Parse(authorization)
	if err != nil {
		t.Fatal(err)
	}
	state := parsed.Query().Get("state")

	page, pageRaw := h.rawRoundTrip("GET", parsed.RequestURI(), nil, nil)
	if page.StatusCode != 200 || !strings.Contains(string(pageRaw), "PAM Gmail dev consent") {
		t.Fatalf("consent page = %d", page.StatusCode)
	}
	unknown, _ := h.rawRoundTrip("GET",
		"/v1/gmail/connect/dev/authorize?state=bogus", nil, nil)
	if unknown.StatusCode != 400 {
		t.Fatalf("bogus state = %d", unknown.StatusCode)
	}

	approve, _ := h.rawRoundTrip("GET",
		"/v1/gmail/connect/dev/approve?state="+url.QueryEscape(state)+"&approve=1", nil, nil)
	if approve.StatusCode != 302 {
		t.Fatalf("approve = %d", approve.StatusCode)
	}
	location, err := url.Parse(approve.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(approve.Header.Get("Location"),
		"http://127.0.0.1:18090/v1/gmail/connect/callback?") {
		t.Fatalf("approve location = %q", approve.Header.Get("Location"))
	}
	code := location.Query().Get("code")
	if code == "" || location.Query().Get("state") != state {
		t.Fatalf("approve query = %q", approve.Header.Get("Location"))
	}
	callback, _ := h.rawRoundTrip("GET", "/v1/gmail/connect/callback?code="+
		url.QueryEscape(code)+"&state="+url.QueryEscape(state), nil, nil)
	if callback.StatusCode != 302 ||
		!strings.Contains(callback.Header.Get("Location"), "status=success") {
		t.Fatalf("dev callback = %d %s", callback.StatusCode, callback.Header.Get("Location"))
	}

	status, body := h.request("GET", "/v1/gmail/status", token, nil)
	if status != 200 || body["connected"] != true {
		t.Fatalf("dev connected status = %d %#v", status, body)
	}
	if body["account_email_masked"] == "pilot@pam.test" {
		t.Fatal("dev status leaked the fixture mailbox")
	}
	if status, _ := h.request("GET", "/v1/gmail/dev/stats", "", nil); status != 401 {
		t.Fatalf("anonymous dev stats = %d", status)
	}
	status, stats := h.request("GET", "/v1/gmail/dev/stats", token, nil)
	if status != 200 {
		t.Fatalf("dev stats = %d %#v", status, stats)
	}
	if stats["watchCalls"].(float64) != 0 || stats["stopCalls"].(float64) != 0 {
		t.Fatalf("polling dev stats touched watch: %#v", stats)
	}
}

func writeFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0o600)
}

func TestGmailSyncRejectedWhenNeedsReauth(t *testing.T) {
	h := newGmailPollingHarness(t, false)
	h.register("reauth@example.test")
	token, _ := h.login("reauth@example.test")
	startStatus, start := h.request("POST", "/v1/gmail/connect/start", token, map[string]any{})
	if startStatus != 200 {
		t.Fatalf("start = %d %#v", startStatus, start)
	}
	parsed, err := url.Parse(start["authorization_url"].(string))
	if err != nil {
		t.Fatal(err)
	}
	callback, _ := h.rawRoundTrip("GET", "/v1/gmail/connect/callback?code=code-good&state="+
		url.QueryEscape(parsed.Query().Get("state")), nil, nil)
	if callback.StatusCode != 302 {
		t.Fatalf("callback = %d", callback.StatusCode)
	}
	owner := store.OwnerIDForEmail("reauth@example.test")
	if err := h.store.UpdateGmailSyncState(context.Background(), owner, "error", "",
		"needs_reauth", time.Now(), time.Now()); err != nil {
		t.Fatal(err)
	}
	status, body := h.request("POST", "/v1/gmail/sync", token, nil)
	if status != 409 || body["code"] != "gmail_needs_reauth" || body["retryable"] != false {
		t.Fatalf("needs_reauth sync = %d %#v", status, body)
	}
}
