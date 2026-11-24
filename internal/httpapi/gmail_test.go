package httpapi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/pam/recap/backend-go/internal/gmail"
)

// gmailHarness attaches a fake Gmail service to the shared harness. The push verifier accepts one
// fixed bearer token, which is enough to exercise the internal endpoint without Google.
type gmailHarness struct {
	*harness
	service  *gmail.Service
	provider *gmail.FakeProvider
	oauth    *gmail.FakeExchanger
}

func newGmailHarness(t *testing.T) *gmailHarness {
	t.Helper()
	h := newHarness(t)
	provider := &gmail.FakeProvider{
		ProfileValue: gmail.Profile{EmailAddress: "user@gmail.test", HistoryID: "900"},
		WatchState:   gmail.WatchState{Expiration: time.Now().Add(6 * 24 * time.Hour), HistoryID: "900"},
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
	service := gmail.NewService(h.store, provider, oauth, gmail.Settings{
		RedirectURI: "https://api.example.test/v1/gmail/connect/callback",
		TopicName:   "projects/pam/topics/gmail", AppDeepLink: "pam://gmail/connected",
	}, testLogger())
	h.api.SetGmail(service, &gmail.FakePushVerifier{
		Token:  "push-token",
		Claims: gmail.PushClaims{Email: "pubsub@project.iam.gserviceaccount.com", Audience: "push"},
	})
	return &gmailHarness{harness: h, service: service, provider: provider, oauth: oauth}
}

// rawRoundTrip performs one request without following redirects (the deep link is a pam:// URL).
func (h *gmailHarness) rawRoundTrip(method, path string, headers map[string]string,
	body []byte) (*http.Response, []byte) {
	h.t.Helper()
	request, err := http.NewRequest(method, h.server.URL+path, strings.NewReader(string(body)))
	if err != nil {
		h.t.Fatal(err)
	}
	for key, value := range headers {
		request.Header.Set(key, value)
	}
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	response, err := client.Do(request)
	if err != nil {
		h.t.Fatal(err)
	}
	defer response.Body.Close()
	raw, _ := io.ReadAll(response.Body)
	return response, raw
}

func pushBody(t *testing.T, email, historyID, messageID string) []byte {
	t.Helper()
	data, err := json.Marshal(map[string]string{"emailAddress": email, "historyId": historyID})
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(map[string]any{"message": map[string]any{
		"data": base64.StdEncoding.EncodeToString(data), "messageId": messageID,
		"publishTime": "2026-11-24T06:10:00Z",
	}})
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func TestGmailDisabledIsExplicit(t *testing.T) {
	h := newHarness(t)
	h.register("nogmail@example.test")
	token, _ := h.login("nogmail@example.test")
	if status, body := h.request("GET", "/v1/gmail/status", token, nil); status != 503 ||
		body["code"] != "gmail_disabled" {
		t.Fatalf("disabled status = %d %#v", status, body)
	}
	if status, _ := h.request("POST", "/v1/gmail/connect/start", token, map[string]any{}); status != 503 {
		t.Fatalf("disabled start = %d", status)
	}
	if status, _ := h.request("POST", "/v1/gmail/disconnect", token, nil); status != 503 {
		t.Fatalf("disabled disconnect = %d", status)
	}
	// The callback must still land on the deep link so the app can show a message.
	response, _ := (&gmailHarness{harness: h}).rawRoundTrip("GET",
		"/v1/gmail/connect/callback?state=x", nil, nil)
	if response.StatusCode != http.StatusFound ||
		!strings.Contains(response.Header.Get("Location"), "status=error") {
		t.Fatalf("disabled callback = %d %s", response.StatusCode, response.Header.Get("Location"))
	}
}

func TestGmailOAuthFlowStatusAndOwnerIsolation(t *testing.T) {
	h := newGmailHarness(t)
	h.register("gmail-alice@example.test")
	h.register("gmail-bob@example.test")
	alice, _ := h.login("gmail-alice@example.test")
	bob, _ := h.login("gmail-bob@example.test")

	status, body := h.request("GET", "/v1/gmail/status", alice, nil)
	if status != 200 || body["connected"] != false {
		t.Fatalf("initial status = %d %#v", status, body)
	}
	for _, field := range []string{"connected_at", "last_sync_at", "watch_expires_at",
		"account_email_masked", "last_error_code"} {
		if body[field] != nil {
			t.Fatalf("%s must be null when not connected: %#v", field, body[field])
		}
	}

	status, start := h.request("POST", "/v1/gmail/connect/start", alice, map[string]any{})
	if status != 200 {
		t.Fatalf("start = %d %#v", status, start)
	}
	authorization, _ := start["authorization_url"].(string)
	parsed, err := url.Parse(authorization)
	if err != nil || parsed.Query().Get("state") == "" || parsed.Query().Get("code_challenge") == "" {
		t.Fatalf("authorization url invalid: %q", authorization)
	}
	state := parsed.Query().Get("state")

	response, _ := h.rawRoundTrip("GET",
		"/v1/gmail/connect/callback?code=code-good&state="+url.QueryEscape(state), nil, nil)
	location := response.Header.Get("Location")
	if response.StatusCode != http.StatusFound || !strings.Contains(location, "status=success") {
		t.Fatalf("callback = %d %s", response.StatusCode, location)
	}
	if strings.Contains(location, "user@gmail.test") || strings.Contains(location, "refresh") {
		t.Fatalf("redirect leaked mailbox or token: %s", location)
	}
	// The state is single use: a replay must not connect a second mailbox.
	response, _ = h.rawRoundTrip("GET",
		"/v1/gmail/connect/callback?code=code-good&state="+url.QueryEscape(state), nil, nil)
	if location := response.Header.Get("Location"); !strings.Contains(location, "reason=state_invalid") {
		t.Fatalf("replayed state accepted: %s", location)
	}

	status, body = h.request("GET", "/v1/gmail/status", alice, nil)
	if status != 200 || body["connected"] != true {
		t.Fatalf("connected status = %d %#v", status, body)
	}
	email := body["account_email_masked"].(string)
	if strings.Contains(email, "user@gmail.test") || !strings.Contains(email, "***") {
		t.Fatalf("mailbox not masked: %q", email)
	}
	if body["scope"] != "https://www.googleapis.com/auth/gmail.readonly" {
		t.Fatalf("scope mismatch: %#v", body["scope"])
	}
	if status, body := h.request("GET", "/v1/gmail/status", bob, nil); status != 200 ||
		body["connected"] != false {
		t.Fatalf("owner isolation broken: %d %#v", status, body)
	}
	// A second start without reconnect is a conflict, not a silent second grant.
	if status, body := h.request("POST", "/v1/gmail/connect/start", alice, map[string]any{}); status != 409 {
		t.Fatalf("already connected start = %d %#v", status, body)
	}
	if status, _ := h.request("POST", "/v1/gmail/disconnect", bob, nil); status != 409 {
		t.Fatal("bob must not be able to disconnect alice's mailbox")
	}
	if status, body := h.request("POST", "/v1/gmail/disconnect", alice, nil); status != 200 ||
		body["disconnected"] != true {
		t.Fatalf("disconnect = %d %#v", status, body)
	}
	if h.provider.StopCalls != 1 || h.oauth.Revokes != 1 {
		t.Fatalf("disconnect work missing: stop=%d revoke=%d", h.provider.StopCalls,
			h.oauth.Revokes)
	}
}

func TestGmailPushJWTAndIdempotency(t *testing.T) {
	h := newGmailHarness(t)
	h.register("gmail-push@example.test")
	token, _ := h.login("gmail-push@example.test")
	startResp, startMap := h.request("POST", "/v1/gmail/connect/start", token, map[string]any{})
	if startResp != 200 {
		t.Fatalf("start = %d %#v", startResp, startMap)
	}
	authorization, _ := startMap["authorization_url"].(string)
	parsed, err := url.Parse(authorization)
	if err != nil {
		t.Fatal(err)
	}
	response, _ := h.rawRoundTrip("GET", "/v1/gmail/connect/callback?code=code-good&state="+
		url.QueryEscape(parsed.Query().Get("state")), nil, nil)
	if !strings.Contains(response.Header.Get("Location"), "status=success") {
		t.Fatalf("callback failed: %s", response.Header.Get("Location"))
	}

	if !h.connectionExists(context.Background(), "user@gmail.test") {
		t.Fatal("server-side connection missing")
	}

	good := pushBody(t, "user@gmail.test", "901", "message-1")
	headers := map[string]string{"Authorization": "Bearer push-token",
		"Content-Type": "application/json"}
	if response, raw := h.rawRoundTrip("POST", "/v1/internal/gmail/push", headers, good); response.StatusCode != 204 {
		t.Fatalf("valid push = %d %s", response.StatusCode, raw)
	}
	// Duplicate delivery is acknowledged but stored once.
	if response, _ := h.rawRoundTrip("POST", "/v1/internal/gmail/push", headers, good); response.StatusCode != 204 {
		t.Fatal("duplicate push must be acknowledged")
	}
	var events int
	if err := h.store.DB.QueryRow(`SELECT COUNT(*) FROM gmail_push_events`).Scan(&events); err != nil {
		t.Fatal(err)
	}
	if events != 1 {
		t.Fatalf("push events = %d, want 1", events)
	}
	// Unknown mailbox: acknowledged without an event, because the owner is never guessed.
	unknown := pushBody(t, "someone-else@gmail.test", "902", "message-2")
	if response, _ := h.rawRoundTrip("POST", "/v1/internal/gmail/push", headers, unknown); response.StatusCode != 204 {
		t.Fatal("unknown mailbox push must be acknowledged")
	}
	if err := h.store.DB.QueryRow(`SELECT COUNT(*) FROM gmail_push_events`).Scan(&events); err != nil {
		t.Fatal(err)
	}
	if events != 1 {
		t.Fatalf("unknown mailbox created an event: %d", events)
	}
	// Bad JWT is rejected before any event is written.
	badHeaders := map[string]string{"Authorization": "Bearer wrong-token",
		"Content-Type": "application/json"}
	response, _ = h.rawRoundTrip("POST", "/v1/internal/gmail/push", badHeaders, good)
	if response.StatusCode != 401 {
		t.Fatalf("bad push JWT = %d", response.StatusCode)
	}
	if err := h.store.DB.QueryRow(`SELECT COUNT(*) FROM gmail_push_events`).Scan(&events); err != nil {
		t.Fatal(err)
	}
	if events != 1 {
		t.Fatalf("bad JWT created an event: %d", events)
	}
	// A malformed body from an authenticated publisher is acknowledged and dropped.
	if response, _ := h.rawRoundTrip("POST", "/v1/internal/gmail/push", headers,
		[]byte("not-json")); response.StatusCode != 204 {
		t.Fatal("malformed push body must be acknowledged")
	}
}

func (h *gmailHarness) connectionExists(ctx context.Context, email string) bool {
	h.t.Helper()
	_, err := h.store.GmailConnectionByEmailHash(ctx, h.store.GmailEmailHash(email))
	return err == nil
}

func TestGmailCallbackRedirectSanitizedRoute(t *testing.T) {
	cases := map[string]string{
		"/v1/gmail/connect/start":    "/v1/gmail/connect/start",
		"/v1/gmail/connect/callback": "/v1/gmail/connect/callback",
		"/v1/gmail/status":           "/v1/gmail/status",
		"/v1/gmail/disconnect":       "/v1/gmail/disconnect",
		"/v1/internal/gmail/push":    "/v1/internal/gmail/push",
		"/v1/gmail/connect/other":    "{unknown}",
	}
	for path, want := range cases {
		if got := sanitizedRoute(path); got != want {
			t.Fatalf("sanitizedRoute(%q) = %q, want %q", path, got, want)
		}
	}
}
