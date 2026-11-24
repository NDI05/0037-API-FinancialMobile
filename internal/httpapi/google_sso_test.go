package httpapi

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/pam/recap/backend-go/internal/auth"
	"github.com/pam/recap/backend-go/internal/llm"
	"github.com/pam/recap/backend-go/internal/store"
)

const googleTestClientID = "sso-client.apps.googleusercontent.com"

type googleHarness struct {
	*harness
	key *rsa.PrivateKey
	kid string
}

func newGoogleHarness(t *testing.T) *googleHarness {
	t.Helper()
	h := newHarnessWithConfig(t, &llm.Fake{Scenario: "valid"}, map[string]string{
		"APP_ENV": "development", "GOOGLE_SSO_ENABLED": "true",
		"GOOGLE_SSO_CLIENT_ID": googleTestClientID,
	})
	verifier, key := newTestGoogleVerifier(t, "kid-1")
	h.api.GoogleSSO = verifier
	return &googleHarness{harness: h, key: key, kid: "kid-1"}
}

func newTestGoogleVerifier(t *testing.T, kid string) (*auth.GoogleVerifier, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		public := &key.PublicKey
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
			"kty": "RSA", "alg": "RS256", "use": "sig", "kid": kid,
			"n": base64.RawURLEncoding.EncodeToString(public.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(public.E)).Bytes()),
		}}})
	}))
	t.Cleanup(server.Close)
	return auth.NewGoogleVerifier(googleTestClientID, server.URL, server.Client(), time.Now), key
}

func (h *googleHarness) nonce(t *testing.T) string {
	t.Helper()
	status, body := h.request("GET", "/v1/auth/google/nonce", "", nil)
	if status != 200 {
		t.Fatalf("nonce = %d %#v", status, body)
	}
	if body["nonce"] == "" || body["expiresInSeconds"] != float64(600) {
		t.Fatalf("nonce body = %#v", body)
	}
	if _, err := time.Parse(time.RFC3339, body["expiresAt"].(string)); err != nil {
		t.Fatalf("expiresAt not RFC3339: %v", err)
	}
	return body["nonce"].(string)
}

func (h *googleHarness) tokenFor(t *testing.T, subject, nonce string, mutate func(map[string]any)) string {
	t.Helper()
	now := time.Now().UTC()
	claims := map[string]any{
		"iss": "https://accounts.google.com", "aud": googleTestClientID, "sub": subject,
		"email": subject + "@example.test", "email_verified": true, "nonce": nonce,
		"iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(),
	}
	if mutate != nil {
		mutate(claims)
	}
	header, _ := json.Marshal(map[string]any{"alg": "RS256", "typ": "JWT", "kid": h.kid})
	payload, _ := json.Marshal(claims)
	input := base64.RawURLEncoding.EncodeToString(header) + "." +
		base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(input))
	signature, err := rsa.SignPKCS1v15(rand.Reader, h.key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func (h *googleHarness) googleLogin(t *testing.T, idToken, nonce string) (int, map[string]any) {
	t.Helper()
	return h.request("POST", "/v1/auth/google", "", map[string]any{
		"idToken": idToken, "nonce": nonce,
	})
}

func (h *googleHarness) link(t *testing.T, accessToken, idToken, nonce string) (int, map[string]any) {
	t.Helper()
	return h.request("POST", "/v1/auth/google/link", accessToken, map[string]any{
		"idToken": idToken, "nonce": nonce,
	})
}

func (h *googleHarness) userCount(t *testing.T) int {
	t.Helper()
	var count int
	if err := h.store.DB.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

func TestGoogleSSODisabledAnswers503(t *testing.T) {
	h := newHarness(t)
	status, body := h.request("GET", "/v1/auth/google/nonce", "", nil)
	if status != 503 || body["code"] != "google_sso_disabled" {
		t.Fatalf("disabled nonce = %d %#v", status, body)
	}
	status, body = h.request("POST", "/v1/auth/google", "", map[string]any{
		"idToken": "x", "nonce": "y"})
	if status != 503 || body["code"] != "google_sso_disabled" {
		t.Fatalf("disabled login = %d %#v", status, body)
	}
}

func TestGoogleSSOLoginRejectsBadTokensAndNonces(t *testing.T) {
	h := newGoogleHarness(t)
	h.register("owner@example.test")
	before := h.userCount(t)

	// A valid token for an unlinked identity must not create an account.
	nonce := h.nonce(t)
	if status, body := h.googleLogin(t, h.tokenFor(t, "unlinked-sub", nonce, nil),
		nonce); status != 409 || body["code"] != "google_identity_not_linked" {
		t.Fatalf("unlinked login = %d %#v", status, body)
	}
	if after := h.userCount(t); after != before {
		t.Fatalf("unlinked login created a user: %d -> %d", before, after)
	}

	cases := []struct {
		name   string
		token  func(nonce string) string
		useBad bool
	}{
		{"bad signature", func(nonce string) string {
			return h.tokenFor(t, "sub", nonce, nil) + "x"
		}, false},
		{"wrong issuer", func(nonce string) string {
			return h.tokenFor(t, "sub", nonce, func(claims map[string]any) {
				claims["iss"] = "https://evil.example.test"
			})
		}, false},
		{"wrong audience", func(nonce string) string {
			return h.tokenFor(t, "sub", nonce, func(claims map[string]any) {
				claims["aud"] = "another-client"
			})
		}, false},
		{"expired", func(nonce string) string {
			return h.tokenFor(t, "sub", nonce, func(claims map[string]any) {
				claims["exp"] = time.Now().Add(-time.Minute).Unix()
			})
		}, false},
		{"unknown nonce", func(nonce string) string {
			return h.tokenFor(t, "sub", nonce, nil)
		}, true},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			nonce := h.nonce(t)
			if test.useBad {
				nonce = "not-a-server-nonce"
			}
			status, body := h.googleLogin(t, test.token(nonce), nonce)
			if status != 401 || body["code"] != "google_invalid_token" {
				t.Fatalf("login = %d %#v", status, body)
			}
		})
	}

	// A nonce is single-use even when the first attempt fails: the second request with the same
	// nonce gets 401, never a session.
	nonce = h.nonce(t)
	bad := h.tokenFor(t, "unlinked-sub", nonce, func(claims map[string]any) {
		claims["aud"] = "wrong"
	})
	if status, _ := h.googleLogin(t, bad, nonce); status != 401 {
		t.Fatalf("bad token = %d", status)
	}
	if status, body := h.googleLogin(t, h.tokenFor(t, "unlinked-sub", nonce, nil),
		nonce); status != 401 || body["code"] != "google_invalid_token" {
		t.Fatalf("nonce replay = %d %#v", status, body)
	}
}

func TestGoogleLinkAndLoginFlow(t *testing.T) {
	h := newGoogleHarness(t)
	h.register("alice@example.test")
	access, refresh := h.login("alice@example.test")
	owner := store.OwnerIDForEmail("alice@example.test")

	// /v1/me exposes the additive flag and defaults to false.
	status, me := h.request("GET", "/v1/me", access, nil)
	if status != 200 || me["googleLinked"] != false {
		t.Fatalf("initial me = %d %#v", status, me)
	}

	nonce := h.nonce(t)
	status, body := h.link(t, access, h.tokenFor(t, "google-sub-alice", nonce, nil), nonce)
	if status != 200 || body["linked"] != true || body["googleLinked"] != true {
		t.Fatalf("link = %d %#v", status, body)
	}
	// Idempotent relink of the same identity succeeds with a fresh nonce.
	nonce = h.nonce(t)
	if status, body := h.link(t, access, h.tokenFor(t, "google-sub-alice", nonce, nil), nonce); status != 200 {
		t.Fatalf("idempotent link = %d %#v", status, body)
	}
	if status, me := h.request("GET", "/v1/me", access, nil); status != 200 ||
		me["googleLinked"] != true {
		t.Fatalf("linked me = %d %#v", status, me)
	}

	// SSO login returns the same session shape plus googleLinked and resolves the same owner.
	nonce = h.nonce(t)
	status, session := h.googleLogin(t, h.tokenFor(t, "google-sub-alice", nonce, nil), nonce)
	if status != 200 || session["googleLinked"] != true || session["accessToken"] == nil {
		t.Fatalf("google login = %d %#v", status, session)
	}
	sessionUser, _ := session["user"].(map[string]any)
	if sessionUser["ownerId"] != owner {
		t.Fatalf("google login owner = %#v, want %s", sessionUser["ownerId"], owner)
	}
	status, me = h.request("GET", "/v1/me", session["accessToken"].(string), nil)
	if status != 200 || me["googleLinked"] != true {
		t.Fatalf("sso session me = %d %#v", status, me)
	}
	// Refresh continuity: the SSO-issued refresh token rotates like any other session.
	if status, refreshed := h.request("POST", "/v1/sessions/refresh", "", map[string]any{
		"refreshToken": session["refreshToken"]}); status != 200 || refreshed["accessToken"] == nil {
		t.Fatalf("sso refresh = %d %#v", status, refreshed)
	}
	_ = refresh
}

func TestGoogleLinkConflictDoesNotTouchOtherAccount(t *testing.T) {
	h := newGoogleHarness(t)
	h.register("alice@example.test")
	h.register("bob@example.test")
	aliceAccess, _ := h.login("alice@example.test")
	bobAccess, _ := h.login("bob@example.test")

	nonce := h.nonce(t)
	if status, body := h.link(t, aliceAccess, h.tokenFor(t, "shared-sub", nonce, nil), nonce); status != 200 {
		t.Fatalf("alice link = %d %#v", status, body)
	}
	nonce = h.nonce(t)
	status, body := h.link(t, bobAccess, h.tokenFor(t, "shared-sub", nonce, nil), nonce)
	if status != 409 || body["code"] != "google_identity_conflict" {
		t.Fatalf("bob link conflict = %d %#v", status, body)
	}
	if status, me := h.request("GET", "/v1/me", bobAccess, nil); status != 200 ||
		me["googleLinked"] != false {
		t.Fatalf("bob must stay unlinked: %d %#v", status, me)
	}
	// Alice's identity is unaffected and still logs her in.
	nonce = h.nonce(t)
	if status, session := h.googleLogin(t, h.tokenFor(t, "shared-sub", nonce, nil), nonce); status != 200 {
		t.Fatalf("alice sso login = %d %#v", status, session)
	}
}

func TestGoogleLinkRejectsSecondIdentityAndInactiveAccount(t *testing.T) {
	h := newGoogleHarness(t)
	h.register("alice@example.test")
	access, _ := h.login("alice@example.test")
	nonce := h.nonce(t)
	if status, _ := h.link(t, access, h.tokenFor(t, "first-sub", nonce, nil), nonce); status != 200 {
		t.Fatalf("first link = %d", status)
	}
	nonce = h.nonce(t)
	status, body := h.link(t, access, h.tokenFor(t, "second-sub", nonce, nil), nonce)
	if status != 409 || body["code"] != "google_already_linked" {
		t.Fatalf("second identity link = %d %#v", status, body)
	}

	// An inactive owner cannot link or SSO-login; the check happens before any state change.
	if _, err := h.store.DB.Exec(`UPDATE users SET status = 'SUSPENDED' WHERE owner_id = ?`,
		store.OwnerIDForEmail("alice@example.test")); err != nil {
		t.Fatal(err)
	}
	nonce = h.nonce(t)
	status, body = h.link(t, access, h.tokenFor(t, "third-sub", nonce, nil), nonce)
	if status != 403 || body["code"] != "account_inactive" {
		t.Fatalf("inactive link = %d %#v", status, body)
	}
}

func TestGoogleSSOInactiveOwnerIsForbidden(t *testing.T) {
	h := newGoogleHarness(t)
	h.register("inactive@example.test")
	access, _ := h.login("inactive@example.test")
	nonce := h.nonce(t)
	if status, _ := h.link(t, access, h.tokenFor(t, "inactive-sub", nonce, nil), nonce); status != 200 {
		t.Fatalf("link = %d", status)
	}
	if _, err := h.store.DB.Exec(`UPDATE users SET status = 'SUSPENDED' WHERE owner_id = ?`,
		store.OwnerIDForEmail("inactive@example.test")); err != nil {
		t.Fatal(err)
	}
	nonce = h.nonce(t)
	status, body := h.googleLogin(t, h.tokenFor(t, "inactive-sub", nonce, nil), nonce)
	if status != 403 || body["code"] != "account_inactive" {
		t.Fatalf("inactive google login = %d %#v", status, body)
	}
}

func TestConcurrentGoogleLinkHasExactlyOneWinner(t *testing.T) {
	h := newGoogleHarness(t)
	h.register("one@example.test")
	h.register("two@example.test")
	oneAccess, _ := h.login("one@example.test")
	twoAccess, _ := h.login("two@example.test")

	nonceA, nonceB := h.nonce(t), h.nonce(t)
	tokenA := h.tokenFor(t, "race-sub", nonceA, nil)
	tokenB := h.tokenFor(t, "race-sub", nonceB, nil)
	var wg sync.WaitGroup
	statuses := make([]int, 2)
	bodies := make([]map[string]any, 2)
	for index, request := range []struct {
		access, token, nonce string
	}{{oneAccess, tokenA, nonceA}, {twoAccess, tokenB, nonceB}} {
		wg.Add(1)
		go func(index int, access, token, nonce string) {
			defer wg.Done()
			statuses[index], bodies[index] = h.link(t, access, token, nonce)
		}(index, request.access, request.token, request.nonce)
	}
	wg.Wait()
	wins, conflicts, other := 0, 0, 0
	for index, status := range statuses {
		switch {
		case status == 200:
			wins++
		case status == 409 && bodies[index]["code"] == "google_identity_conflict":
			conflicts++
		default:
			other++
		}
	}
	if wins != 1 || conflicts != 1 || other != 0 {
		t.Fatalf("concurrent link statuses = %v %#v", statuses, bodies)
	}
	// The committed winner is the only owner allowed in through the identity.
	identity, err := h.store.FindGoogleIdentity(context.Background(),
		"https://accounts.google.com", "race-sub")
	if err != nil {
		t.Fatal(err)
	}
	nonce := h.nonce(t)
	status, _ := h.googleLogin(t, h.tokenFor(t, "race-sub", nonce, nil), nonce)
	if status != 200 {
		t.Fatalf("winner sso login = %d", status)
	}
	if identity.OwnerID != store.OwnerIDForEmail("one@example.test") &&
		identity.OwnerID != store.OwnerIDForEmail("two@example.test") {
		t.Fatalf("winner owner = %q", identity.OwnerID)
	}
	if errors.Is(err, store.ErrGoogleIdentityNotLinked) {
		t.Fatal("identity missing after concurrent link")
	}
}

func (h *googleHarness) countRows(t *testing.T, table, ownerID string) int {
	t.Helper()
	var count int
	if err := h.store.DB.QueryRow(`SELECT COUNT(*) FROM `+table+` WHERE owner_id = ?`,
		ownerID).Scan(&count); err != nil {
		t.Fatalf("count %s: %v", table, err)
	}
	return count
}

// TestConcurrentGoogleLinkSameOwnerDifferentSubjectsHTTP is the audit P2-1 regression. Both orders
// must be deterministic: if the requests race, the loser hits UNIQUE(owner_id) and must map to
// 409 google_already_linked; if the server serializes them, the pre-check returns the same code.
// Neither order may produce 500 or a second identity row.
func TestConcurrentGoogleLinkSameOwnerDifferentSubjectsHTTP(t *testing.T) {
	h := newGoogleHarness(t)
	h.register("race-owner@example.test")
	access, _ := h.login("race-owner@example.test")
	owner := store.OwnerIDForEmail("race-owner@example.test")

	// Link must not touch account data: seed one transaction and assert both tables are unchanged.
	food := h.category(access, "food")
	if status, body := h.request("POST", "/v1/transactions", access, map[string]any{
		"direction": "DEBIT", "amountMinor": 17_500_000, "currency": "IDR",
		"eventAt": "2026-11-19T04:10:00Z", "categoryId": food,
	}); status != 201 {
		t.Fatalf("seed transaction = %d %#v", status, body)
	}
	transactionsBefore := h.countRows(t, "transactions", owner)
	gmailBefore := h.countRows(t, "gmail_connections", owner)

	nonceA, nonceB := h.nonce(t), h.nonce(t)
	tokenA := h.tokenFor(t, "owner-race-sub-a", nonceA, nil)
	tokenB := h.tokenFor(t, "owner-race-sub-b", nonceB, nil)
	barrier := make(chan struct{})
	statuses := make([]int, 2)
	bodies := make([]map[string]any, 2)
	var wg sync.WaitGroup
	for index, request := range []struct{ token, nonce string }{
		{tokenA, nonceA}, {tokenB, nonceB},
	} {
		wg.Add(1)
		go func(index int, token, nonce string) {
			defer wg.Done()
			<-barrier
			statuses[index], bodies[index] = h.link(t, access, token, nonce)
		}(index, request.token, request.nonce)
	}
	close(barrier)
	wg.Wait()

	wins, alreadyLinked, other := 0, 0, 0
	for index, status := range statuses {
		switch {
		case status == 200:
			wins++
		case status == 409 && bodies[index]["code"] == "google_already_linked":
			alreadyLinked++
		default:
			other++
			t.Errorf("unexpected status/body: %d %#v", status, bodies[index])
		}
	}
	if wins != 1 || alreadyLinked != 1 || other != 0 {
		t.Fatalf("statuses=%v bodies=%#v, want exactly one 200 and one 409 already_linked",
			statuses, bodies)
	}
	if rows := h.countRows(t, "google_identities", owner); rows != 1 {
		t.Fatalf("identity rows = %d, want 1", rows)
	}
	if after := h.countRows(t, "transactions", owner); after != transactionsBefore {
		t.Fatalf("transactions changed by link: %d -> %d", transactionsBefore, after)
	}
	if after := h.countRows(t, "gmail_connections", owner); after != gmailBefore {
		t.Fatalf("gmail connections changed by link: %d -> %d", gmailBefore, after)
	}
	// Sequential retry with a third identity is already_linked too, never a 500.
	nonce := h.nonce(t)
	status, body := h.link(t, access, h.tokenFor(t, "owner-race-sub-c", nonce, nil), nonce)
	if status != 409 || body["code"] != "google_already_linked" {
		t.Fatalf("sequential third link = %d %#v", status, body)
	}
}

// TestGoogleSSOSameEmailDifferentSubjectsDoNotMerge proves the email claim is informational only:
// two owners may have Google identities with the same verified email but different subjects, and
// each subject keeps logging into its own PAM account.
func TestGoogleSSOSameEmailDifferentSubjectsDoNotMerge(t *testing.T) {
	h := newGoogleHarness(t)
	h.register("first@example.test")
	h.register("second@example.test")
	firstAccess, _ := h.login("first@example.test")
	secondAccess, _ := h.login("second@example.test")
	firstOwner := store.OwnerIDForEmail("first@example.test")
	secondOwner := store.OwnerIDForEmail("second@example.test")

	sameEmail := "shared-claim@example.test"
	nonce := h.nonce(t)
	if status, body := h.link(t, firstAccess, h.tokenFor(t, "email-sub-first", nonce,
		func(claims map[string]any) { claims["email"] = sameEmail }), nonce); status != 200 {
		t.Fatalf("first link = %d %#v", status, body)
	}
	nonce = h.nonce(t)
	if status, body := h.link(t, secondAccess, h.tokenFor(t, "email-sub-second", nonce,
		func(claims map[string]any) { claims["email"] = sameEmail }), nonce); status != 200 {
		t.Fatalf("second link = %d %#v", status, body)
	}
	if rows := h.countRows(t, "google_identities", firstOwner); rows != 1 {
		t.Fatalf("first owner rows = %d", rows)
	}
	if rows := h.countRows(t, "google_identities", secondOwner); rows != 1 {
		t.Fatalf("second owner rows = %d", rows)
	}
	for subject, wantOwner := range map[string]string{
		"email-sub-first": firstOwner, "email-sub-second": secondOwner,
	} {
		nonce = h.nonce(t)
		status, session := h.googleLogin(t, h.tokenFor(t, subject, nonce, nil), nonce)
		if status != 200 {
			t.Fatalf("%s login = %d %#v", subject, status, session)
		}
		user := session["user"].(map[string]any)
		if user["ownerId"] != wantOwner {
			t.Fatalf("%s owner = %v, want %s", subject, user["ownerId"], wantOwner)
		}
	}
}
