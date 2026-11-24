package gmail

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func rsaJWKS(t *testing.T, key *rsa.PrivateKey, kid string) []byte {
	t.Helper()
	payload := map[string]any{
		"keys": []map[string]any{{
			"kty": "RSA", "alg": "RS256", "use": "sig", "kid": kid,
			"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
		}},
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func signOIDC(t *testing.T, key *rsa.PrivateKey, kid string, claims jwt.MapClaims) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = kid
	signed, err := token.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func TestOIDCVerifierAcceptsOnlyGoogleServiceAccountPush(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	const kid = "test-key-1"
	const audience = "https://api.example.test/v1/internal/gmail/push"
	const serviceAccount = "pubsub-push@project.iam.gserviceaccount.com"
	jwks := rsaJWKS(t, key, kid)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(jwks)
	}))
	defer server.Close()

	now := time.Date(2026, 11, 24, 6, 0, 0, 0, time.UTC)
	verifier := NewOIDCVerifier(OIDCConfig{
		Audience: audience, ServiceAccount: serviceAccount, JWKSURL: server.URL,
		Now: func() time.Time { return now },
	})
	good := signOIDC(t, key, kid, jwt.MapClaims{
		"iss": "https://accounts.google.com", "aud": audience,
		"exp": now.Add(5 * time.Minute).Unix(), "iat": now.Unix(),
		"email": serviceAccount, "email_verified": true,
	})
	claims, err := verifier.Verify(context.Background(), "Bearer "+good)
	if err != nil {
		t.Fatalf("valid push token rejected: %v", err)
	}
	if claims.Email != serviceAccount || claims.Audience != audience {
		t.Fatalf("verified claims mismatch: %+v", claims)
	}

	badCases := map[string]string{
		"wrong audience": signOIDC(t, key, kid, jwt.MapClaims{
			"iss": "https://accounts.google.com", "aud": "someone-else",
			"exp": now.Add(5 * time.Minute).Unix(), "email": serviceAccount, "email_verified": true,
		}),
		"wrong service account": signOIDC(t, key, kid, jwt.MapClaims{
			"iss": "https://accounts.google.com", "aud": audience,
			"exp": now.Add(5 * time.Minute).Unix(), "email": "attacker@example.test", "email_verified": true,
		}),
		"expired": signOIDC(t, key, kid, jwt.MapClaims{
			"iss": "https://accounts.google.com", "aud": audience,
			"exp": now.Add(-time.Minute).Unix(), "email": serviceAccount, "email_verified": true,
		}),
		"wrong issuer": signOIDC(t, key, kid, jwt.MapClaims{
			"iss": "https://evil.example.test", "aud": audience,
			"exp": now.Add(5 * time.Minute).Unix(), "email": serviceAccount, "email_verified": true,
		}),
		"garbage": "not-a-jwt",
	}
	for name, token := range badCases {
		if _, err := verifier.Verify(context.Background(), "Bearer "+token); !errors.Is(err, ErrPushUnauthorized) {
			t.Fatalf("%s must be rejected, got %v", name, err)
		}
	}
	if _, err := verifier.Verify(context.Background(), ""); !errors.Is(err, ErrPushUnauthorized) {
		t.Fatalf("missing bearer must be rejected: %v", err)
	}
	if _, err := verifier.Verify(context.Background(), "Basic abc"); !errors.Is(err, ErrPushUnauthorized) {
		t.Fatalf("non-bearer scheme must be rejected: %v", err)
	}
}

func TestOIDCVerifierRequiresConfiguredJWKS(t *testing.T) {
	verifier := NewOIDCVerifier(OIDCConfig{Audience: "aud", ServiceAccount: "sa@example.test"})
	if _, err := verifier.Verify(context.Background(), "Bearer abc"); !errors.Is(err, ErrPushUnauthorized) {
		t.Fatalf("unconfigured verifier must fail closed: %v", err)
	}
}

func TestPKCEPairAndAuthorizationURL(t *testing.T) {
	pair, err := NewPKCEPair()
	if err != nil {
		t.Fatal(err)
	}
	if len(pair.Verifier) < 43 || len(pair.Verifier) > 128 || pair.Challenge == "" {
		t.Fatalf("pkce pair out of range: %+v", pair)
	}
	state, err := NewState()
	if err != nil || len(state) < 32 {
		t.Fatalf("state too short: %q %v", state, err)
	}
	oauth := NewOAuth(OAuthConfig{
		ClientID: "client-id", ClientSecret: "secret",
		RedirectURI: "https://api.example.test/v1/gmail/connect/callback",
		AuthURL:     "https://accounts.example.test/auth",
		Scopes:      []string{"https://www.googleapis.com/auth/gmail.readonly"},
	})
	target := oauth.AuthorizationURL(state, pair.Challenge)
	if target == "" {
		t.Fatal("missing authorization url")
	}
	for _, needle := range []string{"code_challenge=", "code_challenge_method=S256", "state=" + state,
		"access_type=offline", "response_type=code"} {
		if !strings.Contains(target, needle) {
			t.Fatalf("authorization url missing %s: %s", needle, target)
		}
	}
}
