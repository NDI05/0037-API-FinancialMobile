package auth

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
	"sync/atomic"
	"testing"
	"time"
)

const googleTestClientID = "test-client.apps.googleusercontent.com"

func newGoogleTestKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func signGoogleToken(t *testing.T, key *rsa.PrivateKey, kid, algorithm string,
	claims map[string]any) string {
	t.Helper()
	header, _ := json.Marshal(map[string]any{"alg": algorithm, "typ": "JWT", "kid": kid})
	payload, _ := json.Marshal(claims)
	signingInput := base64.RawURLEncoding.EncodeToString(header) + "." +
		base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func googleJWKSHandler(keys map[string]*rsa.PublicKey) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		entries := make([]map[string]string, 0, len(keys))
		for kid, key := range keys {
			entries = append(entries, map[string]string{
				"kty": "RSA", "alg": "RS256", "use": "sig", "kid": kid,
				"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
				"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
			})
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": entries})
	}
}

type googleTestClock struct{ at time.Time }

func (c *googleTestClock) now() time.Time { return c.at }

func newGoogleTestVerifier(t *testing.T, kid string, publicKey *rsa.PublicKey) (*GoogleVerifier,
	*googleTestClock) {
	t.Helper()
	server := httptest.NewServer(googleJWKSHandler(map[string]*rsa.PublicKey{kid: publicKey}))
	t.Cleanup(server.Close)
	clock := &googleTestClock{at: time.Date(2026, 11, 24, 10, 0, 0, 0, time.UTC)}
	verifier := NewGoogleVerifier(googleTestClientID, server.URL, server.Client(), clock.now)
	return verifier, clock
}

func googleClaims(now time.Time) map[string]any {
	return map[string]any{
		"iss": "https://accounts.google.com", "aud": googleTestClientID,
		"sub": "google-sub-1", "email": "User@Example.test", "email_verified": true,
		"nonce": "nonce-1", "iat": now.Unix(), "exp": now.Add(10 * time.Minute).Unix(),
	}
}

func TestGoogleVerifierAcceptsValidTokenAndDropsUnverifiedEmail(t *testing.T) {
	key := newGoogleTestKey(t)
	verifier, clock := newGoogleTestVerifier(t, "kid-1", &key.PublicKey)
	token := signGoogleToken(t, key, "kid-1", "RS256", googleClaims(clock.at))
	claims, err := verifier.Verify(context.Background(), token, "nonce-1")
	if err != nil {
		t.Fatal(err)
	}
	if claims.Subject != "google-sub-1" || claims.Issuer != "https://accounts.google.com" ||
		claims.Email != "user@example.test" || !claims.EmailVerified {
		t.Fatalf("claims = %#v", claims)
	}
	// The short issuer form is valid too.
	short := googleClaims(clock.at)
	short["iss"] = "accounts.google.com"
	if _, err := verifier.Verify(context.Background(),
		signGoogleToken(t, key, "kid-1", "RS256", short), "nonce-1"); err != nil {
		t.Fatalf("short issuer rejected: %v", err)
	}
	// audience may be an array.
	array := googleClaims(clock.at)
	array["aud"] = []string{"other", googleTestClientID}
	if _, err := verifier.Verify(context.Background(),
		signGoogleToken(t, key, "kid-1", "RS256", array), "nonce-1"); err != nil {
		t.Fatalf("array audience rejected: %v", err)
	}
	unverified := googleClaims(clock.at)
	unverified["email_verified"] = false
	claims, err = verifier.Verify(context.Background(),
		signGoogleToken(t, key, "kid-1", "RS256", unverified), "nonce-1")
	if err != nil {
		t.Fatal(err)
	}
	if claims.Email != "" || claims.EmailVerified {
		t.Fatalf("unverified email retained: %#v", claims)
	}
}

func TestGoogleVerifierRejectsEveryInvalidToken(t *testing.T) {
	key := newGoogleTestKey(t)
	other := newGoogleTestKey(t)
	verifier, clock := newGoogleTestVerifier(t, "kid-1", &key.PublicKey)
	valid := func() map[string]any { return googleClaims(clock.at) }

	cases := []struct {
		name  string
		token func() string
		nonce string
	}{
		{"bad signature", func() string {
			return signGoogleToken(t, other, "kid-1", "RS256", valid())
		}, "nonce-1"},
		{"algorithm none", func() string {
			return signGoogleToken(t, key, "kid-1", "none", valid())
		}, "nonce-1"},
		{"algorithm HS256", func() string {
			return signGoogleToken(t, key, "kid-1", "HS256", valid())
		}, "nonce-1"},
		{"wrong issuer", func() string {
			claims := valid()
			claims["iss"] = "https://evil.example.test"
			return signGoogleToken(t, key, "kid-1", "RS256", claims)
		}, "nonce-1"},
		{"wrong audience", func() string {
			claims := valid()
			claims["aud"] = "another-client"
			return signGoogleToken(t, key, "kid-1", "RS256", claims)
		}, "nonce-1"},
		{"expired", func() string {
			claims := valid()
			claims["exp"] = clock.at.Add(-time.Minute).Unix()
			return signGoogleToken(t, key, "kid-1", "RS256", claims)
		}, "nonce-1"},
		{"not yet valid", func() string {
			claims := valid()
			claims["nbf"] = clock.at.Add(time.Hour).Unix()
			return signGoogleToken(t, key, "kid-1", "RS256", claims)
		}, "nonce-1"},
		{"nonce mismatch", func() string {
			return signGoogleToken(t, key, "kid-1", "RS256", valid())
		}, "different-nonce"},
		{"missing nonce claim", func() string {
			claims := valid()
			delete(claims, "nonce")
			return signGoogleToken(t, key, "kid-1", "RS256", claims)
		}, "nonce-1"},
		{"unknown kid", func() string {
			return signGoogleToken(t, key, "kid-unseen", "RS256", valid())
		}, "nonce-1"},
		{"malformed", func() string { return "not-a-jwt" }, "nonce-1"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			if _, err := verifier.Verify(context.Background(), test.token(), test.nonce); !errors.Is(
				err, ErrGoogleInvalidToken) {
				t.Fatalf("error = %v, want ErrGoogleInvalidToken", err)
			}
		})
	}
	if _, err := verifier.Verify(context.Background(),
		signGoogleToken(t, key, "kid-1", "RS256", valid()), ""); !errors.Is(err,
		ErrGoogleInvalidToken) {
		t.Fatalf("empty expected nonce accepted: %v", err)
	}
}

func TestGoogleVerifierHandlesJWKSFailureAndRotation(t *testing.T) {
	keyA := newGoogleTestKey(t)
	keyB := newGoogleTestKey(t)
	var current atomic.Value
	current.Store(googleJWKSHandler(map[string]*rsa.PublicKey{"kid-a": &keyA.PublicKey}))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		current.Load().(http.HandlerFunc)(w, r)
	}))
	t.Cleanup(server.Close)
	clock := &googleTestClock{at: time.Date(2026, 11, 24, 10, 0, 0, 0, time.UTC)}
	verifier := NewGoogleVerifier(googleTestClientID, server.URL, server.Client(), clock.now)

	tokenA := signGoogleToken(t, keyA, "kid-a", "RS256", googleClaims(clock.at))
	if _, err := verifier.Verify(context.Background(), tokenA, "nonce-1"); err != nil {
		t.Fatalf("initial verify: %v", err)
	}
	// Simulate Google rotating its signing key: the cache must be refreshed after its TTL.
	current.Store(googleJWKSHandler(map[string]*rsa.PublicKey{"kid-b": &keyB.PublicKey}))
	clock.at = clock.at.Add(6 * time.Minute)
	tokenB := signGoogleToken(t, keyB, "kid-b", "RS256", googleClaims(clock.at))
	if _, err := verifier.Verify(context.Background(), tokenB, "nonce-1"); err != nil {
		t.Fatalf("rotation verify: %v", err)
	}
	// A JWKS endpoint that is down must not panic; a token from an empty cache fails closed.
	broken := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "down", http.StatusInternalServerError)
	}))
	t.Cleanup(broken.Close)
	offline := NewGoogleVerifier(googleTestClientID, broken.URL, broken.Client(), clock.now)
	if _, err := offline.Verify(context.Background(), tokenA, "nonce-1"); !errors.Is(err,
		ErrGoogleInvalidToken) {
		t.Fatalf("jwks outage error = %v", err)
	}
}
