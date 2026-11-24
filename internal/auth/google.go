package auth

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"
)

// ErrGoogleInvalidToken is the single error class for every ID-token failure: malformed JWT, bad
// signature/alg, wrong issuer/audience, expired token, nonce mismatch and unknown key. Callers map
// it to 401 google_invalid_token without learning which checks passed, so the response cannot be
// used as an oracle.
var ErrGoogleInvalidToken = errors.New("google id token is invalid")

const (
	googleDefaultJWKSURL = "https://www.googleapis.com/oauth2/v3/certs"
	googleJWKSCacheTTL   = 5 * time.Minute
	googleClockSkew      = 2 * time.Minute
	// googleJWKSMinRefetch throttles unknown-kid refetches. Google rotates keys rarely, and without
	// this bound a stream of random kid values would turn every request into a Google fetch.
	googleJWKSMinRefetch = 15 * time.Second
	googleMaxTokenLength = 16 << 10
)

// GoogleClaims are the subset of an ID token the backend consumes. Email is only filled when
// email_verified=true; it is never used to find an owner (the link table is).
type GoogleClaims struct {
	Issuer        string
	Subject       string
	Email         string
	EmailVerified bool
	Nonce         string
	ExpiresAt     time.Time
	IssuedAt      time.Time
}

// GoogleVerifier validates Google ID tokens against a cached JWKS. It has no network dependency
// at construction: the first Verify fetches the keys, and every dependency (HTTP client, clock,
// JWKS URL) is injectable so tests never call Google.
type GoogleVerifier struct {
	clientID string
	jwksURL  string
	client   *http.Client
	now      func() time.Time
	cacheTTL time.Duration

	mu          sync.Mutex
	keys        map[string]*rsa.PublicKey
	fetchedAt   time.Time
	lastAttempt time.Time
}

// NewGoogleVerifier builds a verifier. A nil client uses a bounded default client; a nil clock
// uses time.Now; an empty jwksURL uses Google's production endpoint.
func NewGoogleVerifier(clientID, jwksURL string, client *http.Client, now func() time.Time) *GoogleVerifier {
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	if now == nil {
		now = time.Now
	}
	if jwksURL == "" {
		jwksURL = googleDefaultJWKSURL
	}
	return &GoogleVerifier{clientID: clientID, jwksURL: jwksURL, client: client, now: now,
		cacheTTL: googleJWKSCacheTTL}
}

// Verify parses and validates an ID token. expectedNonce must be the nonce already consumed by the
// caller; the token must echo exactly that value.
func (v *GoogleVerifier) Verify(ctx context.Context, idToken, expectedNonce string) (GoogleClaims, error) {
	if v.clientID == "" || expectedNonce == "" || len(idToken) == 0 ||
		len(idToken) > googleMaxTokenLength {
		return GoogleClaims{}, invalid("missing required verification input")
	}
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return GoogleClaims{}, invalid("malformed token")
	}
	headerRaw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return GoogleClaims{}, invalid("malformed header")
	}
	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(headerRaw, &header); err != nil {
		return GoogleClaims{}, invalid("malformed header")
	}
	// Only RS256 is accepted. Rejecting everything else up front also refuses "none" and HMAC
	// tokens before any signature comparison.
	if header.Alg != "RS256" || header.Kid == "" {
		return GoogleClaims{}, invalid("unsupported algorithm")
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return GoogleClaims{}, invalid("malformed signature")
	}
	key, err := v.key(ctx, header.Kid)
	if err != nil {
		return GoogleClaims{}, err
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], signature); err != nil {
		return GoogleClaims{}, invalid("bad signature")
	}
	payloadRaw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return GoogleClaims{}, invalid("malformed payload")
	}
	var payload struct {
		Iss           string          `json:"iss"`
		Aud           json.RawMessage `json:"aud"`
		Sub           string          `json:"sub"`
		Email         string          `json:"email"`
		EmailVerified bool            `json:"email_verified"`
		Nonce         string          `json:"nonce"`
		Exp           int64           `json:"exp"`
		Iat           int64           `json:"iat"`
		Nbf           int64           `json:"nbf"`
	}
	if err := json.Unmarshal(payloadRaw, &payload); err != nil {
		return GoogleClaims{}, invalid("malformed payload")
	}
	now := v.now()
	if !validGoogleIssuer(payload.Iss) {
		return GoogleClaims{}, invalid("wrong issuer")
	}
	if !v.validAudience(payload.Aud) {
		return GoogleClaims{}, invalid("wrong audience")
	}
	if payload.Sub == "" || payload.Nonce == "" || payload.Nonce != expectedNonce {
		return GoogleClaims{}, invalid("nonce or subject mismatch")
	}
	if payload.Exp == 0 || !now.Before(time.Unix(payload.Exp, 0)) {
		return GoogleClaims{}, invalid("expired token")
	}
	// A small skew accepts clock drift on iat/nbf without letting a far-future token through.
	if payload.Nbf != 0 && time.Unix(payload.Nbf, 0).After(now.Add(googleClockSkew)) {
		return GoogleClaims{}, invalid("token not valid yet")
	}
	if payload.Iat != 0 && time.Unix(payload.Iat, 0).After(now.Add(googleClockSkew)) {
		return GoogleClaims{}, invalid("issued in the future")
	}
	claims := GoogleClaims{Issuer: payload.Iss, Subject: payload.Sub, Nonce: payload.Nonce,
		EmailVerified: payload.EmailVerified,
		ExpiresAt:     time.Unix(payload.Exp, 0).UTC()}
	if payload.Iat != 0 {
		claims.IssuedAt = time.Unix(payload.Iat, 0).UTC()
	}
	// An unverified email is not an identity signal, so it is dropped instead of stored.
	if payload.EmailVerified {
		claims.Email = strings.ToLower(strings.TrimSpace(payload.Email))
	}
	return claims, nil
}

func validGoogleIssuer(issuer string) bool {
	return issuer == "accounts.google.com" || issuer == "https://accounts.google.com"
}

func (v *GoogleVerifier) validAudience(raw json.RawMessage) bool {
	if len(raw) == 0 {
		return false
	}
	var single string
	if err := json.Unmarshal(raw, &single); err == nil {
		return single == v.clientID
	}
	var many []string
	if err := json.Unmarshal(raw, &many); err != nil {
		return false
	}
	for _, audience := range many {
		if audience == v.clientID {
			return true
		}
	}
	return false
}

// key returns the RSA key for kid, refreshing the cache on expiry or an unknown kid.
func (v *GoogleVerifier) key(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	now := v.now()
	needsRefresh := len(v.keys) == 0 || now.Sub(v.fetchedAt) >= v.cacheTTL
	if !needsRefresh {
		if key, ok := v.keys[kid]; ok {
			return key, nil
		}
		// Unknown kid: likely a Google key rotation, so refetch once, but never on every request.
		needsRefresh = now.Sub(v.lastAttempt) >= googleJWKSMinRefetch
	}
	if needsRefresh {
		v.lastAttempt = now
		keys, err := v.fetch(ctx)
		if err != nil {
			// A stale but still-cached key is better than locking every login out during a brief
			// JWKS outage; only fail when no key was ever loaded.
			if len(v.keys) == 0 {
				return nil, invalid("jwks unavailable")
			}
		} else {
			v.keys = keys
			v.fetchedAt = now
		}
	}
	if key, ok := v.keys[kid]; ok {
		return key, nil
	}
	return nil, invalid("unknown signing key")
}

func (v *GoogleVerifier) fetch(ctx context.Context) (map[string]*rsa.PublicKey, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, v.jwksURL, nil)
	if err != nil {
		return nil, err
	}
	response, err := v.client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("jwks status %d", response.StatusCode)
	}
	var set struct {
		Keys []struct {
			Kty string `json:"kty"`
			Kid string `json:"kid"`
			Alg string `json:"alg"`
			Use string `json:"use"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if err := json.NewDecoder(response.Body).Decode(&set); err != nil {
		return nil, err
	}
	keys := make(map[string]*rsa.PublicKey, len(set.Keys))
	for _, jwk := range set.Keys {
		if jwk.Kty != "RSA" || jwk.Kid == "" || (jwk.Alg != "" && jwk.Alg != "RS256") ||
			(jwk.Use != "" && jwk.Use != "sig") {
			continue
		}
		key, err := rsaKeyFromJWK(jwk.N, jwk.E)
		if err != nil {
			return nil, err
		}
		keys[jwk.Kid] = key
	}
	if len(keys) == 0 {
		return nil, errors.New("jwks has no usable RSA keys")
	}
	return keys, nil
}

func rsaKeyFromJWK(encodedModulus, encodedExponent string) (*rsa.PublicKey, error) {
	modulus, err := base64.RawURLEncoding.DecodeString(encodedModulus)
	if err != nil || len(modulus) == 0 {
		return nil, errors.New("jwks modulus is invalid")
	}
	exponentBytes, err := base64.RawURLEncoding.DecodeString(encodedExponent)
	if err != nil || len(exponentBytes) == 0 || len(exponentBytes) > 4 {
		return nil, errors.New("jwks exponent is invalid")
	}
	exponent := 0
	for _, value := range exponentBytes {
		exponent = exponent<<8 | int(value)
	}
	if exponent < 3 {
		return nil, errors.New("jwks exponent is too small")
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(modulus), E: exponent}, nil
}

func invalid(reason string) error {
	return fmt.Errorf("%w: %s", ErrGoogleInvalidToken, reason)
}
