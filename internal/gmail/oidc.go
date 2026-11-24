package gmail

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// ErrPushUnauthorized is the only failure a Pub/Sub caller sees; it never explains which check
// failed.
var ErrPushUnauthorized = errors.New("push token is not authorized")

// OIDCConfig is the Pub/Sub push verification policy. Google signs push requests with the
// service account that owns the subscription; both the audience and the account are pinned.
type OIDCConfig struct {
	Audience       string
	ServiceAccount string
	Issuer         string
	JWKSURL        string
	HTTPClient     *http.Client
	CacheTTL       time.Duration
	Now            func() time.Time
}

// OIDCVerifier verifies Google-signed Pub/Sub push JWTs against the public JWKS.
type OIDCVerifier struct {
	cfg OIDCConfig

	mu        sync.Mutex
	keys      map[string]*rsa.PublicKey
	fetchedAt time.Time
}

func NewOIDCVerifier(cfg OIDCConfig) *OIDCVerifier {
	if cfg.Issuer == "" {
		cfg.Issuer = "https://accounts.google.com"
	}
	if cfg.JWKSURL == "" {
		cfg.JWKSURL = "https://www.googleapis.com/oauth2/v3/certs"
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 10 * time.Second}
	}
	if cfg.CacheTTL <= 0 {
		cfg.CacheTTL = time.Hour
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &OIDCVerifier{cfg: cfg}
}

// Verify validates the Authorization header and returns the pinned claims.
func (v *OIDCVerifier) Verify(ctx context.Context, authorization string) (PushClaims, error) {
	raw := bearerRaw(authorization)
	if raw == "" || v.cfg.Audience == "" || v.cfg.ServiceAccount == "" {
		return PushClaims{}, ErrPushUnauthorized
	}
	claims := jwt.MapClaims{}
	parser := jwt.NewParser(
		jwt.WithAudience(v.cfg.Audience),
		jwt.WithExpirationRequired(),
		jwt.WithIssuer(v.cfg.Issuer),
		jwt.WithValidMethods([]string{"RS256"}),
		jwt.WithTimeFunc(v.cfg.Now),
	)
	token, err := parser.ParseWithClaims(raw, claims, func(token *jwt.Token) (any, error) {
		kid, _ := token.Header["kid"].(string)
		key, err := v.key(ctx, kid)
		if err != nil {
			return nil, err
		}
		return key, nil
	})
	if err != nil || !token.Valid {
		return PushClaims{}, ErrPushUnauthorized
	}
	email, _ := claims["email"].(string)
	verified, _ := claims["email_verified"].(bool)
	if !strings.EqualFold(email, v.cfg.ServiceAccount) || !verified {
		return PushClaims{}, ErrPushUnauthorized
	}
	issuer, _ := claims["iss"].(string)
	audience, _ := claims["aud"].(string)
	return PushClaims{Email: email, Audience: audience, Issuer: issuer}, nil
}

func bearerRaw(header string) string {
	parts := strings.Fields(header)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return ""
	}
	return parts[1]
}

// key returns a JWKS key, refreshing the cache when the kid is unknown or the cache is stale.
func (v *OIDCVerifier) key(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	stale := v.cfg.Now().Sub(v.fetchedAt) > v.cfg.CacheTTL
	if key, ok := v.keys[kid]; ok && !stale {
		return key, nil
	}
	if err := v.refreshLocked(ctx); err != nil {
		// A stale cache is still better than no verification path; only fail closed when a key
		// for this kid is genuinely absent.
		if key, ok := v.keys[kid]; ok {
			return key, nil
		}
		return nil, err
	}
	key, ok := v.keys[kid]
	if !ok {
		return nil, fmt.Errorf("push token key is unknown")
	}
	return key, nil
}

func (v *OIDCVerifier) refreshLocked(ctx context.Context) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, v.cfg.JWKSURL, nil)
	if err != nil {
		return err
	}
	response, err := v.cfg.HTTPClient.Do(request)
	if err != nil {
		return err
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("jwks fetch rejected")
	}
	var document struct {
		Keys []struct {
			KID string `json:"kid"`
			KTY string `json:"kty"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if err := json.NewDecoder(response.Body).Decode(&document); err != nil {
		return fmt.Errorf("jwks document is not JSON")
	}
	keys := make(map[string]*rsa.PublicKey, len(document.Keys))
	for _, entry := range document.Keys {
		if entry.KID == "" || entry.KTY != "RSA" {
			continue
		}
		modulus, err := base64.RawURLEncoding.DecodeString(entry.N)
		if err != nil {
			continue
		}
		exponentBytes, err := base64.RawURLEncoding.DecodeString(entry.E)
		if err != nil {
			continue
		}
		exponent := 0
		for _, raw := range exponentBytes {
			exponent = exponent<<8 | int(raw)
		}
		if exponent == 0 {
			continue
		}
		keys[entry.KID] = &rsa.PublicKey{N: new(big.Int).SetBytes(modulus), E: exponent}
	}
	if len(keys) == 0 {
		return fmt.Errorf("jwks document has no usable keys")
	}
	v.keys = keys
	v.fetchedAt = v.cfg.Now()
	return nil
}
