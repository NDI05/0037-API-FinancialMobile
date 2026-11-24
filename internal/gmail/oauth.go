package gmail

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// OAuthConfig carries the public client settings. Secrets never live in this struct: the client
// secret is used server-side only and never serialized into a response.
type OAuthConfig struct {
	ClientID     string
	ClientSecret string
	RedirectURI  string
	AuthURL      string
	TokenURL     string
	RevokeURL    string
	Scopes       []string
	HTTPClient   *http.Client
}

// OAuth implements TokenExchanger against Google's token endpoints.
type OAuth struct {
	cfg OAuthConfig
}

func NewOAuth(cfg OAuthConfig) *OAuth {
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 20 * time.Second}
	}
	return &OAuth{cfg: cfg}
}

// PKCEPair is one single-use verifier/challenge pair (S256).
type PKCEPair struct {
	Verifier  string
	Challenge string
}

func NewPKCEPair() (PKCEPair, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return PKCEPair{}, err
	}
	verifier := base64.RawURLEncoding.EncodeToString(raw)
	sum := sha256.Sum256([]byte(verifier))
	return PKCEPair{Verifier: verifier, Challenge: base64.RawURLEncoding.EncodeToString(sum[:])}, nil
}

// NewState returns an unguessable single-use OAuth state value.
func NewState() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// AuthorizationURL builds the consent URL for one state/challenge pair.
func (o *OAuth) AuthorizationURL(state, challenge string) string {
	values := url.Values{}
	values.Set("client_id", o.cfg.ClientID)
	values.Set("redirect_uri", o.cfg.RedirectURI)
	values.Set("response_type", "code")
	values.Set("scope", strings.Join(o.cfg.Scopes, " "))
	values.Set("state", state)
	values.Set("code_challenge", challenge)
	values.Set("code_challenge_method", "S256")
	values.Set("access_type", "offline")
	// force consent so a reconnect always yields a refresh token.
	values.Set("prompt", "consent")
	values.Set("include_granted_scopes", "true")
	authURL := o.cfg.AuthURL
	if authURL == "" {
		authURL = "https://accounts.google.com/o/oauth2/v2/auth"
	}
	return authURL + "?" + values.Encode()
}

func (o *OAuth) Exchange(ctx context.Context, code, verifier, redirectURI string) (TokenSet, error) {
	form := url.Values{}
	form.Set("code", code)
	form.Set("client_id", o.cfg.ClientID)
	form.Set("client_secret", o.cfg.ClientSecret)
	form.Set("redirect_uri", redirectURI)
	form.Set("grant_type", "authorization_code")
	form.Set("code_verifier", verifier)
	return o.tokenRequest(ctx, form)
}

func (o *OAuth) Refresh(ctx context.Context, refreshToken string) (TokenSet, error) {
	form := url.Values{}
	form.Set("client_id", o.cfg.ClientID)
	form.Set("client_secret", o.cfg.ClientSecret)
	form.Set("refresh_token", refreshToken)
	form.Set("grant_type", "refresh_token")
	return o.tokenRequest(ctx, form)
}

// Revoke best-effort revokes a token. A revocation failure never blocks a disconnect.
func (o *OAuth) Revoke(ctx context.Context, token string) error {
	revokeURL := o.cfg.RevokeURL
	if revokeURL == "" {
		revokeURL = "https://oauth2.googleapis.com/revoke"
	}
	form := url.Values{"token": {token}}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, revokeURL,
		strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := o.cfg.HTTPClient.Do(request)
	if err != nil {
		return err
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode >= 300 {
		return fmt.Errorf("revoke rejected with status %d", response.StatusCode)
	}
	return nil
}

func (o *OAuth) tokenRequest(ctx context.Context, form url.Values) (TokenSet, error) {
	tokenURL := o.cfg.TokenURL
	if tokenURL == "" {
		tokenURL = "https://oauth2.googleapis.com/token"
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL,
		strings.NewReader(form.Encode()))
	if err != nil {
		return TokenSet{}, err
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := o.cfg.HTTPClient.Do(request)
	if err != nil {
		return TokenSet{}, err
	}
	defer func() { _ = response.Body.Close() }()
	var payload struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int64  `json:"expires_in"`
		Scope        string `json:"scope"`
		Error        string `json:"error"`
	}
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		return TokenSet{}, fmt.Errorf("token response is not JSON")
	}
	if response.StatusCode >= 300 || payload.Error != "" {
		if payload.Error == "invalid_grant" {
			return TokenSet{}, ErrUnauthorized
		}
		return TokenSet{}, errors.New("token exchange rejected")
	}
	if payload.AccessToken == "" {
		return TokenSet{}, errors.New("token exchange returned no access token")
	}
	return TokenSet{
		AccessToken:  payload.AccessToken,
		RefreshToken: payload.RefreshToken,
		Expiry:       time.Now().Add(time.Duration(payload.ExpiresIn) * time.Second),
		Scope:        payload.Scope,
	}, nil
}
