package httpapi

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/pam/recap/backend-go/internal/auth"
	"github.com/pam/recap/backend-go/internal/store"
)

const (
	googleNonceBytes = 32
	googleNonceMax   = 128
	googleTokenMax   = 16 << 10
)

type googleTokenRequest struct {
	IDToken string `json:"idToken"`
	Nonce   string `json:"nonce"`
}

// googleSSODisabled is the single gate for every Google SSO route: feature off (or no verifier
// configured) answers 503 without changing the route table.
func (s *Server) googleSSODisabled(w http.ResponseWriter, r *http.Request) bool {
	if !s.Config.GoogleSSO.Enabled || s.GoogleSSO == nil {
		writeError(w, http.StatusServiceUnavailable, "google_sso_disabled",
			"Google sign-in is not enabled", correlationOf(r))
		return true
	}
	return false
}

// googleNonce issues the single-use nonce a client embeds in its Google ID-token request. The
// nonce is stored server-side and consumed by the first POST that presents it.
func (s *Server) googleNonce(w http.ResponseWriter, r *http.Request) {
	if s.googleSSODisabled(w, r) {
		return
	}
	now := s.Now()
	expiresAt := now.Add(s.Config.GoogleSSO.NonceTTL)
	for attempt := 0; attempt < 3; attempt++ {
		raw := make([]byte, googleNonceBytes)
		if _, err := rand.Read(raw); err != nil {
			writeError(w, http.StatusInternalServerError, "internal_error", "Unexpected error",
				correlationOf(r))
			return
		}
		nonce := base64.RawURLEncoding.EncodeToString(raw)
		err := s.Store.CreateGoogleNonce(r.Context(), nonce, expiresAt, now)
		if err == nil {
			writeJSON(w, http.StatusOK, map[string]any{
				"nonce": nonce, "expiresAt": expiresAt,
				"expiresInSeconds": int(s.Config.GoogleSSO.NonceTTL / time.Second),
			})
			return
		}
		if !isUniqueConstraint(err) {
			s.databaseOrInternal(w, r, err)
			return
		}
	}
	writeError(w, http.StatusInternalServerError, "internal_error", "Unexpected error", correlationOf(r))
}

// googleLogin is both the direct login and the direct registration path. A verified Google identity
// that is already linked logs straight in. Otherwise the identity auto-links to the account that
// owns the same verified email, or provisions a fresh USER account when no account owns it. Owner
// decision overrides the older CR-008 "never auto-create" rule; the security invariant is that only
// a verified email can claim or create an account.
func (s *Server) googleLogin(w http.ResponseWriter, r *http.Request) {
	if s.googleSSODisabled(w, r) {
		return
	}
	var body googleTokenRequest
	if !decodeJSON(w, r, &body) {
		return
	}
	body.IDToken = strings.TrimSpace(body.IDToken)
	body.Nonce = strings.TrimSpace(body.Nonce)
	if body.IDToken == "" || body.Nonce == "" || len(body.IDToken) > googleTokenMax ||
		len(body.Nonce) > googleNonceMax {
		writeError(w, http.StatusBadRequest, "invalid_request", "idToken and nonce are required",
			correlationOf(r))
		return
	}
	// Consume before verifying so a replay loses even when the first token was invalid, and a
	// concurrent duplicate can never verify twice.
	if err := s.Store.ConsumeGoogleNonce(r.Context(), body.Nonce, s.Now()); err != nil {
		if errors.Is(err, store.ErrGoogleNonceInvalid) {
			writeError(w, http.StatusUnauthorized, "google_invalid_token", "Google token is invalid",
				correlationOf(r))
			return
		}
		s.databaseOrInternal(w, r, err)
		return
	}
	claims, err := s.GoogleSSO.Verify(r.Context(), body.IDToken, body.Nonce)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "google_invalid_token", "Google token is invalid",
			correlationOf(r))
		return
	}
	now := s.Now()
	var account store.Account
	identity, err := s.Store.FindGoogleIdentity(r.Context(), claims.Issuer, claims.Subject)
	switch {
	case err == nil:
		// Linked fast path: the link table stays authoritative even if the Google email changed.
		account, err = s.Store.FindAccountByOwner(r.Context(), identity.OwnerID)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				writeError(w, http.StatusConflict, "google_identity_not_linked",
					"This Google account is not linked to a PAM account", correlationOf(r))
				return
			}
			s.databaseOrInternal(w, r, err)
			return
		}
	case errors.Is(err, store.ErrGoogleIdentityNotLinked):
		// An unverified address is not proof of ownership, so it can neither create an account
		// nor claim an existing one.
		if !claims.EmailVerified || claims.Email == "" {
			writeError(w, http.StatusForbidden, "google_email_unverified",
				"Google did not verify this account's email address", correlationOf(r))
			return
		}
		digest, digestErr := googleAccountDigest()
		if digestErr != nil {
			s.Log.Error("request_failed", "correlationId", correlationOf(r),
				"error", digestErr.Error())
			writeError(w, http.StatusInternalServerError, "internal_error", "Unexpected error",
				correlationOf(r))
			return
		}
		result, loginErr := s.Store.FindOrCreateAccountForGoogle(r.Context(), claims.Issuer,
			claims.Subject, claims.Email, googleDisplayName(claims), digest, now)
		if loginErr != nil {
			if errors.Is(loginErr, store.ErrGoogleIdentityConflict) {
				writeError(w, http.StatusConflict, "google_identity_conflict",
					"This email belongs to a PAM account linked to a different Google account",
					correlationOf(r))
				return
			}
			s.databaseOrInternal(w, r, loginErr)
			return
		}
		account = result.Account
	default:
		s.databaseOrInternal(w, r, err)
		return
	}
	if account.Status != "ACTIVE" {
		writeError(w, http.StatusForbidden, "account_inactive", "Account is not active",
			correlationOf(r))
		return
	}
	_ = s.Store.TouchGoogleIdentity(r.Context(), claims.Issuer, claims.Subject, now)
	_ = s.Store.TouchAccount(r.Context(), account.OwnerID, now)
	response, err := s.issueSession(r, account, now)
	if err != nil {
		s.databaseOrInternal(w, r, err)
		return
	}
	response.GoogleLinked = boolPointer(true)
	writeJSON(w, http.StatusOK, response)
}

// googleAccountDigest hashes 32 random bytes, so a Google-only account has no usable password: the
// input is never known to anyone and password login for that email can never be guessed.
func googleAccountDigest() (store.PasswordDigest, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return store.PasswordDigest{}, err
	}
	digest, err := auth.HashPassword(base64.RawURLEncoding.EncodeToString(raw))
	if err != nil {
		return store.PasswordDigest{}, err
	}
	return store.PasswordDigest{Salt: digest.Salt, Hash: digest.Hash, KDF: digest.KDF}, nil
}

// googleDisplayName derives the display name for a provisioned account: the Google profile name
// trimmed to 80 runes, falling back to the local part of the verified email.
func googleDisplayName(claims auth.GoogleClaims) string {
	name := strings.TrimSpace(claims.Name)
	if runes := []rune(name); len(runes) > 80 {
		name = string(runes[:80])
	}
	if name != "" {
		return name
	}
	local := claims.Email
	if at := strings.IndexByte(local, '@'); at >= 0 {
		local = local[:at]
	}
	return local
}

// googleLink binds a verified identity to the authenticated owner. It is an explicit, idempotent
// operation: the same identity returns 200 again, a different one conflicts.
func (s *Server) googleLink(w http.ResponseWriter, r *http.Request) {
	if s.googleSSODisabled(w, r) {
		return
	}
	info, _ := authFrom(r)
	account, err := s.Store.FindAccountByOwner(r.Context(), info.OwnerID)
	if err != nil {
		s.databaseOrInternal(w, r, err)
		return
	}
	if account.Status != "ACTIVE" {
		writeError(w, http.StatusForbidden, "account_inactive", "Account is not active",
			correlationOf(r))
		return
	}
	var body googleTokenRequest
	if !decodeJSON(w, r, &body) {
		return
	}
	body.IDToken = strings.TrimSpace(body.IDToken)
	body.Nonce = strings.TrimSpace(body.Nonce)
	if body.IDToken == "" || body.Nonce == "" || len(body.IDToken) > googleTokenMax ||
		len(body.Nonce) > googleNonceMax {
		writeError(w, http.StatusBadRequest, "invalid_request", "idToken and nonce are required",
			correlationOf(r))
		return
	}
	if err := s.Store.ConsumeGoogleNonce(r.Context(), body.Nonce, s.Now()); err != nil {
		if errors.Is(err, store.ErrGoogleNonceInvalid) {
			writeError(w, http.StatusUnauthorized, "google_invalid_token", "Google token is invalid",
				correlationOf(r))
			return
		}
		s.databaseOrInternal(w, r, err)
		return
	}
	claims, err := s.GoogleSSO.Verify(r.Context(), body.IDToken, body.Nonce)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "google_invalid_token", "Google token is invalid",
			correlationOf(r))
		return
	}
	err = s.Store.LinkGoogleIdentity(r.Context(), account.OwnerID, claims.Issuer, claims.Subject,
		claims.Email, s.Now())
	switch {
	case errors.Is(err, store.ErrGoogleIdentityConflict):
		writeError(w, http.StatusConflict, "google_identity_conflict",
			"This Google account is linked to another PAM account", correlationOf(r))
		return
	case errors.Is(err, store.ErrGoogleAlreadyLinked):
		writeError(w, http.StatusConflict, "google_already_linked",
			"This PAM account already has a Google identity", correlationOf(r))
		return
	case err != nil:
		s.databaseOrInternal(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"linked": true, "googleLinked": true})
}

func boolPointer(value bool) *bool { return &value }

// isUniqueConstraint keeps nonce-collision retries local to the handler instead of importing the
// store's SQL error classifier.
func isUniqueConstraint(err error) bool {
	message := err.Error()
	return strings.Contains(message, "UNIQUE constraint failed") ||
		strings.Contains(message, "constraint failed: UNIQUE")
}
