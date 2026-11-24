package httpapi

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"time"

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
	identity, err := s.Store.FindGoogleIdentity(r.Context(), claims.Issuer, claims.Subject)
	if err != nil {
		if errors.Is(err, store.ErrGoogleIdentityNotLinked) {
			// No account is created and no email match is attempted: linking is explicit.
			writeError(w, http.StatusConflict, "google_identity_not_linked",
				"This Google account is not linked to a PAM account", correlationOf(r))
			return
		}
		s.databaseOrInternal(w, r, err)
		return
	}
	account, err := s.Store.FindAccountByOwner(r.Context(), identity.OwnerID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusConflict, "google_identity_not_linked",
				"This Google account is not linked to a PAM account", correlationOf(r))
			return
		}
		s.databaseOrInternal(w, r, err)
		return
	}
	if account.Status != "ACTIVE" {
		writeError(w, http.StatusForbidden, "account_inactive", "Account is not active",
			correlationOf(r))
		return
	}
	now := s.Now()
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
