package httpapi

import (
	"errors"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/pam/recap/backend-go/internal/gmail"
)

// gmailStartRequest is `{}` unless the app wants to replace an existing connection.
type gmailStartRequest struct {
	Reconnect bool `json:"reconnect"`
}

type gmailStartResponse struct {
	AuthorizationURL string `json:"authorization_url"`
	ExpiresAt        string `json:"expires_at"`
}

type gmailStatusResponse struct {
	Connected          bool    `json:"connected"`
	AccountEmailMasked *string `json:"account_email_masked"`
	Scope              *string `json:"scope"`
	ConnectedAt        *string `json:"connected_at"`
	LastSyncAt         *string `json:"last_sync_at"`
	WatchExpiresAt     *string `json:"watch_expires_at"`
	SyncState          *string `json:"sync_state"`
	LastErrorCode      *string `json:"last_error_code"`
}

type gmailDisconnectResponse struct {
	Disconnected bool `json:"disconnected"`
}

// gmailConnectStart returns the Google consent URL. The state binds the flow to this owner and
// expires within ten minutes; nothing about the Google account is accepted from the client.
func (s *Server) gmailConnectStart(w http.ResponseWriter, r *http.Request) {
	service, ok := s.gmailService(w, r)
	if !ok {
		return
	}
	request := gmailStartRequest{}
	if r.ContentLength > 0 {
		if !decodeJSON(w, r, &request) {
			return
		}
	}
	start, err := service.Start(r.Context(), gmailOwner(r), request.Reconnect)
	switch {
	case errors.Is(err, gmail.ErrAlreadyConnected):
		writeError(w, http.StatusConflict, "gmail_already_connected",
			"Gmail is already connected; reconnect to replace it", correlationOf(r))
		return
	case err != nil:
		writeError(w, http.StatusInternalServerError, "internal_error", "Could not start the Gmail connection", correlationOf(r))
		return
	}
	writeJSON(w, http.StatusOK, gmailStartResponse{
		AuthorizationURL: start.AuthorizationURL,
		ExpiresAt:        start.ExpiresAt.UTC().Format(time.RFC3339Nano),
	})
}

// gmailConnectCallback finishes the OAuth flow and redirects to the app deep link. The query string
// is never logged; sanitizedRoute folds it into one fixed route label.
func (s *Server) gmailConnectCallback(w http.ResponseWriter, r *http.Request) {
	if s.Gmail == nil {
		http.Redirect(w, r, s.gmailRedirect("error", "gmail_disabled"), http.StatusFound)
		return
	}
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")
	result := s.Gmail.Callback(r.Context(), code, state)
	http.Redirect(w, r, s.gmailRedirect(result.Status, result.Reason), http.StatusFound)
}

func (s *Server) gmailRedirect(status, reason string) string {
	base := "pam://gmail/connected"
	if s.Config != nil && s.Config.Gmail.AppDeepLink != "" {
		base = s.Config.Gmail.AppDeepLink
	}
	target, err := url.Parse(base)
	if err != nil {
		target = &url.URL{Scheme: "pam", Host: "gmail", Path: "/connected"}
	}
	query := target.Query()
	query.Set("status", status)
	if reason != "" {
		query.Set("reason", reason)
	}
	target.RawQuery = query.Encode()
	return target.String()
}

// gmailStatus reports the connection without ever returning the mailbox address in full.
func (s *Server) gmailStatus(w http.ResponseWriter, r *http.Request) {
	service, ok := s.gmailService(w, r)
	if !ok {
		return
	}
	view, err := service.Status(r.Context(), gmailOwner(r))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "Could not read the Gmail status", correlationOf(r))
		return
	}
	response := gmailStatusResponse{Connected: view.Connected}
	if view.Connected {
		email := view.AccountEmail
		scope := view.Scope
		syncState := view.SyncState
		if syncState == "" {
			syncState = "idle"
		}
		response.AccountEmailMasked = &email
		response.Scope = &scope
		response.SyncState = &syncState
		response.ConnectedAt = timeOrNil(view.ConnectedAt)
		response.LastSyncAt = timeOrNil(view.LastSyncAt)
		response.WatchExpiresAt = timeOrNil(view.WatchExpiresAt)
		if view.LastErrorCode != "" {
			code := view.LastErrorCode
			response.LastErrorCode = &code
		}
	}
	writeJSON(w, http.StatusOK, response)
}

// gmailDisconnect stops the watch, revokes the grant when possible and clears the sealed token.
func (s *Server) gmailDisconnect(w http.ResponseWriter, r *http.Request) {
	service, ok := s.gmailService(w, r)
	if !ok {
		return
	}
	err := service.Disconnect(r.Context(), gmailOwner(r))
	switch {
	case errors.Is(err, gmail.ErrNotConnected):
		writeError(w, http.StatusConflict, "gmail_not_connected", "No active Gmail connection", correlationOf(r))
		return
	case err != nil:
		writeError(w, http.StatusInternalServerError, "internal_error", "Could not disconnect Gmail", correlationOf(r))
		return
	}
	writeJSON(w, http.StatusOK, gmailDisconnectResponse{Disconnected: true})
}

// gmailPush receives a Pub/Sub push. Authentication is the OIDC JWT issued to the Pub/Sub service
// account, not a PAM session; the owner is resolved only from server-side connections.
func (s *Server) gmailPush(w http.ResponseWriter, r *http.Request) {
	if s.Gmail == nil || s.GmailPushVerifier == nil {
		writeError(w, http.StatusServiceUnavailable, "gmail_disabled", "Gmail push is not enabled", correlationOf(r))
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 64*1024))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "Push body is invalid", correlationOf(r))
		return
	}
	err = s.Gmail.HandlePush(r.Context(), s.GmailPushVerifier, r.Header.Get("Authorization"), body)
	switch {
	case errors.Is(err, gmail.ErrPushUnauthorized):
		writeError(w, http.StatusUnauthorized, "unauthorized", "Push token is not authorized", correlationOf(r))
		return
	case err != nil:
		// A transient store failure must be retried by Pub/Sub, so it is not acknowledged.
		writeError(w, http.StatusInternalServerError, "internal_error", "Could not record the push event", correlationOf(r))
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// gmailService is the shared "is the feature enabled" guard.
func (s *Server) gmailService(w http.ResponseWriter, r *http.Request) (*gmail.Service, bool) {
	if s.Gmail == nil {
		writeError(w, http.StatusServiceUnavailable, "gmail_disabled", "Gmail integration is not enabled", correlationOf(r))
		return nil, false
	}
	return s.Gmail, true
}

func gmailOwner(r *http.Request) string {
	info, _ := authFrom(r)
	return info.OwnerID
}

func timeOrNil(t time.Time) *string {
	if t.IsZero() {
		return nil
	}
	formatted := t.UTC().Format(time.RFC3339Nano)
	return &formatted
}
