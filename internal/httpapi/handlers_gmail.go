package httpapi

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/pam/recap/backend-go/internal/gmail"
	"github.com/pam/recap/backend-go/internal/store"
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
	Connected          bool                   `json:"connected"`
	AccountEmailMasked *string                `json:"account_email_masked"`
	Scope              *string                `json:"scope"`
	ConnectedAt        *string                `json:"connected_at"`
	LastSyncAt         *string                `json:"last_sync_at"`
	WatchExpiresAt     *string                `json:"watch_expires_at"`
	SyncState          *string                `json:"sync_state"`
	LastErrorCode      *string                `json:"last_error_code"`
	NeedsReauth        bool                   `json:"needs_reauth"`
	LastAttemptAt      *string                `json:"last_attempt_at"`
	LastSuccessAt      *string                `json:"last_success_at"`
	NextSyncAt         *string                `json:"next_sync_at"`
	SyncRequestedAt    *string                `json:"sync_requested_at"`
	Progress           *gmailProgressResponse `json:"progress"`
}

// gmailProgressResponse is the staged backfill projection from durable rows only.
type gmailProgressResponse struct {
	Phase       string `json:"phase"`
	Month       string `json:"month"`
	MonthsDone  int    `json:"months_done"`
	MonthsTotal int    `json:"months_total"`
	PagesDone   int    `json:"pages_done"`
}

type gmailSyncAcceptedResponse struct {
	Queued        bool   `json:"queued"`
	Coalesced     bool   `json:"coalesced"`
	RequestedAt   string `json:"requested_at"`
	NextAllowedAt string `json:"next_allowed_at"`
}

type gmailSyncCooldownResponse struct {
	Code              string `json:"code"`
	Message           string `json:"message"`
	RetryAfterSeconds int    `json:"retry_after_seconds"`
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
	authorizationURL := start.AuthorizationURL
	if start.DevAuthorization {
		// The fixture consent page is served by this backend, on whatever host/port the client
		// reached (no hardcoded loopback port). State/PKCE stay the same.
		state := ""
		if parsed, parseErr := url.Parse(start.AuthorizationURL); parseErr == nil {
			state = parsed.Query().Get("state")
		}
		scheme := "http"
		if r.TLS != nil {
			scheme = "https"
		}
		authorizationURL = scheme + "://" + r.Host + "/v1/gmail/connect/dev/authorize?state=" +
			url.QueryEscape(state)
	}
	writeJSON(w, http.StatusOK, gmailStartResponse{
		AuthorizationURL: authorizationURL,
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
	response := gmailStatusResponse{Connected: view.Connected, NeedsReauth: view.NeedsReauth}
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
		response.LastAttemptAt = timeOrNil(view.LastAttemptAt)
		response.LastSuccessAt = timeOrNil(view.LastSuccessAt)
		response.NextSyncAt = timeOrNil(view.NextSyncAt)
		response.SyncRequestedAt = timeOrNil(view.SyncRequestedAt)
		if view.LastErrorCode != "" {
			code := view.LastErrorCode
			response.LastErrorCode = &code
		}
		response.Progress = &gmailProgressResponse{
			Phase:       view.Progress.Phase,
			Month:       view.Progress.Month,
			MonthsDone:  view.Progress.MonthsDone,
			MonthsTotal: view.Progress.MonthsTotal,
			PagesDone:   view.Progress.PagesDone,
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
		// Polling/disconnected deployments must look like the route does not exist (contract §9.1).
		writeError(w, http.StatusNotFound, "not_found", "Gmail push is not enabled", correlationOf(r))
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

// gmailSync queues one durable delta run. It never blocks on Gmail: the coordinator picks the
// request up on its next tick, so a slow provider cannot hold the HTTP request open.
func (s *Server) gmailSync(w http.ResponseWriter, r *http.Request) {
	service, ok := s.gmailService(w, r)
	if !ok {
		return
	}
	request, err := service.RequestSync(r.Context(), gmailOwner(r))
	switch {
	case errors.Is(err, gmail.ErrNotConnected):
		writeError(w, http.StatusConflict, "gmail_not_connected", "No active Gmail connection",
			correlationOf(r))
		return
	case errors.Is(err, gmail.ErrSyncCooldown):
		cooldown := &gmail.SyncCooldownError{}
		_ = errors.As(err, &cooldown)
		seconds := int(cooldown.RetryAfter.Seconds())
		if seconds < 1 {
			seconds = 1
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusTooManyRequests)
		_ = json.NewEncoder(w).Encode(gmailSyncCooldownResponse{
			Code: "sync_cooldown", Message: "A Gmail sync was requested recently",
			RetryAfterSeconds: seconds,
		})
		return
	case err != nil:
		writeError(w, http.StatusInternalServerError, "internal_error",
			"Could not queue the Gmail sync", correlationOf(r))
		return
	}
	writeJSON(w, http.StatusAccepted, gmailSyncAcceptedResponse{
		Queued: true, Coalesced: request.Coalesced,
		RequestedAt:   request.RequestedAt.UTC().Format(time.RFC3339Nano),
		NextAllowedAt: request.NextAllowedAt.UTC().Format(time.RFC3339Nano),
	})
}

// gmailDevAuthorize renders the development-only consent page. It is reachable only when the fake
// provider is active (development + loopback flag); production never registers fixture state.
func (s *Server) gmailDevAuthorize(w http.ResponseWriter, r *http.Request) {
	if s.Gmail == nil {
		http.NotFound(w, r)
		return
	}
	if _, ok := s.Gmail.DevStats(); !ok {
		http.NotFound(w, r)
		return
	}
	state := r.URL.Query().Get("state")
	if _, err := s.Gmail.DevAuthorize(r.Context(), state); err != nil {
		writeError(w, http.StatusBadRequest, "gmail_state_invalid", "Consent state is invalid",
			correlationOf(r))
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("<!doctype html><html><body><h1>PAM Gmail dev consent</h1>" +
		"<p>Development fixture provider. No Google account is contacted.</p>" +
		"<a href=\"/v1/gmail/connect/dev/approve?state=" + url.QueryEscape(state) +
		"&approve=1\">Approve</a></body></html>"))
}

// gmailDevApprove returns a one-time fixture code to the redirect URI. The real callback still
// consumes the state and seals the token, so this path cannot bypass the OAuth checks.
func (s *Server) gmailDevApprove(w http.ResponseWriter, r *http.Request) {
	if s.Gmail == nil {
		http.NotFound(w, r)
		return
	}
	if _, ok := s.Gmail.DevStats(); !ok {
		http.NotFound(w, r)
		return
	}
	state := r.URL.Query().Get("state")
	redirectURI, err := s.Gmail.DevAuthorize(r.Context(), state)
	if err != nil {
		writeError(w, http.StatusBadRequest, "gmail_state_invalid", "Consent state is invalid",
			correlationOf(r))
		return
	}
	parsed, err := url.Parse(redirectURI)
	if err != nil {
		writeError(w, http.StatusBadRequest, "gmail_redirect_invalid", "Redirect URI is invalid",
			correlationOf(r))
		return
	}
	query := parsed.Query()
	query.Set("code", store.NewID("devcode"))
	query.Set("state", state)
	parsed.RawQuery = query.Encode()
	http.Redirect(w, r, parsed.String(), http.StatusFound)
}

// gmailDevStats exposes call counters only. Owner authentication is required even though the data
// is not sensitive, so a public deployment with the fake accidentally enabled still is not open.
func (s *Server) gmailDevStats(w http.ResponseWriter, r *http.Request) {
	service, ok := s.gmailService(w, r)
	if !ok {
		return
	}
	counters, active := service.DevStats()
	if !active {
		http.NotFound(w, r)
		return
	}
	writeJSON(w, http.StatusOK, counters)
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
