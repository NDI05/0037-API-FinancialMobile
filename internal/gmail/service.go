package gmail

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/pam/recap/backend-go/internal/retention"
	"github.com/pam/recap/backend-go/internal/store"
)

// Errors exposed to HTTP handlers. Every one maps to a safe client-facing code; internal detail
// (Google error bodies, tokens) never leaves this package.
var (
	ErrAlreadyConnected  = errors.New("gmail is already connected")
	ErrNotConnected      = store.ErrGmailNotConnected
	ErrOAuthStateInvalid = store.ErrGmailStateInvalid
	ErrOAuthStateExpired = store.ErrGmailStateExpired
	ErrMailboxTaken      = store.ErrGmailMailboxTaken
)

// Settings is the deployment policy for the Gmail workflow.
type Settings struct {
	RedirectURI string
	// Mode is "polling" (default) or "push". Polling never calls users.watch/stop and never
	// initialises the Pub/Sub verifier; push is the opt-in rollback transport.
	Mode             string
	AppDeepLink      string
	TopicName        string
	Scope            string
	StateTTL         time.Duration
	BackfillMonths   int
	PageSize         int
	MaxPagesPerRun   int
	WatchRenewBefore time.Duration
	// DeltaInterval is the minimum automatic delta cadence per owner (contract: 900 s).
	DeltaInterval time.Duration
	// SyncCooldown throttles POST /v1/gmail/sync per owner (default 60 s).
	SyncCooldown time.Duration
	// RetryAttempts/RetryBackoff bound the automatic retry of transient provider failures.
	RetryAttempts int
	RetryBackoff  time.Duration
	// OwnerRatePerMinute and ProjectRatePerMinute pace Gmail calls so one owner cannot exhaust the
	// project quota. They are process-local.
	OwnerRatePerMinute   int
	ProjectRatePerMinute int
	// DevFake marks the development fixture provider. It only changes the connect flow (the
	// authorization URL is served by the backend) and never weakens state/PKCE/token handling.
	DevFake bool
	// DevScenario selects the fake provider scenario: normal, history_expired or rate_limit.
	DevScenario string
	QueryFilter string
}

// ErrSyncCooldown reports a manual sync request that arrived inside the configured cooldown.
var ErrSyncCooldown = errors.New("gmail sync cooldown active")

// ErrNeedsReauth reports a manual sync on a connection whose grant was revoked. A job queued in
// that state would never drain, so the request is rejected until the owner reconnects.
var ErrNeedsReauth = errors.New("gmail connection needs reauthorization")

// SyncCooldownError carries the remaining cooldown for the HTTP 429 response.
type SyncCooldownError struct {
	RetryAfter time.Duration
}

func (e *SyncCooldownError) Error() string { return ErrSyncCooldown.Error() }

// Is reports ErrSyncCooldown so handlers can map it without type assertions.
func (e *SyncCooldownError) Is(target error) bool { return target == ErrSyncCooldown }

func (s Settings) withDefaults() Settings {
	if s.Scope == "" {
		s.Scope = "https://www.googleapis.com/auth/gmail.readonly"
	}
	if s.StateTTL <= 0 || s.StateTTL > 10*time.Minute {
		s.StateTTL = 10 * time.Minute
	}
	if s.BackfillMonths <= 0 || s.BackfillMonths > 12 {
		s.BackfillMonths = 12
	}
	if s.PageSize <= 0 || s.PageSize > 100 {
		s.PageSize = 50
	}
	if s.MaxPagesPerRun <= 0 || s.MaxPagesPerRun > 50 {
		s.MaxPagesPerRun = 5
	}
	if s.WatchRenewBefore <= 0 {
		s.WatchRenewBefore = 24 * time.Hour
	}
	if s.QueryFilter == "" {
		s.QueryFilter = `(subject:"Pembayaran Berhasil" OR subject:"Transaksi Berhasil" OR ` +
			`subject:"Livin" OR from:livin OR subject:QRIS)`
	}
	if s.AppDeepLink == "" {
		s.AppDeepLink = "pam://gmail/connected"
	}
	if s.Mode != "push" {
		s.Mode = "polling"
	}
	if s.DeltaInterval <= 0 || s.DeltaInterval > 24*time.Hour {
		s.DeltaInterval = 15 * time.Minute
	}
	if s.SyncCooldown <= 0 {
		s.SyncCooldown = 60 * time.Second
	}
	if s.RetryAttempts == 0 {
		s.RetryAttempts = 2
	}
	if s.RetryAttempts < 0 || s.RetryAttempts > 5 {
		s.RetryAttempts = 2
	}
	if s.RetryBackoff <= 0 || s.RetryBackoff > 5*time.Second {
		s.RetryBackoff = 200 * time.Millisecond
	}
	if s.OwnerRatePerMinute <= 0 {
		s.OwnerRatePerMinute = 60
	}
	if s.ProjectRatePerMinute <= 0 {
		s.ProjectRatePerMinute = 600
	}
	return s
}

// pushMode reports whether the legacy Pub/Sub transport is active.
func (s *Service) pushMode() bool { return s.Settings.Mode == "push" }

// Service owns the OAuth connect flow and the sync coordinator.
// CategoryEnqueuer is the optional server-side hook that turns freshly imported transactions into
// automatic categorization work. EnqueueImported must be provider-free; DrainOwner runs one
// bounded, single-flight window and may call the classifier. A hook error never rolls back an
// acknowledged import.
type CategoryEnqueuer interface {
	EnqueueImported(ctx context.Context, ownerID string, transactionIDs []string) (int, error)
	DrainOwner(ctx context.Context, ownerID string) error
}

type Service struct {
	Store    *store.Store
	Provider Provider
	OAuth    TokenExchanger
	Settings Settings
	Log      *slog.Logger
	Now      func() time.Time
	// Categories is wired during startup when automatic categorization is enabled; nil keeps the
	// Gmail worker import-only.
	Categories CategoryEnqueuer
}

func NewService(data *store.Store, provider Provider, exchanger TokenExchanger, settings Settings,
	logger *slog.Logger) *Service {
	if logger == nil {
		logger = slog.Default()
	}
	settings = settings.withDefaults()
	if settings.StateTTL > 10*time.Minute {
		settings.StateTTL = 10 * time.Minute
	}
	service := &Service{Store: data, OAuth: exchanger, Settings: settings, Log: logger,
		Now: time.Now}
	// Every provider call goes through pacing + bounded retries. Tests can still inspect the inner
	// fake via the fixture's pointer because the wrapper is transparent.
	service.Provider = newLimitedProvider(provider, settings, func() time.Time { return service.Now() },
		logger)
	return service
}

// ConnectStart is the response of /v1/gmail/connect/start.
type ConnectStart struct {
	AuthorizationURL string
	ExpiresAt        time.Time
	// DevAuthorization marks the development fixture flow: the handler replaces AuthorizationURL
	// with a backend-served consent page on the request host (no hardcoded port).
	DevAuthorization bool
}

// Start creates a single-use state plus PKCE verifier and returns the consent URL.
func (s *Service) Start(ctx context.Context, ownerID string, reconnect bool) (ConnectStart, error) {
	now := s.Now()
	existing, err := s.Store.GetGmailConnection(ctx, ownerID)
	switch {
	case err == nil && existing.State == "ACTIVE" && !reconnect:
		return ConnectStart{}, ErrAlreadyConnected
	case err != nil && !errors.Is(err, store.ErrGmailNotConnected):
		return ConnectStart{}, err
	}
	state, err := NewState()
	if err != nil {
		return ConnectStart{}, err
	}
	pkce, err := NewPKCEPair()
	if err != nil {
		return ConnectStart{}, err
	}
	expiresAt := now.Add(s.Settings.StateTTL)
	if err := s.Store.CreateGmailOAuthState(ctx, ownerID, hashState(state), pkce.Verifier,
		s.Settings.RedirectURI, expiresAt, now); err != nil {
		return ConnectStart{}, err
	}
	oauth, ok := s.OAuth.(*OAuth)
	authURL := ""
	if ok {
		authURL = oauth.AuthorizationURL(state, pkce.Challenge)
	} else {
		// A fake exchanger has no consent screen. The placeholder keeps the state round-trip for
		// unit tests; the dev HTTP layer replaces it with a runtime-host consent URL.
		authURL = "http://127.0.0.1:18090/v1/gmail/connect/callback/dev/authorize?state=" +
			state + "&code=dev-code&code_challenge=" + pkce.Challenge +
			"&code_challenge_method=S256"
	}
	return ConnectStart{AuthorizationURL: authURL, ExpiresAt: expiresAt,
		DevAuthorization: s.Settings.DevFake}, nil
}

func hashState(state string) string {
	sum := sha256.Sum256([]byte("pam/gmail-oauth-state/v1|" + state))
	return hex.EncodeToString(sum[:])
}

// CallbackResult is what the HTTP handler redirects with.
type CallbackResult struct {
	Status string
	Reason string
}

// Callback completes the OAuth flow: validate state, exchange code, verify the mailbox, seal the
// refresh token, start the watch and schedule the rolling backfill.
func (s *Service) Callback(ctx context.Context, code, state string) CallbackResult {
	now := s.Now()
	ownerID, verifier, redirectURI, err := s.Store.ConsumeGmailOAuthState(ctx, hashState(state), now)
	if err != nil {
		switch {
		case errors.Is(err, store.ErrGmailStateExpired):
			return CallbackResult{Status: "error", Reason: "state_expired"}
		default:
			return CallbackResult{Status: "error", Reason: "state_invalid"}
		}
	}
	if strings.TrimSpace(code) == "" {
		return CallbackResult{Status: "error", Reason: "access_denied"}
	}
	exchange, err := s.OAuth.Exchange(ctx, code, verifier, redirectURI)
	if err != nil {
		if errors.Is(err, ErrUnauthorized) {
			return CallbackResult{Status: "error", Reason: "access_denied"}
		}
		return CallbackResult{Status: "error", Reason: "exchange_failed"}
	}
	if exchange.RefreshToken == "" {
		return CallbackResult{Status: "error", Reason: "refresh_missing"}
	}
	if !scopeContains(exchange.Scope, s.Settings.Scope) {
		return CallbackResult{Status: "error", Reason: "scope_missing"}
	}
	profile, err := s.Provider.Profile(withOwner(ctx, ownerID), exchange.AccessToken)
	if err != nil || !validMailbox(profile.EmailAddress) {
		return CallbackResult{Status: "error", Reason: "email_unverified"}
	}
	var watch WatchState
	// Polling never registers a Pub/Sub watch; push mode keeps the opt-in rollback behaviour.
	if s.pushMode() && s.Settings.TopicName != "" {
		watch, err = s.Provider.Watch(ctx, exchange.AccessToken, s.Settings.TopicName)
		if err != nil {
			return CallbackResult{Status: "error", Reason: "watch_failed"}
		}
	}
	// A reconnect may point the same owner at a different mailbox. Stop and revoke the previous
	// connection's credential before replacing it, so the old mailbox can no longer deliver push
	// notifications and the old token is not left valid.
	if prior, priorErr := s.Store.GetGmailConnection(ctx, ownerID); priorErr == nil &&
		prior.State == "ACTIVE" && prior.AccountEmailHash != s.Store.GmailEmailHash(profile.EmailAddress) {
		if s.pushMode() {
			if token, tokenErr := s.accessToken(ctx, prior); tokenErr == nil {
				if stopErr := s.Provider.StopWatch(withOwner(ctx, ownerID), token); stopErr != nil {
					s.Log.Warn("gmail_reconnect_stop_watch_failed", "correlationId", "-")
				}
			} else {
				s.Log.Warn("gmail_reconnect_stop_watch_skipped", "correlationId", "-")
			}
		}
		if prior.RefreshToken != "" {
			if revokeErr := s.OAuth.Revoke(ctx, prior.RefreshToken); revokeErr != nil {
				s.Log.Warn("gmail_reconnect_revoke_failed", "correlationId", "-")
			}
		}
	}
	connection, err := s.Store.SaveGmailConnection(ctx, store.GmailConnectionInput{
		OwnerID:        ownerID,
		AccountEmail:   profile.EmailAddress,
		Scope:          exchange.Scope,
		RefreshToken:   exchange.RefreshToken,
		WatchExpiresAt: watch.Expiration,
		HistoryCursor:  firstNonEmpty(watch.HistoryID, profile.HistoryID),
		Now:            now,
	})
	if err != nil {
		if errors.Is(err, store.ErrGmailMailboxTaken) {
			return CallbackResult{Status: "error", Reason: "mailbox_taken"}
		}
		return CallbackResult{Status: "error", Reason: "store_failed"}
	}
	// Schedule the rolling-year backfill: the coordinator starts at the current month.
	if err := s.ensureBackfillJobs(ctx, connection, now); err != nil {
		s.Log.Warn("gmail_schedule_backfill_failed", "correlationId", "-")
	}
	return CallbackResult{Status: "success"}
}

// ensureBackfillJobs only materialises the current-month job, so a fresh connect starts syncing
// immediately instead of waiting for the first timer tick.
func (s *Service) ensureBackfillJobs(ctx context.Context, connection store.GmailConnection,
	now time.Time) error {
	month := monthOf(now)
	start, end := monthWindow(month)
	_, err := s.Store.EnsureGmailBackfillJob(ctx, connection.OwnerID, month, start, end, now)
	return err
}

// SyncProgress is the staged backfill progress reported by GET /v1/gmail/status.
type SyncProgress struct {
	Phase       string
	Month       string
	MonthsDone  int
	MonthsTotal int
	PagesDone   int
}

// StatusView is the /v1/gmail/status response body (contract section 9.2).
type StatusView struct {
	Connected       bool
	AccountEmail    string
	Scope           string
	ConnectedAt     time.Time
	LastSyncAt      time.Time
	WatchExpiresAt  time.Time
	SyncState       string
	LastErrorCode   string
	NeedsReauth     bool
	LastAttemptAt   time.Time
	LastSuccessAt   time.Time
	NextSyncAt      time.Time
	SyncRequestedAt time.Time
	Progress        SyncProgress
}

// Status returns the connection state for one owner. Times are zero when null.
func (s *Service) Status(ctx context.Context, ownerID string) (StatusView, error) {
	connection, err := s.Store.GetGmailConnection(ctx, ownerID)
	if errors.Is(err, store.ErrGmailNotConnected) {
		return StatusView{}, nil
	}
	if err != nil {
		return StatusView{}, err
	}
	if connection.State != "ACTIVE" {
		return StatusView{}, nil
	}
	view := StatusView{
		Connected:       true,
		AccountEmail:    maskEmail(connection.AccountEmail),
		Scope:           connection.Scope,
		ConnectedAt:     connection.ConnectedAt,
		LastSyncAt:      connection.LastSyncAt,
		WatchExpiresAt:  connection.WatchExpiresAt,
		SyncState:       connection.SyncState,
		LastErrorCode:   sanitizeErrorCode(connection.LastErrorCode),
		NeedsReauth:     connection.LastErrorCode == "needs_reauth",
		LastAttemptAt:   connection.LastAttemptAt,
		LastSuccessAt:   connection.LastSuccessAt,
		SyncRequestedAt: connection.SyncRequestedAt,
	}
	if !connection.LastAttemptAt.IsZero() {
		view.NextSyncAt = connection.LastAttemptAt.Add(s.Settings.DeltaInterval)
	}
	view.Progress = s.progress(ctx, connection, s.Now())
	return view, nil
}

// progress derives the staged backfill phase from durable rows only, so it is identical after a
// restart and never needs an in-memory counter.
func (s *Service) progress(ctx context.Context, connection store.GmailConnection,
	now time.Time) SyncProgress {
	months := s.backfillMonths(now)
	progress := SyncProgress{Phase: "idle", Month: monthOf(now), MonthsTotal: len(months)}
	if len(months) > 0 {
		since, _ := monthWindow(months[len(months)-1])
		if completed, err := s.Store.CompletedGmailBackfillMonths(ctx, connection.OwnerID, since); err == nil {
			for _, month := range months {
				if completed[month] {
					progress.MonthsDone++
				}
			}
		}
	}
	if job, open, err := s.Store.OpenGmailBackfillJob(ctx, connection.OwnerID); err == nil && open {
		progress.Phase = "backfill"
		if job.MonthID != "" {
			progress.Month = job.MonthID
		}
		progress.PagesDone = job.PagesDone
		return progress
	}
	if job, open, err := s.Store.OpenGmailDeltaJob(ctx, connection.OwnerID); err == nil && open {
		progress.Phase = "delta"
		progress.PagesDone = job.PagesDone
		return progress
	}
	return progress
}

// SyncRequest is the accepted manual sync result.
type SyncRequest struct {
	RequestedAt   time.Time
	Coalesced     bool
	NextAllowedAt time.Time
}

// RequestSync durably queues one delta run. It returns ErrNotConnected when no active mailbox
// exists and a SyncCooldownError while the per-owner cooldown is active. The request survives a
// restart because it is stored on the connection and materialised as a gmail_sync_jobs row.
func (s *Service) RequestSync(ctx context.Context, ownerID string) (SyncRequest, error) {
	now := s.Now()
	connection, err := s.Store.GetGmailConnection(ctx, ownerID)
	if errors.Is(err, store.ErrGmailNotConnected) {
		return SyncRequest{}, ErrNotConnected
	}
	if err != nil {
		return SyncRequest{}, err
	}
	if connection.State != "ACTIVE" {
		return SyncRequest{}, ErrNotConnected
	}
	if connection.LastErrorCode == "needs_reauth" {
		return SyncRequest{}, ErrNeedsReauth
	}
	requestedAt, queued, err := s.Store.RequestGmailSync(ctx, ownerID, s.Settings.SyncCooldown, now)
	if err != nil {
		return SyncRequest{}, err
	}
	if !queued {
		retryAfter := requestedAt.Add(s.Settings.SyncCooldown).Sub(now)
		if retryAfter < 0 {
			retryAfter = 0
		}
		return SyncRequest{}, &SyncCooldownError{RetryAfter: retryAfter}
	}
	_, open, err := s.Store.OpenGmailDeltaJob(ctx, ownerID)
	if err != nil {
		return SyncRequest{}, err
	}
	if !open {
		start := connection.LastSuccessAt
		if start.IsZero() {
			start = now.Add(-48 * time.Hour)
		}
		if _, err := s.Store.EnsureGmailDeltaJob(ctx, ownerID, start, now, now); err != nil {
			return SyncRequest{}, err
		}
	}
	// Reflect the accepted request in the status projection: the owner can see that a delta is
	// pending until the worker drains the durable job and writes "idle" again.
	if err := s.Store.UpdateGmailSyncState(ctx, ownerID, "delta", "", "", time.Time{}, now); err != nil {
		return SyncRequest{}, err
	}
	return SyncRequest{RequestedAt: requestedAt, Coalesced: open,
		NextAllowedAt: requestedAt.Add(s.Settings.SyncCooldown)}, nil
}

// DevAuthorize validates a pending state for the development consent page. The real callback is
// still the only consumer of the state, and PKCE/state handling is unchanged.
func (s *Service) DevAuthorize(ctx context.Context, state string) (string, error) {
	if !s.Settings.DevFake || state == "" {
		return "", store.ErrGmailStateInvalid
	}
	_, redirectURI, err := s.Store.PeekGmailOAuthState(ctx, hashState(state), s.Now())
	return redirectURI, err
}

// DevStats returns fake-provider counters for the owner-authenticated dev endpoint. The second
// return value is false when the fake provider is not active (production or Google provider).
func (s *Service) DevStats() (DevProviderCounters, bool) {
	limited, ok := s.Provider.(*limitedProvider)
	if !ok {
		return DevProviderCounters{}, false
	}
	provider, ok := limited.inner.(*DevFakeProvider)
	if !ok {
		return DevProviderCounters{}, false
	}
	counters := provider.Counters()
	if exchanger, ok := s.OAuth.(*FakeExchanger); ok {
		exchanges, refreshes, _ := exchanger.Counters()
		counters.Exchanges = exchanges
		counters.RefreshCalls = refreshes
	}
	return counters, true
}

// Disconnect stops the watch, revokes the grant when possible and clears the sealed credentials.
func (s *Service) Disconnect(ctx context.Context, ownerID string) error {
	connection, err := s.Store.GetGmailConnection(ctx, ownerID)
	if errors.Is(err, store.ErrGmailNotConnected) {
		return ErrNotConnected
	}
	if err != nil {
		return err
	}
	if connection.State != "ACTIVE" {
		return ErrNotConnected
	}
	if s.pushMode() {
		if token, err := s.accessToken(ctx, connection); err == nil {
			// Stop the watch before revoking: after revocation Gmail rejects users.stop. Polling
			// never registered one, so it must not call the endpoint at all.
			if stopErr := s.Provider.StopWatch(withOwner(ctx, ownerID), token); stopErr != nil {
				s.Log.Warn("gmail_stop_watch_failed", "ownerId", ownerID)
			}
		}
	}
	if connection.RefreshToken != "" {
		if revokeErr := s.OAuth.Revoke(ctx, connection.RefreshToken); revokeErr != nil {
			s.Log.Warn("gmail_revoke_failed", "ownerId", ownerID)
		}
	}
	return s.Store.DisconnectGmail(ctx, ownerID, s.Now())
}

// PushPayload is the decoded Pub/Sub notification. It is stored sealed and never logged.
type PushPayload struct {
	EmailAddress string
	HistoryID    string
}

// HandlePush verifies the push JWT, resolves the owner through the server-side connection only,
// and stores one durable event. Duplicate or unknown-mailbox notifications are acknowledged
// without work so Pub/Sub stops retrying them.
func (s *Service) HandlePush(ctx context.Context, verifier PushVerifier, authorization string,
	rawBody []byte) error {
	claims, err := verifier.Verify(ctx, authorization)
	if err != nil {
		return ErrPushUnauthorized
	}
	payload, publishTime, messageID, ok := decodePushEnvelope(rawBody)
	if !ok {
		return nil
	}
	emailHash := s.Store.GmailEmailHash(payload.EmailAddress)
	connection, err := s.Store.GmailConnectionByEmailHash(ctx, emailHash)
	if errors.Is(err, store.ErrGmailNotConnected) {
		s.Log.Info("gmail_push_unmapped", "audience", claims.Audience)
		return nil
	}
	if err != nil {
		return err
	}
	eventKey := pushEventKey(emailHash, payload.HistoryID, messageID, publishTime)
	encoded, err := json.Marshal(map[string]string{
		"emailAddress": payload.EmailAddress,
		"historyId":    payload.HistoryID,
	})
	if err != nil {
		return err
	}
	if _, err := s.Store.RecordGmailPushEvent(ctx, connection.OwnerID, connection.ID, eventKey,
		string(encoded), publishTime, s.Now()); err != nil {
		return err
	}
	return nil
}

func pushEventKey(emailHash, historyID, messageID, publishTime string) string {
	sum := sha256.Sum256([]byte(strings.Join([]string{"pam/gmail-push/v1", emailHash, historyID,
		messageID, publishTime}, "|")))
	return hex.EncodeToString(sum[:])
}

func decodePushEnvelope(raw []byte) (PushPayload, string, string, bool) {
	var envelope struct {
		Message struct {
			Data        string `json:"data"`
			MessageID   string `json:"messageId"`
			PublishTime string `json:"publishTime"`
		} `json:"message"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return PushPayload{}, "", "", false
	}
	data, err := base64.StdEncoding.DecodeString(envelope.Message.Data)
	if err != nil {
		return PushPayload{}, "", "", false
	}
	var notification struct {
		EmailAddress string `json:"emailAddress"`
		HistoryID    string `json:"historyId"`
	}
	if err := json.Unmarshal(data, &notification); err != nil {
		return PushPayload{}, "", "", false
	}
	if !validMailbox(notification.EmailAddress) || notification.HistoryID == "" {
		return PushPayload{}, "", "", false
	}
	return PushPayload{EmailAddress: notification.EmailAddress, HistoryID: notification.HistoryID},
		envelope.Message.PublishTime, envelope.Message.MessageID, true
}

// SyncReport is the counts-only outcome of one coordinator pass.
type SyncReport struct {
	Connections int
	Backfills   int
	Deltas      int
	Events      int
	Failures    int
}

// RunOnce advances every active connection by a bounded amount of work. In polling mode the tick
// is the only scheduler: a due delta has priority and, after it, exactly one staged backfill unit
// runs so a rolling-year backfill still converges. An idle connection performs no provider call at
// all, which is what makes an empty poll cost zero downloads and zero category work.
func (s *Service) RunOnce(ctx context.Context) (SyncReport, error) {
	now := s.Now()
	connections, err := s.Store.ListActiveGmailConnections(ctx, 100)
	if err != nil {
		return SyncReport{}, err
	}
	report := SyncReport{Connections: len(connections)}
	for _, connection := range connections {
		if skip, reason := s.syncBackoff(connection); skip {
			report.Failures++
			s.Log.Info("gmail_sync_backoff", "reason", reason)
			continue
		}
		// Push events only exist in push mode. Polling must not read or depend on them.
		var events []store.GmailPushEvent
		if s.pushMode() {
			events, err = s.Store.PendingGmailPushEvents(ctx, connection.OwnerID, 20)
			if err != nil {
				report.Failures++
				continue
			}
			if len(events) > 0 {
				if _, err := s.Store.EnsureGmailDeltaJob(ctx, connection.OwnerID,
					now.Add(-48*time.Hour), now, now); err != nil {
					report.Failures++
					continue
				}
				s.finishEvents(ctx, events, "")
				report.Events += len(events)
			}
		}
		deltaDue := s.deltaDue(ctx, connection, now)
		backfillDue := s.backfillPending(ctx, connection, now)
		if !deltaDue && !backfillDue {
			// Nothing is due: do not refresh a token or touch Gmail just because the timer fired.
			continue
		}
		token, tokenErr := s.accessToken(ctx, connection)
		if tokenErr != nil {
			report.Failures++
			phase := "delta"
			if !deltaDue && backfillDue {
				phase = "backfill"
			}
			s.recordFailure(ctx, connection, tokenErr, phase)
			s.finishEvents(ctx, events, "needs_reauth")
			continue
		}
		if s.pushMode() && s.watchDue(connection, now) {
			state, watchErr := s.Provider.Watch(withOwner(ctx, connection.OwnerID), token,
				s.Settings.TopicName)
			if watchErr != nil {
				report.Failures++
				// Watch bookkeeping is push-only; keep the sync phase unchanged on failure.
				s.recordFailure(ctx, connection, watchErr, "delta")
				continue
			}
			historyID := state.HistoryID
			if connection.HistoryCursor != "" {
				historyID = ""
			}
			if err := s.Store.UpdateGmailWatch(ctx, connection.OwnerID, state.Expiration, historyID,
				now); err != nil {
				report.Failures++
				continue
			}
		}
		// Re-read after a possible watch update so the delta job sees the fresh cursor.
		if refreshed, refreshErr := s.Store.GetGmailConnection(ctx, connection.OwnerID); refreshErr == nil {
			connection = refreshed
		}
		if err := s.Store.RecordGmailAttempt(ctx, connection.OwnerID, now); err != nil {
			report.Failures++
			continue
		}
		ownerCtx := withOwner(ctx, connection.OwnerID)
		if deltaDue {
			if err := s.runDelta(ownerCtx, connection, token); err != nil {
				report.Failures++
				s.recordFailure(ctx, connection, err, "delta")
				continue
			}
			report.Deltas++
			if err := s.Store.RecordGmailSuccess(ctx, connection.OwnerID, s.Now()); err != nil {
				s.Log.Warn("gmail_record_success_failed")
			}
			if refreshed, refreshErr := s.Store.GetGmailConnection(ctx, connection.OwnerID); refreshErr == nil {
				connection = refreshed
			}
		}
		// Round-robin staging: one backfill unit per tick after the delta, never a full window in
		// one pass. The month job carries its own page checkpoint, so restarts resume safely.
		if backfillDue {
			if err := s.runBackfill(ownerCtx, connection, token); err != nil {
				report.Failures++
				s.recordFailure(ctx, connection, err, "backfill")
				continue
			}
			report.Backfills++
			if err := s.Store.RecordGmailSuccess(ctx, connection.OwnerID, s.Now()); err != nil {
				s.Log.Warn("gmail_record_success_failed")
			}
		}
	}
	return report, nil
}

// deltaDue reports whether an automatic delta is due: an open delta job (manual sync, push event or
// a restarted checkpoint) always wins, otherwise the 15-minute per-owner cadence applies.
func (s *Service) deltaDue(ctx context.Context, connection store.GmailConnection, now time.Time) bool {
	if _, open, err := s.Store.OpenGmailDeltaJob(ctx, connection.OwnerID); err == nil && open {
		return true
	}
	if connection.HistoryCursor == "" {
		return true
	}
	lastRun := connection.LastAttemptAt
	if lastRun.IsZero() {
		// A freshly connected mailbox is not delta-due immediately: its cursor was just captured,
		// so the first automatic delta follows the configured interval after the connect.
		lastRun = connection.ConnectedAt
	}
	if lastRun.IsZero() {
		return true
	}
	return !now.Before(lastRun.Add(s.Settings.DeltaInterval))
}

func (s *Service) finishEvents(ctx context.Context, events []store.GmailPushEvent, errorCode string) {
	now := s.Now()
	for _, event := range events {
		state := "PROCESSED"
		if errorCode != "" {
			state = "FAILED"
		}
		if err := s.Store.FinishGmailPushEvent(ctx, event.ID, state, errorCode, now); err != nil {
			s.Log.Warn("gmail_push_event_update_failed")
		}
	}
}

func (s *Service) watchDue(connection store.GmailConnection, now time.Time) bool {
	if s.Settings.TopicName == "" {
		return false
	}
	return connection.WatchExpiresAt.IsZero() ||
		connection.WatchExpiresAt.Before(now.Add(s.Settings.WatchRenewBefore))
}

func (s *Service) deltaPending(ctx context.Context, ownerID string) bool {
	_, open, err := s.Store.OpenGmailDeltaJob(ctx, ownerID)
	return err == nil && open
}

// accessToken reuses the sealed access token until shortly before expiry, then refreshes it from
// the sealed refresh token. Reusing the token keeps a backfill run from refreshing once per call.
func (s *Service) accessToken(ctx context.Context, connection store.GmailConnection) (string, error) {
	now := s.Now()
	if connection.AccessToken != "" &&
		connection.AccessTokenExpiresAt.After(now.Add(2*time.Minute)) {
		return connection.AccessToken, nil
	}
	if connection.RefreshToken == "" {
		return "", ErrUnauthorized
	}
	tokens, err := s.OAuth.Refresh(ctx, connection.RefreshToken)
	if err != nil {
		return "", err
	}
	if tokens.AccessToken == "" {
		return "", ErrUnauthorized
	}
	expiry := tokens.Expiry
	if expiry.IsZero() || expiry.Before(now) {
		expiry = now.Add(time.Hour)
	}
	if err := s.Store.UpdateGmailAccessToken(ctx, connection.OwnerID, tokens.AccessToken, expiry,
		now); err != nil {
		// A failed cache write only costs an extra refresh; it must not fail the sync.
		s.Log.Warn("gmail_access_token_cache_failed")
	}
	return tokens.AccessToken, nil
}

func (s *Service) recordFailure(ctx context.Context, connection store.GmailConnection, err error,
	phase string) {
	code := classifyError(err)
	// needs_reauth is a terminal state until the owner reconnects; it keeps the schema's existing
	// "error" sync_state and is carried in last_error_code. A retryable failure (rate limit, 5xx)
	// keeps the phase that failed ("delta" or "backfill") because its job stays open and the next
	// tick retries it.
	syncState := phase
	if code == "needs_reauth" || syncState == "" {
		syncState = "error"
	}
	if updateErr := s.Store.UpdateGmailSyncState(ctx, connection.OwnerID, syncState, "",
		code, s.Now(), s.Now()); updateErr != nil {
		s.Log.Warn("gmail_sync_state_failed")
	}
}

// syncBackoff reports whether this connection should be skipped by the current tick. Only a
// revoked/expired grant stops automatic work; transient failures are retried by the next tick
// through the requeued job, with the provider wrapper's own bounded backoff.
func (s *Service) syncBackoff(connection store.GmailConnection) (bool, string) {
	if connection.LastErrorCode == "needs_reauth" {
		return true, "needs_reauth"
	}
	return false, ""
}

func classifyError(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, ErrUnauthorized):
		return "needs_reauth"
	case IsHistoryExpired(err):
		return "history_expired"
	}
	if IsRateLimited(err) {
		return "rate_limited"
	}
	var apiErr *APIError
	if AsAPIError(err, &apiErr) {
		if apiErr.Code == "provider_unavailable" {
			return "provider_unavailable"
		}
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return "provider_unavailable"
	}
	return "provider_error"
}

func sanitizeErrorCode(code string) string {
	switch code {
	case "needs_reauth", "provider_unavailable", "history_expired", "provider_error",
		"rate_limited", "disconnected", "mailbox_taken":
		return code
	}
	return ""
}

func maskEmail(email string) string {
	email = strings.TrimSpace(email)
	at := strings.LastIndex(email, "@")
	if at <= 0 {
		return "***"
	}
	local, domain := email[:at], email[at+1:]
	if domain == "" {
		return "***"
	}
	first := []rune(local)[0]
	return string(first) + "***@" + domain
}

func validMailbox(email string) bool {
	email = strings.TrimSpace(email)
	if len(email) < 5 || len(email) > 254 || strings.ContainsAny(email, " \t\r\n<>\"") {
		return false
	}
	at := strings.LastIndex(email, "@")
	if at <= 0 || at == len(email)-1 {
		return false
	}
	domain := email[at+1:]
	return strings.Contains(domain, ".") && !strings.HasPrefix(domain, ".") &&
		!strings.HasSuffix(domain, ".")
}

func scopeContains(scope, wanted string) bool {
	for _, granted := range strings.Fields(scope) {
		if granted == wanted {
			return true
		}
	}
	return false
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

// monthOf maps an instant to its WIB month id (YYYY-MM), matching the store's month derivation.
func monthOf(t time.Time) string {
	return t.In(jakarta).Format("2006-01")
}

func monthWindow(month string) (time.Time, time.Time) {
	parsed, err := time.ParseInLocation("2006-01", month, jakarta)
	if err != nil {
		return time.Time{}, time.Time{}
	}
	return parsed.UTC(), parsed.AddDate(0, 1, 0).UTC()
}

func shiftMonth(month string, delta int) string {
	parsed, err := time.ParseInLocation("2006-01", month, jakarta)
	if err != nil {
		return ""
	}
	return parsed.AddDate(0, delta, 0).Format("2006-01")
}

// backfillMonths is the initial-history scan set: the configured rolling WIB months, plus the month
// that contains the NFR-15 window start when that window begins before the oldest month's first
// day. FR-16 requires the initial history to cover the same rolling one-year window as NFR-15,
// including that partial first month; without the extra month the first few days of the window
// would never be queried. Callers still validate every parsed event with the exact window, so the
// extra month is partially retained rather than fully imported.
func (s *Service) backfillMonths(now time.Time) []string {
	months := rollingMonths(now, s.Settings.BackfillMonths)
	if len(months) == 0 {
		return months
	}
	oldestStart, _ := monthWindow(months[len(months)-1])
	windowStart := retention.NewWindow(now).Start
	if windowStart.Before(oldestStart) {
		if extra := monthOf(windowStart); extra != "" {
			months = append(months, extra)
		}
	}
	return months
}

// rollingMonths returns the last N WIB months, newest first.
func rollingMonths(now time.Time, count int) []string {
	current := monthOf(now)
	months := make([]string, 0, count)
	for index := 0; index < count; index++ {
		months = append(months, shiftMonth(current, -index))
	}
	return months
}

// monthQuery builds the Gmail search for one WIB month. The date filter is inclusive of the first
// day and exclusive of the next month's first day; results are still re-checked locally before
// import because Gmail's date filter is timezone-approximate.
func (s *Service) monthQuery(month string) string {
	start, end := monthWindow(month)
	startDate := start.In(jakarta).Format("2006/01/02")
	endDate := end.In(jakarta).Format("2006/01/02")
	return fmt.Sprintf("%s after:%s before:%s", s.Settings.QueryFilter, startDate, endDate)
}

// BackfillPending reports whether the rolling window still has a missing month. It exists so a
// health check (and the tests) can assert scheduling without running a page.
func (s *Service) BackfillPending(ctx context.Context, ownerID string, now time.Time) (bool, error) {
	connection, err := s.Store.GetGmailConnection(ctx, ownerID)
	if err != nil {
		return false, err
	}
	return s.backfillPending(ctx, connection, now), nil
}

// InitialBackfillPending tests the retained months belonging to the mailbox's initial import.
// A new calendar month after that import does not reopen the initial classification gate.
func (s *Service) InitialBackfillPending(ctx context.Context, ownerID string, now time.Time) (bool, error) {
	connection, err := s.Store.GetGmailConnection(ctx, ownerID)
	if errors.Is(err, store.ErrGmailNotConnected) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if connection.State == "DISCONNECTED" {
		return false, nil
	}
	initial := s.backfillMonths(connection.ConnectedAt)
	current := monthSet(s.backfillMonths(now))
	if len(initial) == 0 {
		return false, nil
	}
	since, _ := monthWindow(initial[len(initial)-1])
	completed, err := s.Store.CompletedGmailBackfillMonths(ctx, ownerID, since)
	if err != nil {
		return false, err
	}
	for _, month := range initial {
		if current[month] && !completed[month] {
			return true, nil
		}
	}
	return false, nil
}

func (s *Service) backfillPending(ctx context.Context, connection store.GmailConnection,
	now time.Time) bool {
	months := s.backfillMonths(now)
	if len(months) == 0 {
		return false
	}
	since, _ := monthWindow(months[len(months)-1])
	completed, err := s.Store.CompletedGmailBackfillMonths(ctx, connection.OwnerID, since)
	if err != nil {
		return false
	}
	for _, month := range months {
		if !completed[month] {
			return true
		}
	}
	return false
}

func (s *Service) nextBackfillMonth(ctx context.Context, connection store.GmailConnection,
	now time.Time) (string, bool) {
	months := s.backfillMonths(now)
	if len(months) == 0 {
		return "", false
	}
	since, _ := monthWindow(months[len(months)-1])
	completed, err := s.Store.CompletedGmailBackfillMonths(ctx, connection.OwnerID, since)
	if err != nil {
		return "", false
	}
	for _, month := range months {
		if !completed[month] {
			return month, true
		}
	}
	return "", false
}
