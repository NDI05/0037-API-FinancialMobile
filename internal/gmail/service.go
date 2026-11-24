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
	RedirectURI      string
	AppDeepLink      string
	TopicName        string
	Scope            string
	StateTTL         time.Duration
	BackfillMonths   int
	PageSize         int
	MaxPagesPerRun   int
	WatchRenewBefore time.Duration
	QueryFilter      string
}

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
	return s
}

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
	if settings.withDefaults().StateTTL > 10*time.Minute {
		settings.StateTTL = 10 * time.Minute
	}
	return &Service{Store: data, Provider: provider, OAuth: exchanger,
		Settings: settings.withDefaults(), Log: logger, Now: time.Now}
}

// ConnectStart is the response of /v1/gmail/connect/start.
type ConnectStart struct {
	AuthorizationURL string
	ExpiresAt        time.Time
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
		// A fake exchanger has no consent screen; tests still need the state to round-trip.
		authURL = "https://accounts.google.com/o/oauth2/v2/auth?state=" + state +
			"&code_challenge=" + pkce.Challenge
	}
	return ConnectStart{AuthorizationURL: authURL, ExpiresAt: expiresAt}, nil
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
	if !scopeContains(exchange.Scope, "https://www.googleapis.com/auth/gmail.readonly") {
		return CallbackResult{Status: "error", Reason: "scope_missing"}
	}
	profile, err := s.Provider.Profile(ctx, exchange.AccessToken)
	if err != nil || !validMailbox(profile.EmailAddress) {
		return CallbackResult{Status: "error", Reason: "email_unverified"}
	}
	var watch WatchState
	if s.Settings.TopicName != "" {
		watch, err = s.Provider.Watch(ctx, exchange.AccessToken, s.Settings.TopicName)
		if err != nil {
			return CallbackResult{Status: "error", Reason: "watch_failed"}
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

// StatusView is the /v1/gmail/status response body (contract section 3).
type StatusView struct {
	Connected      bool
	AccountEmail   string
	Scope          string
	ConnectedAt    time.Time
	LastSyncAt     time.Time
	WatchExpiresAt time.Time
	SyncState      string
	LastErrorCode  string
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
	return StatusView{
		Connected:      true,
		AccountEmail:   maskEmail(connection.AccountEmail),
		Scope:          connection.Scope,
		ConnectedAt:    connection.ConnectedAt,
		LastSyncAt:     connection.LastSyncAt,
		WatchExpiresAt: connection.WatchExpiresAt,
		SyncState:      connection.SyncState,
		LastErrorCode:  sanitizeErrorCode(connection.LastErrorCode),
	}, nil
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
	if token, err := s.accessToken(ctx, connection); err == nil {
		// Stop the watch before revoking: after revocation Gmail rejects users.stop.
		if stopErr := s.Provider.StopWatch(ctx, token); stopErr != nil {
			s.Log.Warn("gmail_stop_watch_failed", "ownerId", ownerID)
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

// RunOnce advances every active connection by a bounded amount of work.
func (s *Service) RunOnce(ctx context.Context) (SyncReport, error) {
	now := s.Now()
	connections, err := s.Store.ListActiveGmailConnections(ctx, 100)
	if err != nil {
		return SyncReport{}, err
	}
	report := SyncReport{Connections: len(connections)}
	for _, connection := range connections {
		events, err := s.Store.PendingGmailPushEvents(ctx, connection.OwnerID, 20)
		if err != nil {
			report.Failures++
			continue
		}
		token, tokenErr := s.accessToken(ctx, connection)
		if tokenErr != nil {
			report.Failures++
			s.recordFailure(ctx, connection, tokenErr)
			s.finishEvents(ctx, events, "needs_reauth")
			continue
		}
		if s.watchDue(connection, now) {
			state, watchErr := s.Provider.Watch(ctx, token, s.Settings.TopicName)
			if watchErr != nil {
				report.Failures++
				s.recordFailure(ctx, connection, watchErr)
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
		if len(events) > 0 {
			if _, err := s.Store.EnsureGmailDeltaJob(ctx, connection.OwnerID,
				now.Add(-48*time.Hour), now, now); err != nil {
				report.Failures++
				continue
			}
			s.finishEvents(ctx, events, "")
			report.Events += len(events)
		}
		// Refresh the connection after the watch update so the delta job sees the new cursor.
		connection, err = s.Store.GetGmailConnection(ctx, connection.OwnerID)
		if err != nil {
			report.Failures++
			continue
		}
		// Priority: backfill while the rolling window still has missing months, then the delta
		// cursor. Push-triggered deltas were enqueued above, so they run before the next month.
		if s.backfillPending(ctx, connection, now) {
			if err := s.runBackfill(ctx, connection, token); err != nil {
				report.Failures++
				continue
			}
			report.Backfills++
			continue
		}
		if s.deltaPending(ctx, connection.OwnerID) {
			if err := s.runDelta(ctx, connection, token); err != nil {
				report.Failures++
				continue
			}
			report.Deltas++
			continue
		}
		// Idle timer tick: advance the history cursor so a missed push is caught up.
		if _, err := s.Store.EnsureGmailDeltaJob(ctx, connection.OwnerID,
			now.Add(-48*time.Hour), now, now); err != nil {
			report.Failures++
			continue
		}
		if err := s.runDelta(ctx, connection, token); err != nil {
			report.Failures++
			continue
		}
		report.Deltas++
	}
	return report, nil
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

// accessToken refreshes the short-lived Google access token from the sealed refresh token.
func (s *Service) accessToken(ctx context.Context, connection store.GmailConnection) (string, error) {
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
	return tokens.AccessToken, nil
}

func (s *Service) recordFailure(ctx context.Context, connection store.GmailConnection, err error) {
	code := classifyError(err)
	syncState := "error"
	if code == "provider_unavailable" {
		syncState = "error"
	}
	if updateErr := s.Store.UpdateGmailSyncState(ctx, connection.OwnerID, syncState, "",
		code, time.Time{}, s.Now()); updateErr != nil {
		s.Log.Warn("gmail_sync_state_failed")
	}
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
		"disconnected", "mailbox_taken":
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

func (s *Service) backfillPending(ctx context.Context, connection store.GmailConnection,
	now time.Time) bool {
	months := rollingMonths(now, s.Settings.BackfillMonths)
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
	months := rollingMonths(now, s.Settings.BackfillMonths)
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
