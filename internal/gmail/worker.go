package gmail

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/pam/recap/backend-go/internal/store"
)

// pageProgress is the resumable state of one month scan. It is only advanced after ImportBatch
// acknowledged the page, so a crash re-reads a page instead of skipping notifications.
type pageProgress struct {
	NextToken  string
	Done       bool
	Seen       int
	Imported   int
	Duplicates int
	Skipped    int
}

// runBackfill advances the rolling one-year window by one month (current month first).
func (s *Service) runBackfill(ctx context.Context, connection store.GmailConnection,
	accessToken string) error {
	now := s.Now()
	month, ok := s.nextBackfillMonth(ctx, connection, now)
	if !ok {
		return nil
	}
	start, end := monthWindow(month)
	job, err := s.Store.EnsureGmailBackfillJob(ctx, connection.OwnerID, month, start, end, now)
	if err != nil {
		return err
	}
	job, err = s.Store.StartGmailSyncJob(ctx, connection.OwnerID, job.ID, now)
	if err != nil {
		return err
	}
	if err := s.Store.UpdateGmailSyncState(ctx, connection.OwnerID, "backfill", "", "", time.Time{}, now); err != nil {
		return err
	}
	progress, err := s.importMonthPages(ctx, connection, accessToken, month, job.PageToken,
		"backfill:"+job.ID, func(page pageProgress) error {
			return s.Store.CheckpointGmailSyncJob(ctx, connection.OwnerID, job.ID, page.NextToken,
				page.Seen, page.Imported, page.Duplicates, page.Skipped, s.Now())
		})
	if err != nil {
		s.failJob(ctx, connection, job, err)
		return err
	}
	if !progress.Done {
		// Bounded run: the next tick resumes from the persisted page token.
		return nil
	}
	if err := s.Store.FinishGmailSyncJob(ctx, connection.OwnerID, job.ID, "COMPLETE", "", s.Now()); err != nil {
		return err
	}
	return s.Store.UpdateGmailSyncState(ctx, connection.OwnerID, "idle", "", "", s.Now(), s.Now())
}

// syncDelta applies the Gmail history cursor. An expired cursor falls back to a staged re-scan of
// the current month, then resumes from a fresh profile history id.
func (s *Service) runDelta(ctx context.Context, connection store.GmailConnection,
	accessToken string) error {
	now := s.Now()
	job, err := s.Store.EnsureGmailDeltaJob(ctx, connection.OwnerID, now.Add(-48*time.Hour), now, now)
	if err != nil {
		return err
	}
	job, err = s.Store.StartGmailSyncJob(ctx, connection.OwnerID, job.ID, now)
	if err != nil {
		return err
	}
	if err := s.Store.UpdateGmailSyncState(ctx, connection.OwnerID, "delta", "", "", time.Time{}, now); err != nil {
		return err
	}
	cursor := connection.HistoryCursor
	if cursor == "" {
		return s.recoverHistory(ctx, connection, accessToken, job, "cursor_missing")
	}
	pageToken := job.PageToken
	latest := cursor
	for pages := 0; pages < s.Settings.MaxPagesPerRun; pages++ {
		page, listErr := s.Provider.History(ctx, accessToken, cursor, pageToken,
			s.Settings.PageSize)
		if listErr != nil {
			if IsHistoryExpired(listErr) {
				return s.recoverHistory(ctx, connection, accessToken, job, "history_expired")
			}
			s.failJob(ctx, connection, job, listErr)
			return listErr
		}
		if err := s.importHistoryMessages(ctx, connection, accessToken, page.MessageIDs); err != nil {
			s.failJob(ctx, connection, job, err)
			return err
		}
		pageToken = page.NextPageToken
		if page.LatestHistoryID != "" {
			latest = page.LatestHistoryID
		}
		if err := s.Store.CheckpointGmailSyncJob(ctx, connection.OwnerID, job.ID, pageToken,
			job.Seen, job.Imported, job.Duplicates, job.Skipped, s.Now()); err != nil {
			return err
		}
		if pageToken == "" {
			break
		}
	}
	if pageToken != "" {
		return nil
	}
	if err := s.Store.FinishGmailSyncJob(ctx, connection.OwnerID, job.ID, "COMPLETE", "", s.Now()); err != nil {
		return err
	}
	return s.Store.UpdateGmailSyncState(ctx, connection.OwnerID, "idle", latest, "", s.Now(), s.Now())
}

// recoverHistory is the documented recovery path for an expired/missing cursor: re-scan the
// current month (dedupe makes it safe), take a fresh cursor from profile and close the delta job.
func (s *Service) recoverHistory(ctx context.Context, connection store.GmailConnection,
	accessToken string, job store.GmailSyncJob, reason string) error {
	now := s.Now()
	month := monthOf(now)
	if _, err := s.importMonthPages(ctx, connection, accessToken, month, "",
		"recover:"+job.ID, func(page pageProgress) error { return nil }); err != nil {
		s.failJob(ctx, connection, job, err)
		return err
	}
	profile, err := s.Provider.Profile(ctx, accessToken)
	if err != nil {
		s.failJob(ctx, connection, job, err)
		return err
	}
	if err := s.Store.FinishGmailSyncJob(ctx, connection.OwnerID, job.ID, "COMPLETE", reason,
		now); err != nil {
		return err
	}
	return s.Store.UpdateGmailSyncState(ctx, connection.OwnerID, "idle", profile.HistoryID, "",
		now, now)
}

// failJob records a typed failure and marks the connection as errored. The next tick retries the
// same month; a retried backfill page is safe because the page token was not advanced.
func (s *Service) failJob(ctx context.Context, connection store.GmailConnection,
	job store.GmailSyncJob, cause error) {
	now := s.Now()
	state := "FAILED"
	code := classifyError(cause)
	if code == "needs_reauth" {
		state = "NEEDS_REAUTH"
	}
	if err := s.Store.FinishGmailSyncJob(ctx, connection.OwnerID, job.ID, state, code, now); err != nil {
		s.Log.Warn("gmail_sync_finish_failed")
	}
	s.recordFailure(ctx, connection, cause)
}

// importMonthPages lists and imports one WIB month, page by page, checkpointing after each
// acknowledged page. It is used by the rolling backfill and by the history-recovery scan.
func (s *Service) importMonthPages(ctx context.Context, connection store.GmailConnection,
	accessToken, month, startToken, prefix string, checkpoint func(pageProgress) error) (pageProgress, error) {
	now := s.Now()
	importJob, err := s.Store.CreateImportJob(ctx, connection.OwnerID, month, TemplateVersion, now)
	if err != nil {
		return pageProgress{}, err
	}
	progress := pageProgress{NextToken: startToken}
	query := s.monthQuery(month)
	for pages := 0; pages < s.Settings.MaxPagesPerRun; pages++ {
		list, err := s.Provider.ListMessages(ctx, accessToken, query, progress.NextToken,
			s.Settings.PageSize)
		if err != nil {
			s.finalizeMonthJob(ctx, connection.OwnerID, importJob.ID, progress, "PARTIAL", classifyError(err))
			return pageProgress{}, err
		}
		candidates, err := s.buildCandidates(ctx, connection, accessToken, refIDs(list.Messages), month)
		if err != nil {
			s.finalizeMonthJob(ctx, connection.OwnerID, importJob.ID, progress, "PARTIAL", classifyError(err))
			return pageProgress{}, err
		}
		if len(candidates) > 0 {
			counts, importedIDs, _, err := s.Store.ImportBatch(ctx, connection.OwnerID,
				importJob.ID, fmt.Sprintf("%s:p%d", prefix, pages),
				candidatesRequestHash(candidates), pages, candidates, now)
			if err != nil {
				s.finalizeMonthJob(ctx, connection.OwnerID, importJob.ID, progress, "FAILED", "import_failed")
				return pageProgress{}, err
			}
			progress.Seen += counts.Matched
			progress.Imported += counts.Imported
			progress.Duplicates += counts.Duplicates
			progress.Skipped += counts.Skipped
			s.autoCategorize(ctx, connection.OwnerID, importedIDs)
		}
		progress.NextToken = list.NextPageToken
		if err := checkpoint(progress); err != nil {
			return pageProgress{}, err
		}
		if progress.NextToken == "" {
			progress.Done = true
			break
		}
	}
	if progress.Done {
		finalState := "COMPLETE"
		if progress.Seen == 0 {
			finalState = "EMPTY"
		}
		s.finalizeMonthJob(ctx, connection.OwnerID, importJob.ID, progress, finalState, "")
	} else {
		s.finalizeMonthJob(ctx, connection.OwnerID, importJob.ID, progress, "PARTIAL", "")
	}
	return progress, nil
}

func (s *Service) finalizeMonthJob(ctx context.Context, ownerID, jobID string,
	progress pageProgress, state, errorCode string) {
	if _, err := s.Store.FinalizeImportJob(ctx, ownerID, jobID, state, errorCode, s.Now()); err != nil {
		s.Log.Warn("gmail_import_finalize_failed", "state", state)
	}
}

// autoCategorize hands newly imported transactions to the server-side category pipeline: enqueue
// is provider-free, the drain is bounded and single-flight. A failure here is logged and retried by
// the durable category window; the import stays acknowledged either way.
func (s *Service) autoCategorize(ctx context.Context, ownerID string, transactionIDs []string) {
	if s.Categories == nil || len(transactionIDs) == 0 {
		return
	}
	queued, err := s.Categories.EnqueueImported(ctx, ownerID, transactionIDs)
	if err != nil {
		s.Log.Warn("gmail_category_enqueue_failed")
		return
	}
	if queued == 0 {
		return
	}
	if err := s.Categories.DrainOwner(ctx, ownerID); err != nil {
		s.Log.Warn("gmail_category_drain_failed")
		return
	}
	s.Log.Info("gmail_category_window", "queued", queued)
}

// importHistoryMessages parses history message ids, groups them by WIB month and imports each
// group through the normal ingest pipeline.
func (s *Service) importHistoryMessages(ctx context.Context, connection store.GmailConnection,
	accessToken string, messageIDs []string) error {
	if len(messageIDs) == 0 {
		return nil
	}
	now := s.Now()
	byMonth := map[string][]store.ImportCandidate{}
	for _, messageID := range messageIDs {
		candidate, month, err := s.buildCandidate(ctx, connection, accessToken, messageID)
		if err != nil {
			return err
		}
		if month == "" {
			month = monthOf(now)
		}
		byMonth[month] = append(byMonth[month], candidate)
	}
	months := make([]string, 0, len(byMonth))
	for month := range byMonth {
		months = append(months, month)
	}
	sort.Strings(months)
	for _, month := range months {
		candidates := byMonth[month]
		importJob, err := s.Store.CreateImportJob(ctx, connection.OwnerID, month, TemplateVersion, now)
		if err != nil {
			return err
		}
		seen := 0
		for start := 0; start < len(candidates); start += 100 {
			end := start + 100
			if end > len(candidates) {
				end = len(candidates)
			}
			chunk := candidates[start:end]
			counts, importedIDs, _, err := s.Store.ImportBatch(ctx, connection.OwnerID,
				importJob.ID, fmt.Sprintf("delta:%s:%d", importJob.ID, start/100),
				candidatesRequestHash(chunk), start/100, chunk, now)
			if err != nil {
				s.finalizeMonthJob(ctx, connection.OwnerID, importJob.ID,
					pageProgress{Seen: seen}, "PARTIAL", "import_failed")
				return err
			}
			seen += counts.Matched
			s.autoCategorize(ctx, connection.OwnerID, importedIDs)
		}
		state := "COMPLETE"
		if seen == 0 {
			state = "EMPTY"
		}
		s.finalizeMonthJob(ctx, connection.OwnerID, importJob.ID, pageProgress{Seen: seen}, state, "")
	}
	return nil
}

func (s *Service) buildCandidates(ctx context.Context, connection store.GmailConnection,
	accessToken string, messageIDs []string, month string) ([]store.ImportCandidate, error) {
	candidates := make([]store.ImportCandidate, 0, len(messageIDs))
	for _, messageID := range messageIDs {
		candidate, messageMonth, err := s.buildCandidate(ctx, connection, accessToken, messageID)
		if err != nil {
			return nil, err
		}
		if candidate.Status == "PARSED" && messageMonth != month {
			// Gmail's after/before filter is approximate; never send an out-of-month row into the
			// import job, it would reject the whole page.
			candidate = store.ImportCandidate{
				Fingerprint:   s.Store.IngestFingerprint(candidate.SourceRef, "", "", 0, time.Unix(0, 0)),
				SourceRef:     candidate.SourceRef,
				Status:        "UNRESOLVED",
				Reason:        "outside_period",
				ParserVersion: TemplateVersion,
			}
		}
		candidates = append(candidates, candidate)
	}
	return candidates, nil
}

// buildCandidate fetches one raw message (memory only), decodes and parses it, and returns the
// candidate plus the WIB month it belongs to ("" for unparsed notifications).
func (s *Service) buildCandidate(ctx context.Context, connection store.GmailConnection,
	accessToken, messageID string) (store.ImportCandidate, string, error) {
	sourceRef := store.GmailSourceRef(connection.AccountEmailHash, messageID)
	raw, err := s.Provider.GetMessage(ctx, accessToken, messageID)
	if err != nil {
		return store.ImportCandidate{}, "", err
	}
	decoded, err := DecodeMessage(raw.Raw)
	if err != nil {
		return store.ImportCandidate{
			Fingerprint:   s.Store.IngestFingerprint(sourceRef, "", "", 0, time.Unix(0, 0)),
			SourceRef:     sourceRef,
			Status:        "UNRESOLVED",
			Reason:        "mime_unreadable",
			ParserVersion: TemplateVersion,
		}, "", nil
	}
	parsed := ParseLivinNotification(decoded)
	if parsed.Status != "PARSED" {
		return store.ImportCandidate{
			Fingerprint:   s.Store.IngestFingerprint(sourceRef, "", "", 0, time.Unix(0, 0)),
			SourceRef:     sourceRef,
			Status:        "UNRESOLVED",
			Reason:        firstNonEmpty(parsed.Reason, "template_unknown"),
			ParserVersion: TemplateVersion,
			Description:   parsed.Description,
		}, "", nil
	}
	eventAt := parsed.EventAt
	if eventAt.Location() != jakarta {
		eventAt = eventAt.In(jakarta)
	}
	return store.ImportCandidate{
		Fingerprint: s.Store.IngestFingerprint(sourceRef, parsed.MerchantLabel, parsed.Direction,
			parsed.AmountMinor, eventAt),
		SourceRef:     sourceRef,
		Status:        "PARSED",
		Direction:     parsed.Direction,
		AmountMinor:   parsed.AmountMinor,
		EventAt:       eventAt,
		ParserVersion: TemplateVersion,
		Confidence:    1,
		Description:   parsed.Description,
		MerchantLabel: parsed.MerchantLabel,
	}, monthOf(eventAt), nil
}

// candidatesRequestHash makes the ImportBatch replay detection meaningful: the same page content
// must produce the same hash, a changed page must conflict instead of silently re-importing.
func candidatesRequestHash(candidates []store.ImportCandidate) string {
	hasher := sha256.New()
	for _, candidate := range candidates {
		hasher.Write([]byte(candidate.Fingerprint))
		hasher.Write([]byte{0})
		hasher.Write([]byte(candidate.Status))
		hasher.Write([]byte{0})
		hasher.Write([]byte(candidate.SourceRef))
		hasher.Write([]byte{0})
	}
	return hex.EncodeToString(hasher.Sum(nil))
}

func refIDs(refs []MessageRef) []string {
	ids := make([]string, 0, len(refs))
	for _, ref := range refs {
		if ref.ID != "" {
			ids = append(ids, ref.ID)
		}
	}
	return ids
}

func isTransientProviderError(err error) bool {
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		return apiErr.Code == "provider_unavailable"
	}
	return false
}
