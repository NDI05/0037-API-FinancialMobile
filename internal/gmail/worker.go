package gmail

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/pam/recap/backend-go/internal/retention"
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
	PagesDone  int
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
		"backfill:"+job.ID, "", func(page pageProgress) error {
			return s.Store.CheckpointGmailSyncJob(ctx, connection.OwnerID, job.ID, page.NextToken,
				page.Seen, page.Imported, page.Duplicates, page.Skipped,
				job.PagesDone+page.PagesDone, s.Now())
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
	// A recovery run encodes its month/baseline/checkpoint in the sealed page token. Resume there
	// before touching history.list, otherwise a bounded recovery would restart from page one.
	if _, _, _, resuming := decodeRecoveryState(job.PageToken); resuming {
		return s.recoverHistory(ctx, connection, accessToken, job, "history_expired")
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
			job.Seen, job.Imported, job.Duplicates, job.Skipped,
			job.PagesDone+pages+1, s.Now()); err != nil {
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
	// The job that a manual sync queued is done, so the pending marker must not outlive it.
	if err := s.Store.ClearGmailSyncRequest(ctx, connection.OwnerID, s.Now(), s.Now()); err != nil {
		s.Log.Warn("gmail_sync_request_clear_failed")
	}
	return s.Store.UpdateGmailSyncState(ctx, connection.OwnerID, "idle", latest, "", s.Now(), s.Now())
}

// recoveryTokenPrefix marks a delta job that is executing the cross-month recovery scan. The
// sealed page token carries the current month, the pre-scan baseline historyId and the page token,
// so a restart resumes exactly where the last acknowledged page ended.
const recoveryTokenPrefix = "recover:v1:"

func encodeRecoveryState(month, baseline, pageToken string) string {
	return recoveryTokenPrefix + month + ":" + baseline + ":" + pageToken
}

func decodeRecoveryState(raw string) (month, baseline, pageToken string, ok bool) {
	if !strings.HasPrefix(raw, recoveryTokenPrefix) {
		return "", "", "", false
	}
	parts := strings.SplitN(strings.TrimPrefix(raw, recoveryTokenPrefix), ":", 3)
	if len(parts) != 3 || parts[0] == "" {
		return "", "", "", false
	}
	return parts[0], parts[1], parts[2], true
}

// recoverHistory is the documented recovery path for an expired/missing history cursor. It:
//  1. captures the baseline profile historyId BEFORE scanning (never the post-scan id, which could
//     skip messages that arrived during the scan),
//  2. re-scans every WIB month from the last known success up to now, clamped to the 12-month
//     retention window, using after:<unix> + before:<unix> per month,
//  3. checkpoints after every acknowledged ImportBatch page (month + token + baseline),
//  4. sets the cursor back to the baseline and replays the delta from it.
//
// The scan is bounded by MaxPagesPerRun per tick, so a large downtime is resumed by the next tick
// from the sealed checkpoint instead of restarting.
func (s *Service) recoverHistory(ctx context.Context, connection store.GmailConnection,
	accessToken string, job store.GmailSyncJob, reason string) error {
	now := s.Now()
	baseline, resumeMonth, resumeToken := "", "", ""
	resuming := false
	if month, base, token, ok := decodeRecoveryState(job.PageToken); ok {
		baseline, resumeMonth, resumeToken, resuming = base, month, token, true
	}
	if !resuming {
		// Capture the baseline BEFORE the scan: messages that arrive while the scan runs must replay
		// through the delta, not disappear behind a newer cursor.
		profile, err := s.Provider.Profile(withOwner(ctx, connection.OwnerID), accessToken)
		if err != nil {
			s.failJob(ctx, connection, job, err)
			return err
		}
		baseline = profile.HistoryID
	}
	months := s.backfillMonths(now)
	if len(months) == 0 {
		return nil
	}
	retentionStart := retention.NewWindow(now).Start
	rangeStart := connection.LastSuccessAt
	if rangeStart.IsZero() {
		rangeStart = connection.LastAttemptAt
	}
	if rangeStart.IsZero() || rangeStart.Before(retentionStart) {
		rangeStart = retentionStart
	}
	if rangeStart.After(now) {
		rangeStart = now
	}
	scanMonths := monthsBetween(rangeStart, now)
	startIndex := 0
	if resuming {
		for index, month := range scanMonths {
			if month == resumeMonth {
				startIndex = index
				break
			}
		}
	}
	seen, imported, duplicates, skipped := job.Seen, job.Imported, job.Duplicates, job.Skipped
	pagesDone := job.PagesDone
	for _, month := range scanMonths[startIndex:] {
		monthStart, monthEnd := monthWindow(month)
		from := monthStart
		if rangeStart.After(from) {
			from = rangeStart
		}
		to := monthEnd
		if now.Before(to) {
			to = now
		}
		startToken := ""
		if resuming && month == resumeMonth {
			startToken = resumeToken
		}
		query := recoveryQuery(s.Settings.QueryFilter, from, to)
		progress, err := s.importMonthPages(ctx, connection, accessToken, month, startToken,
			"recover:"+job.ID, query, func(page pageProgress) error {
				nextToken := page.NextToken
				if !page.Done {
					nextToken = encodeRecoveryState(month, baseline, page.NextToken)
				}
				return s.Store.CheckpointGmailSyncJob(ctx, connection.OwnerID, job.ID, nextToken,
					seen+page.Seen, imported+page.Imported, duplicates+page.Duplicates,
					skipped+page.Skipped, pagesDone+page.PagesDone, s.Now())
			})
		if err != nil {
			s.failJob(ctx, connection, job, err)
			return err
		}
		seen += progress.Seen
		imported += progress.Imported
		duplicates += progress.Duplicates
		skipped += progress.Skipped
		pagesDone += progress.PagesDone
		if !progress.Done {
			// Bounded run: the checkpoint holds this month and page; the next tick resumes it.
			return nil
		}
		resuming = false
	}
	if err := s.Store.FinishGmailSyncJob(ctx, connection.OwnerID, job.ID, "COMPLETE", reason,
		now); err != nil {
		return err
	}
	if err := s.Store.UpdateGmailSyncState(ctx, connection.OwnerID, "idle", baseline, "", now,
		now); err != nil {
		return err
	}
	// Replay from the baseline so notifications that arrived during the recovery scan are not lost.
	connection.HistoryCursor = baseline
	return s.replayDeltaAfterRecovery(ctx, connection, accessToken)
}

// recoveryQuery filters one recovery month by absolute unix bounds. after:/before: are inclusive of
// the email timestamp, and the local parser still re-checks the transaction month afterwards.
func recoveryQuery(base string, from, to time.Time) string {
	return fmt.Sprintf("%s after:%d before:%d", base, from.Unix(), to.Unix())
}

// monthsBetween returns the WIB months from start to end inclusive, ascending.
func monthsBetween(start, end time.Time) []string {
	first, last := monthOf(start), monthOf(end)
	months := []string{}
	for month := first; month != "" && month <= last; month = shiftMonth(month, 1) {
		months = append(months, month)
	}
	return months
}

// replayDeltaAfterRecovery runs one bounded history replay from the recovered baseline. A second
// expiry is not recovered recursively: the job is closed and the normal 15-minute delta cadence
// retries later, while the month scans above keep every retained notification importable.
func (s *Service) replayDeltaAfterRecovery(ctx context.Context, connection store.GmailConnection,
	accessToken string) error {
	now := s.Now()
	if connection.HistoryCursor == "" {
		return nil
	}
	job, err := s.Store.EnsureGmailDeltaJob(ctx, connection.OwnerID, now.Add(-48*time.Hour), now, now)
	if err != nil {
		return err
	}
	job, err = s.Store.StartGmailSyncJob(ctx, connection.OwnerID, job.ID, now)
	if err != nil {
		return err
	}
	latest := connection.HistoryCursor
	pageToken := job.PageToken
	for pages := 0; pages < s.Settings.MaxPagesPerRun; pages++ {
		page, listErr := s.Provider.History(withOwner(ctx, connection.OwnerID), accessToken,
			connection.HistoryCursor, pageToken, s.Settings.PageSize)
		if listErr != nil {
			if IsHistoryExpired(listErr) {
				// The provider still refuses the cursor; close the replay and let the next scheduled
				// recovery rescan the retained months (idempotent) instead of looping now.
				if finishErr := s.Store.FinishGmailSyncJob(ctx, connection.OwnerID, job.ID,
					"COMPLETE", "history_expired", now); finishErr != nil {
					return finishErr
				}
				return nil
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
			job.Seen, job.Imported, job.Duplicates, job.Skipped,
			job.PagesDone+pages+1, s.Now()); err != nil {
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
	if err := s.Store.ClearGmailSyncRequest(ctx, connection.OwnerID, s.Now(), s.Now()); err != nil {
		s.Log.Warn("gmail_sync_request_clear_failed")
	}
	return s.Store.UpdateGmailSyncState(ctx, connection.OwnerID, "idle", latest, "", s.Now(), s.Now())
}

// failJob records a typed failure. A revoked grant becomes NEEDS_REAUTH (terminal until the owner
// reconnects); a retryable provider failure (rate limit, 5xx) keeps the same job open at its last
// acknowledged checkpoint so the next tick resumes instead of losing the batch.
func (s *Service) failJob(ctx context.Context, connection store.GmailConnection,
	job store.GmailSyncJob, cause error) {
	now := s.Now()
	code := classifyError(cause)
	phase := "delta"
	if job.Kind == "BACKFILL" {
		phase = "backfill"
	}
	if code == "needs_reauth" {
		if err := s.Store.FinishGmailSyncJob(ctx, connection.OwnerID, job.ID, "NEEDS_REAUTH", code,
			now); err != nil {
			s.Log.Warn("gmail_sync_finish_failed")
		}
		// A terminal job can never drain a manual request; drop the marker so status does not
		// stay "connecting" forever. The reconnect CTA is driven by needs_reauth instead.
		if err := s.Store.ClearGmailSyncRequest(ctx, connection.OwnerID, now, now); err != nil {
			s.Log.Warn("gmail_sync_request_clear_failed")
		}
		s.recordFailure(ctx, connection, cause, phase)
		return
	}
	if err := s.Store.RequeueGmailSyncJob(ctx, connection.OwnerID, job.ID, code, now); err != nil {
		s.Log.Warn("gmail_sync_requeue_failed")
	}
	s.recordFailure(ctx, connection, cause, phase)
}

// candidatePlacement pairs a parsed candidate with the WIB month of its transaction date. The
// transaction date — never the email's arrival date — decides the accounting month, so an email
// that arrives after the month boundary still lands in the correct month.
type candidatePlacement struct {
	candidate store.ImportCandidate
	month     string
}

// importMonthPages lists and imports one WIB month, page by page, checkpointing after each
// acknowledged page. It is used by the rolling backfill and by the history-recovery scan.
//
// Gmail's date search filters by email arrival, which is only approximate: a notification for a
// transaction on 30 Nov can arrive on 1 Dec. Rows routed to another month inside the retention
// window are written into that month's own import job (dedupe makes the later canonical scan safe),
// while rows older than the window are recorded with an explicit outside_retention reason instead
// of being silently dropped.
func (s *Service) importMonthPages(ctx context.Context, connection store.GmailConnection,
	accessToken, month, startToken, prefix, queryOverride string,
	checkpoint func(pageProgress) error) (pageProgress, error) {
	now := s.Now()
	importJob, err := s.Store.CreateImportJob(ctx, connection.OwnerID, month, TemplateVersion, now)
	if err != nil {
		return pageProgress{}, err
	}
	// A resumed run starts at page ordinal zero with a different page token; folding the token into
	// the batch key keeps ImportBatch replay detection from comparing two different pages.
	prefix = prefix + ":" + shortTokenHash(startToken)
	months := s.backfillMonths(now)
	window := retention.NewWindow(now)
	retention := monthSet(months)
	extraJobs := map[string]string{}
	extraSeen := map[string]int{}
	progress := pageProgress{NextToken: startToken}
	query := queryOverride
	if query == "" {
		query = s.monthQuery(month)
	}
	for pages := 0; pages < s.Settings.MaxPagesPerRun; pages++ {
		list, err := s.Provider.ListMessages(ctx, accessToken, query, progress.NextToken,
			s.Settings.PageSize)
		if err != nil {
			s.finalizeMonthJob(ctx, connection.OwnerID, importJob.ID, progress, "PARTIAL", classifyError(err))
			return pageProgress{}, err
		}
		placements, err := s.buildCandidates(ctx, connection, accessToken, refIDs(list.Messages), month)
		if err != nil {
			s.finalizeMonthJob(ctx, connection.OwnerID, importJob.ID, progress, "PARTIAL", classifyError(err))
			return pageProgress{}, err
		}
		if len(placements) > 0 {
			groups, order := routePlacements(placements, month, retention, window)
			for _, target := range order {
				candidates := groups[target]
				jobID := importJob.ID
				batchKey := fmt.Sprintf("%s:p%d", prefix, pages)
				if target != month {
					jobID, err = s.extraImportJob(ctx, connection.OwnerID, target, extraJobs, now)
					if err != nil {
						s.finalizeMonthJob(ctx, connection.OwnerID, importJob.ID, progress, "PARTIAL", "import_failed")
						return pageProgress{}, err
					}
					batchKey = fmt.Sprintf("%s:%s:p%d", prefix, target, pages)
				}
				var counts store.ImportBatchCounts
				var importedIDs []string
				importErr := s.withDatabaseRetry(ctx, func() error {
					var inner error
					counts, importedIDs, _, inner = s.Store.ImportBatch(ctx, connection.OwnerID, jobID,
						batchKey, candidatesRequestHash(candidates), pages, candidates, now)
					return inner
				})
				if importErr != nil {
					s.finalizeMonthJob(ctx, connection.OwnerID, importJob.ID, progress, "FAILED", "import_failed")
					return pageProgress{}, err
				}
				progress.Seen += counts.Matched
				progress.Imported += counts.Imported
				progress.Duplicates += counts.Duplicates
				progress.Skipped += counts.Skipped
				if target != month {
					extraSeen[target] += counts.Matched
				}
				s.autoCategorize(ctx, connection.OwnerID, importedIDs)
			}
		}
		progress.NextToken = list.NextPageToken
		progress.PagesDone++
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
	for target, jobID := range extraJobs {
		state := "COMPLETE"
		if extraSeen[target] == 0 {
			state = "EMPTY"
		}
		s.finalizeMonthJob(ctx, connection.OwnerID, jobID, pageProgress{Seen: extraSeen[target]}, state, "")
	}
	return progress, nil
}

// monthSet is the retention window used to accept a late notification for an older transaction.
// Anything outside it gets an explicit rejection instead of a silent drop.
func monthSet(months []string) map[string]bool {
	set := map[string]bool{}
	for _, month := range months {
		set[month] = true
	}
	return set
}

// outsideRetention turns a parsed candidate into an auditable skip. Source identity is preserved so
// a later run that widens the window can still recognise the row.
func outsideRetention(candidate store.ImportCandidate) store.ImportCandidate {
	return store.ImportCandidate{
		Fingerprint:   candidate.Fingerprint,
		SourceRef:     candidate.SourceRef,
		Status:        "UNRESOLVED",
		Reason:        "outside_retention",
		ParserVersion: TemplateVersion,
	}
}

// routePlacements groups parsed candidates by their transaction month. The scanning month stays
// first so the normal path is deterministic; other in-window months are imported into their own
// job; rows outside the exact NFR-15 window stay in the scanning page as UNRESOLVED so the skip is
// auditable. The exact check matters for the partially retained oldest month, whose days before
// Window.Start must not be offered to ImportBatch (validator rejects the whole page).
func routePlacements(placements []candidatePlacement, scanningMonth string,
	retentionMonths map[string]bool, window retention.Window) (map[string][]store.ImportCandidate, []string) {
	groups := map[string][]store.ImportCandidate{}
	order := []string{}
	for _, placement := range placements {
		candidate := placement.candidate
		target := scanningMonth
		if candidate.Status == "PARSED" {
			if !window.Contains(candidate.EventAt) {
				candidate = outsideRetention(candidate)
			} else if placement.month != "" && placement.month != scanningMonth {
				if retentionMonths[placement.month] {
					target = placement.month
				} else {
					candidate = outsideRetention(candidate)
				}
			}
		}
		groups[target] = append(groups[target], candidate)
	}
	// Scanning month first, then the routed months in ascending order for a stable provider plan.
	order = append(order, scanningMonth)
	sorted := make([]string, 0, len(groups))
	for target := range groups {
		if target != scanningMonth {
			sorted = append(sorted, target)
		}
	}
	sort.Strings(sorted)
	order = append(order, sorted...)
	if _, ok := groups[scanningMonth]; !ok {
		order = order[1:]
	}
	return groups, order
}

// extraImportJob keeps one ad-hoc import job per routed month for the duration of a scan, so the
// backfill state of the scanning month stays independent from the late-arrival imports.
func (s *Service) extraImportJob(ctx context.Context, ownerID, month string,
	cache map[string]string, now time.Time) (string, error) {
	if id, ok := cache[month]; ok {
		return id, nil
	}
	job, err := s.Store.CreateImportJob(ctx, ownerID, month, TemplateVersion, now)
	if err != nil {
		return "", err
	}
	cache[month] = job.ID
	return job.ID, nil
}

// transientDatabaseConflict reports the write conflicts a remote libSQL database returns instead
// of waiting for a peer writer. Retrying the bounded unit of work is safe: ImportBatch dedupes by
// batch key and a finalize retry returns the already-finished job unchanged.
func transientDatabaseConflict(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	for _, marker := range []string{"database is locked", "database table is locked", "database is busy", "sqlite_busy"} {
		if strings.Contains(msg, marker) {
			return true
		}
	}
	return false
}

func (s *Service) withDatabaseRetry(ctx context.Context, work func() error) error {
	const attempts = 4
	var err error
	for attempt := 0; attempt < attempts; attempt++ {
		if err = work(); err == nil || !transientDatabaseConflict(err) {
			return err
		}
		if attempt == attempts-1 {
			break
		}
		// The other writer's window is short; back off instead of hammering the shared database.
		time.Sleep(time.Duration(120*(attempt+1)) * time.Millisecond)
	}
	return err
}

func (s *Service) finalizeMonthJob(ctx context.Context, ownerID, jobID string,
	progress pageProgress, state, errorCode string) {
	finalize := func() error {
		_, err := s.Store.FinalizeImportJob(ctx, ownerID, jobID, state, errorCode, s.Now())
		return err
	}
	if err := s.withDatabaseRetry(ctx, finalize); err != nil {
		// The state alone is not actionable when a hosted import cannot finalize; keep the error
		// text (bounded) so operators can tell a count mismatch from a database/transport failure.
		msg := err.Error()
		if len(msg) > 240 {
			msg = msg[:240]
		}
		s.Log.Warn("gmail_import_finalize_failed", "state", state, "error", msg)
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
			var counts store.ImportBatchCounts
			var importedIDs []string
			importErr := s.withDatabaseRetry(ctx, func() error {
				var inner error
				counts, importedIDs, _, inner = s.Store.ImportBatch(ctx, connection.OwnerID,
					importJob.ID, fmt.Sprintf("delta:%s:%d", importJob.ID, start/100),
					candidatesRequestHash(chunk), start/100, chunk, now)
				return inner
			})
			if importErr != nil {
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
	accessToken string, messageIDs []string, month string) ([]candidatePlacement, error) {
	placements := make([]candidatePlacement, 0, len(messageIDs))
	for _, messageID := range messageIDs {
		candidate, messageMonth, err := s.buildCandidate(ctx, connection, accessToken, messageID)
		if err != nil {
			return nil, err
		}
		if candidate.Status == "PARSED" && messageMonth != month {
			// The Gmail date filter follows email arrival; the parser's transaction date is the
			// accounting truth. Routing (not dropping) happens in importMonthPages.
			placements = append(placements, candidatePlacement{candidate: candidate, month: messageMonth})
			continue
		}
		placements = append(placements, candidatePlacement{candidate: candidate, month: month})
	}
	return placements, nil
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
func shortTokenHash(token string) string {
	if token == "" {
		return "start"
	}
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:4])
}

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
