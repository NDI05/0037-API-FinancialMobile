package httpapi

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/pam/recap/backend-go/internal/retention"
	"github.com/pam/recap/backend-go/internal/store"
)

// retentionDeleteConfirmation is the literal operator confirmation required in addition to the
// internal token and RETENTION_DELETE_ENABLED. Two independent switches make an accidental curl
// against a real database fail closed instead of erasing data.
const retentionDeleteConfirmation = "RETENTION_DELETE"

func (s *Server) retentionWindow() retention.Window { return retention.NewWindow(s.Now()) }

func retentionWindowJSON(window retention.Window) map[string]any {
	return map[string]any{
		"windowStart":  window.Start,
		"windowEnd":    window.End,
		"startMonthId": window.StartMonthID(),
		"endMonthId":   window.EndMonthID(),
		"timezone":     "Asia/Jakarta",
		"months":       12,
	}
}

// writeOutsideRetention is the single safe 4xx for any period or transaction date outside the
// policy. It never falls through to a 500 and it tells the client the current window so a period
// picker can clamp itself instead of guessing.
func (s *Server) writeOutsideRetention(w http.ResponseWriter, r *http.Request) {
	window := s.retentionWindow()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"code":          "outside_retention",
		"message":       "The requested period is outside the one-year retention window",
		"retryable":     false,
		"correlationId": correlationOf(r),
		"retention":     retentionWindowJSON(window),
	})
}

// retainMonth validates a YYYY-MM period against the rolling window. It writes the 400 response
// and returns false when the period is fully expired or in the future.
func (s *Server) retainMonth(w http.ResponseWriter, r *http.Request, monthID string) bool {
	start, end, err := store.ParseMonth(monthID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "monthId must be YYYY-MM", correlationOf(r))
		return false
	}
	if err := s.retentionWindow().ValidateMonth(start, end); err != nil {
		s.writeOutsideRetention(w, r)
		return false
	}
	return true
}

// retainEventAt validates a transaction timestamp against the full window.
func (s *Server) retainEventAt(w http.ResponseWriter, r *http.Request, at time.Time) bool {
	if err := s.retentionWindow().ValidateEventAt(at); err != nil {
		s.writeOutsideRetention(w, r)
		return false
	}
	return true
}

// retainNotExpired rejects already-expired data on direct read/write paths. It deliberately keeps
// the legacy future-dated behaviour of manual entry; period endpoints use retainMonth, which also
// rejects future periods.
func (s *Server) retainNotExpired(w http.ResponseWriter, r *http.Request, at time.Time) bool {
	if err := s.retentionWindow().ValidateNotExpired(at); err != nil {
		s.writeOutsideRetention(w, r)
		return false
	}
	return true
}

// retentionInfo reports the current policy window so clients can clamp their period picker.
func (s *Server) retentionInfo(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, retentionWindowJSON(s.retentionWindow()))
}

// internalRetentionSweep runs one eligible check (CR-005). Report-only is the default; deletion
// needs the internal token, RETENTION_DELETE_ENABLED and ?confirm=RETENTION_DELETE. The response
// and logs contain aggregate counts only.
func (s *Server) internalRetentionSweep(w http.ResponseWriter, r *http.Request) {
	if s.Config.InternalSweepToken == "" {
		writeError(w, http.StatusNotFound, "not_found", "Not found", correlationOf(r))
		return
	}
	if !secureEqual(r.Header.Get("x-internal-token"), s.Config.InternalSweepToken) {
		writeError(w, http.StatusUnauthorized, "unauthorized", "Invalid internal token", correlationOf(r))
		return
	}
	query := r.URL.Query()
	mode := store.RetentionReportOnly
	switch query.Get("mode") {
	case "", "report", "report-only", "dry-run":
		// The default must never delete.
	case "delete":
		if !s.Config.Retention.DeleteEnabled {
			writeError(w, http.StatusForbidden, "retention_delete_disabled",
				"Retention deletion is disabled (RETENTION_DELETE_ENABLED)", correlationOf(r))
			return
		}
		if query.Get("confirm") != retentionDeleteConfirmation {
			writeError(w, http.StatusBadRequest, "confirmation_required",
				"mode=delete requires confirm="+retentionDeleteConfirmation, correlationOf(r))
			return
		}
		mode = store.RetentionDelete
	default:
		writeError(w, http.StatusBadRequest, "invalid_request",
			"mode must be report or delete", correlationOf(r))
		return
	}

	started := time.Now()
	result, err := s.Store.SweepRetention(r.Context(), s.Now(), mode)
	if err != nil {
		// The audit row is written in the same transaction as the deletes, so a failure leaves no
		// misleading "completed" evidence and no partial deletion.
		s.databaseOrInternal(w, r, err)
		return
	}
	s.Log.Info("retention_sweep", "mode", string(result.Mode), "eligible", result.Counts.Total(),
		"transactions", result.Counts.Transactions, "attachments", result.Counts.Attachments,
		"summaries", result.Counts.Summaries, "analyses", result.Counts.Analyses,
		"categoryJobs", result.Counts.CategoryJobs, "categoryCache", result.Counts.CategoryCache,
		"importJobs", result.Counts.ImportJobs, "importBatches", result.Counts.ImportBatches,
		"importSkipped", result.Counts.ImportSkipped, "windowStart", result.WindowStart,
		"windowEnd", result.WindowEnd, "ms", time.Since(started).Milliseconds())
	w.Header().Set("X-Retention-Mode", string(result.Mode))
	writeJSON(w, http.StatusOK, map[string]any{
		"id":              result.ID,
		"mode":            string(result.Mode),
		"deleted":         result.Mode.Deletes(),
		"windowStart":     result.WindowStart,
		"windowEnd":       result.WindowEnd,
		"counts":          result.Counts,
		"eligible":        result.Counts.Total(),
		"startedAt":       result.StartedAt,
		"completedAt":     result.CompletedAt,
		"retentionWindow": retentionWindowJSON(s.retentionWindow()),
	})
}
