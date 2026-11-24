package httpapi

import (
	"context"
	"time"

	"github.com/pam/recap/backend-go/internal/store"
)

// RetentionWorker runs the CR-005 eligible check on a schedule. It is off by default: main only
// starts it when RETENTION_SWEEP_ENABLED (or RETENTION_DELETE_ENABLED) is set. The worker is
// report-only unless deletion is independently enabled and the internal sweep token is configured.
//
// Every tick writes one retention_sweeps audit row (aggregate counts only) so operations can see
// the policy is alive without reading financial data.
type RetentionWorker struct {
	api      *Server
	interval time.Duration
	stop     chan struct{}
	done     chan struct{}
}

// NewRetentionWorker builds a worker from the loaded configuration.
func NewRetentionWorker(api *Server) *RetentionWorker {
	interval := api.Config.Retention.SweepInterval
	if interval <= 0 {
		interval = 24 * time.Hour
	}
	return &RetentionWorker{api: api, interval: interval, stop: make(chan struct{}),
		done: make(chan struct{})}
}

// Start launches the schedule and runs one check immediately so a freshly started deployment
// records its policy state without waiting a full interval.
func (w *RetentionWorker) Start() { go w.run() }

// Stop waits for the current sweep to finish; call it before the HTTP server drains.
func (w *RetentionWorker) Stop() {
	close(w.stop)
	<-w.done
}

func (w *RetentionWorker) run() {
	defer close(w.done)
	w.sweep()
	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()
	for {
		select {
		case <-w.stop:
			return
		case <-ticker.C:
			w.sweep()
		}
	}
}

func (w *RetentionWorker) sweep() {
	mode := store.RetentionReportOnly
	if w.api.Config.Retention.DeleteEnabled && w.api.Config.InternalSweepToken != "" {
		mode = store.RetentionDelete
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	started := time.Now()
	result, err := w.api.Store.SweepRetention(ctx, w.api.Now(), mode)
	if err != nil {
		// Counting/deleting never touches request bodies, so the error is schema/DB level only.
		w.api.Log.Warn("retention_sweep_failed", "mode", string(mode), "error", err.Error())
		return
	}
	w.api.Log.Info("retention_sweep", "mode", string(result.Mode), "eligible", result.Counts.Total(),
		"transactions", result.Counts.Transactions, "attachments", result.Counts.Attachments,
		"summaries", result.Counts.Summaries, "analyses", result.Counts.Analyses,
		"categoryJobs", result.Counts.CategoryJobs, "categoryCache", result.Counts.CategoryCache,
		"importJobs", result.Counts.ImportJobs, "importBatches", result.Counts.ImportBatches,
		"importSkipped", result.Counts.ImportSkipped, "windowStart", result.WindowStart,
		"windowEnd", result.WindowEnd, "ms", time.Since(started).Milliseconds())
}
