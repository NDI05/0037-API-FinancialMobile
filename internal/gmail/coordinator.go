package gmail

import (
	"context"
	"log/slog"
	"time"
)

// Coordinator is the single in-process driver: one timer per process calls RunOnce, which advances
// each active connection by a bounded number of pages. "Sinkronkan sekarang" and the retry button
// use the same RunOnce path, so a manual sync cannot bypass the per-owner ordering.
type Coordinator struct {
	Service  *Service
	Interval time.Duration
	Log      *slog.Logger

	cancel context.CancelFunc
	done   chan struct{}
}

// Start launches the loop. A zero interval falls back to one minute.
func (c *Coordinator) Start() {
	if c.Service == nil || c.done != nil {
		return
	}
	if c.Interval <= 0 {
		c.Interval = time.Minute
	}
	if c.Log == nil {
		c.Log = slog.Default()
	}
	ctx, cancel := context.WithCancel(context.Background())
	c.cancel = cancel
	c.done = make(chan struct{})
	go func() {
		defer close(c.done)
		ticker := time.NewTicker(c.Interval)
		defer ticker.Stop()
		for {
			c.runOnce(ctx)
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
}

// Stop waits for the in-flight pass to finish. It is called before the HTTP server drains so the
// coordinator cannot start new provider calls during shutdown.
func (c *Coordinator) Stop() {
	if c.cancel == nil || c.done == nil {
		return
	}
	c.cancel()
	<-c.done
	c.cancel = nil
	c.done = nil
}

func (c *Coordinator) runOnce(ctx context.Context) {
	runCtx, cancel := context.WithTimeout(ctx, 4*time.Minute)
	defer cancel()
	report, err := c.Service.RunOnce(runCtx)
	if err != nil {
		c.Log.Warn("gmail_sync_pass_failed")
		return
	}
	if report.Connections == 0 && report.Events == 0 {
		return
	}
	// Counts only: mailbox addresses, message ids and tokens never reach a log line.
	c.Log.Info("gmail_sync_pass",
		"connections", report.Connections,
		"backfills", report.Backfills,
		"deltas", report.Deltas,
		"events", report.Events,
		"failures", report.Failures)
}
