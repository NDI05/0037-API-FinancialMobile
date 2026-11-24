package gmail

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"
)

// ownerContextKey carries the owner id to the rate-limited provider wrapper. Provider methods only
// receive a context, so this is how per-owner pacing is enforced without widening the interface.
type ownerContextKey struct{}

func withOwner(ctx context.Context, ownerID string) context.Context {
	return context.WithValue(ctx, ownerContextKey{}, ownerID)
}

func ownerFromContext(ctx context.Context) string {
	owner, _ := ctx.Value(ownerContextKey{}).(string)
	return owner
}

// tokenBucket is a small leaky/token bucket used for provider pacing. Both the per-owner and the
// per-project limit share this type; the limiter is process-local, which matches the single Gmail
// coordinator.
type tokenBucket struct {
	mu     sync.Mutex
	tokens float64
	last   time.Time
	rate   float64 // tokens per second
	burst  float64
}

func newTokenBucket(perMinute int, now time.Time) *tokenBucket {
	if perMinute <= 0 {
		perMinute = 60
	}
	rate := float64(perMinute) / 60
	return &tokenBucket{tokens: float64(perMinute), last: now, rate: rate,
		burst: float64(perMinute)}
}

// wait returns how long the caller has to wait before one token is available. It does not consume
// the token: acquire calls wait and then consumes under the same lock to keep it exact.
func (b *tokenBucket) wait(now time.Time) time.Duration {
	b.mu.Lock()
	defer b.mu.Unlock()
	if now.After(b.last) {
		b.tokens += now.Sub(b.last).Seconds() * b.rate
		if b.tokens > b.burst {
			b.tokens = b.burst
		}
		b.last = now
	}
	if b.tokens >= 1 {
		return 0
	}
	return time.Duration((1 - b.tokens) / b.rate * float64(time.Second))
}

func (b *tokenBucket) take(now time.Time) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if now.After(b.last) {
		b.tokens += now.Sub(b.last).Seconds() * b.rate
		if b.tokens > b.burst {
			b.tokens = b.burst
		}
		b.last = now
	}
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// rateLimiter paces Gmail calls per owner and per project. Gmail quotas are per project, while a
// single owner must not monopolise them, so the wrapper reserves from both buckets.
type rateLimiter struct {
	now       func() time.Time
	ownerRate int
	mu        sync.Mutex
	owners    map[string]*tokenBucket
	project   *tokenBucket
	sleep     func(ctx context.Context, d time.Duration) error
}

func newRateLimiter(ownerPerMinute, projectPerMinute int, now func() time.Time) *rateLimiter {
	if now == nil {
		now = time.Now
	}
	if ownerPerMinute <= 0 {
		ownerPerMinute = 60
	}
	return &rateLimiter{now: now, ownerRate: ownerPerMinute, owners: map[string]*tokenBucket{},
		project: newTokenBucket(projectPerMinute, now()), sleep: sleepContext}
}

// acquire blocks until both the owner and project buckets allow one more call. A cancelled
// context aborts immediately instead of queueing work behind a dead request.
func (l *rateLimiter) acquire(ctx context.Context, ownerID string) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		now := l.now()
		l.mu.Lock()
		owner := l.owners[ownerID]
		if owner == nil {
			owner = newTokenBucket(l.ownerRate, now)
			l.owners[ownerID] = owner
		}
		l.mu.Unlock()
		wait := owner.wait(now)
		if projectWait := l.project.wait(now); projectWait > wait {
			wait = projectWait
		}
		if wait <= 0 && owner.take(now) && l.project.take(now) {
			return nil
		}
		if wait <= 0 {
			wait = time.Millisecond
		}
		if err := l.sleep(ctx, wait); err != nil {
			return err
		}
	}
}

// sleepContext is a context-aware sleep used by both pacing and retry backoff.
func sleepContext(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// limitedProvider wraps a Provider with project/owner pacing and bounded exponential retries. It
// retries only retryable failures (429/403 rate limit, 5xx); an invalid_grant or a history 404 is
// returned immediately so the coordinator can take its own recovery path.
type limitedProvider struct {
	inner    Provider
	limiter  *rateLimiter
	attempts int
	backoff  time.Duration
	log      *slog.Logger
	sleep    func(context.Context, time.Duration) error
}

func newLimitedProvider(inner Provider, settings Settings, now func() time.Time,
	logger *slog.Logger) Provider {
	if inner == nil {
		return nil
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &limitedProvider{inner: inner,
		limiter:  newRateLimiter(settings.OwnerRatePerMinute, settings.ProjectRatePerMinute, now),
		attempts: settings.RetryAttempts, backoff: settings.RetryBackoff, log: logger,
		sleep: sleepContext}
}

func (p *limitedProvider) call(ctx context.Context, fn func() error) error {
	var err error
	for attempt := 0; attempt <= p.attempts; attempt++ {
		if owner := ownerFromContext(ctx); owner != "" {
			if paceErr := p.limiter.acquire(ctx, owner); paceErr != nil {
				return paceErr
			}
		}
		if err = fn(); err == nil {
			return nil
		}
		if !isRetryableProviderError(err) || attempt == p.attempts {
			return err
		}
		// Exponential backoff: 500 ms, 1 s, 2 s by default. The delay is bounded so a worker tick
		// cannot stall on a long upstream outage.
		delay := p.backoff << attempt
		if delay > 8*time.Second {
			delay = 8 * time.Second
		}
		if p.log != nil {
			p.log.Info("gmail_provider_retry", "attempt", attempt+1, "code", classifyError(err))
		}
		if sleepErr := p.sleep(ctx, delay); sleepErr != nil {
			return sleepErr
		}
	}
	return err
}

// isRetryableProviderError reports transient Gmail failures that are safe to retry.
func isRetryableProviderError(err error) bool {
	if err == nil || errors.Is(err, ErrUnauthorized) {
		return false
	}
	if IsRateLimited(err) {
		return true
	}
	var apiErr *APIError
	if AsAPIError(err, &apiErr) {
		return apiErr.Code == "provider_unavailable"
	}
	return false
}

// IsRateLimited reports a Gmail 403 rate-limit reason or 429, which must be retried with backoff
// instead of being mistaken for a revoked grant (invalid_grant).
func IsRateLimited(err error) bool {
	var apiErr *APIError
	if AsAPIError(err, &apiErr) {
		return apiErr.Code == "rate_limited"
	}
	return false
}

func (p *limitedProvider) ListMessages(ctx context.Context, accessToken, query, pageToken string,
	max int) (MessageList, error) {
	var out MessageList
	err := p.call(ctx, func() error {
		var callErr error
		out, callErr = p.inner.ListMessages(ctx, accessToken, query, pageToken, max)
		return callErr
	})
	return out, err
}

func (p *limitedProvider) GetMessage(ctx context.Context, accessToken, id string) (RawMessage, error) {
	var out RawMessage
	err := p.call(ctx, func() error {
		var callErr error
		out, callErr = p.inner.GetMessage(ctx, accessToken, id)
		return callErr
	})
	return out, err
}

func (p *limitedProvider) Watch(ctx context.Context, accessToken, topic string) (WatchState, error) {
	var out WatchState
	err := p.call(ctx, func() error {
		var callErr error
		out, callErr = p.inner.Watch(ctx, accessToken, topic)
		return callErr
	})
	return out, err
}

func (p *limitedProvider) StopWatch(ctx context.Context, accessToken string) error {
	return p.call(ctx, func() error { return p.inner.StopWatch(ctx, accessToken) })
}

func (p *limitedProvider) Profile(ctx context.Context, accessToken string) (Profile, error) {
	var out Profile
	err := p.call(ctx, func() error {
		var callErr error
		out, callErr = p.inner.Profile(ctx, accessToken)
		return callErr
	})
	return out, err
}

func (p *limitedProvider) History(ctx context.Context, accessToken, startHistoryID, pageToken string,
	max int) (HistoryPage, error) {
	var out HistoryPage
	err := p.call(ctx, func() error {
		var callErr error
		out, callErr = p.inner.History(ctx, accessToken, startHistoryID, pageToken, max)
		return callErr
	})
	return out, err
}
