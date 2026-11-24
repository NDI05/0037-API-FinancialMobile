// Package retention defines PAM's one-year rolling retention policy for financial data.
//
// The policy is intentionally a single helper for every caller (HTTP guards, store reads and the
// scheduled cleanup) so the boundary cannot drift between list, summary, analysis and import:
//
//   - Start is 00:00 Asia/Jakarta on the same calendar date one year before "now". A date without
//     the year (29 February) is clamped to the last day of the previous year's month, so the start
//     never jumps forward into the retained period.
//   - End is the instant the data is read ("now"), i.e. the window always means "the last year as
//     of this read" rather than a fixed interval captured once at boot.
//
// Because PAM stores month IDs and derives them in WIB, the boundary month is partially retained:
// it is inside the policy and its rows before Start are simply outside the window. Callers that
// aggregate a month must clamp the query start to Window.Start instead of rejecting the month.
package retention

import (
	"errors"
	"fmt"
	"time"
)

// ErrOutsideRetention marks a request whose period is outside the one-year rolling window. HTTP
// callers map it to a 4xx response; it must never surface as a 500.
var ErrOutsideRetention = errors.New("period is outside the one-year retention window")

// MonthLayout is the YYYY-MM month ID layout shared with store.ParseMonth.
const MonthLayout = "2006-01"

var jakarta = loadJakarta()

func loadJakarta() *time.Location {
	loc, err := time.LoadLocation("Asia/Jakarta")
	if err != nil {
		// WIB has no DST, so the fixed offset is exact when the platform ships no tzdata.
		return time.FixedZone("Asia/Jakarta", 7*60*60)
	}
	return loc
}

// Jakarta returns the Asia/Jakarta location used by the policy.
func Jakarta() *time.Location { return jakarta }

// Window is the half-open retention period for one read: [Start, End].
type Window struct {
	// Start is the inclusive lower bound: WIB midnight one calendar year before the read time.
	Start time.Time
	// End is the inclusive upper bound and is exactly the read time.
	End time.Time
}

// NewWindow derives the rolling window for a read that happens at now.
func NewWindow(now time.Time) Window {
	local := now.In(jakarta)
	startYear := local.Year() - 1
	startMonth := local.Month()
	startDay := local.Day()
	if last := daysIn(startYear, startMonth); startDay > last {
		// 29 February: one calendar year earlier is 28 February (the clamp keeps the start inside
		// the retained period instead of normalizing forward to 1 March).
		startDay = last
	}
	start := time.Date(startYear, startMonth, startDay, 0, 0, 0, 0, jakarta)
	return Window{Start: start, End: now}
}

func daysIn(year int, month time.Month) int {
	// Day 0 of the next month is the last day of this month.
	return time.Date(year, month+1, 0, 0, 0, 0, 0, jakarta).Day()
}

// Contains reports whether an instant is inside the policy: Start <= t <= End.
func (w Window) Contains(t time.Time) bool {
	return !t.Before(w.Start) && !t.After(w.End)
}

// ValidateEventAt rejects a transaction timestamp outside the window. The exact Start instant is
// retained (in), one nanosecond earlier is out.
func (w Window) ValidateEventAt(t time.Time) error {
	if w.Contains(t) {
		return nil
	}
	return fmt.Errorf("%w: eventAt is before %s or after %s",
		ErrOutsideRetention, w.Start.In(jakarta).Format(time.RFC3339), w.End.Format(time.RFC3339))
}

// ValidateMonth rejects a month that is entirely outside the window. A month partially inside the
// window (the boundary month, or the current month) is accepted; callers clamp aggregation to
// Window.Start. Months after the read time (future) are outside the policy.
func (w Window) ValidateMonth(monthStart, monthEnd time.Time) error {
	// A month that starts after the read time is entirely in the future.
	if monthStart.After(w.End) {
		return fmt.Errorf("%w: month starts after the retention window end", ErrOutsideRetention)
	}
	// A month that ends at or before the window start is already fully expired.
	if !monthEnd.After(w.Start) {
		return fmt.Errorf("%w: month ends before the retention window start", ErrOutsideRetention)
	}
	return nil
}

// ClampMonthStart raises a month start to the window start when the month is only partially
// retained. It returns monthStart unchanged for months fully inside the window.
func (w Window) ClampMonthStart(monthStart time.Time) time.Time {
	if monthStart.Before(w.Start) {
		return w.Start
	}
	return monthStart
}

// StartMonthID is the WIB YYYY-MM of the window start. The month it names is partially retained.
func (w Window) StartMonthID() string { return w.Start.In(jakarta).Format(MonthLayout) }

// EndMonthID is the WIB YYYY-MM of the read time (the current month).
func (w Window) EndMonthID() string { return w.End.In(jakarta).Format(MonthLayout) }

// ExpiredBeforeMonthID returns the YYYY-MM boundary for month-keyed derivative tables: every
// month_id strictly smaller than this value is fully outside the window and may be purged. The
// boundary month itself is kept because part of it is retained.
func (w Window) ExpiredBeforeMonthID() string { return w.StartMonthID() }

// Expired reports whether an instant is before the window start, i.e. outside the policy on the
// old side. Data exactly at Start is retained.
func (w Window) Expired(t time.Time) bool { return t.Before(w.Start) }

// ValidateNotExpired rejects expired financial data while leaving the upper bound to the
// period-selection checks. Manual entry and direct resource reads use this lower-bound guard so
// existing future-dated behaviour does not change; month/period endpoints use ValidateMonth, which
// also rejects future periods.
func (w Window) ValidateNotExpired(t time.Time) error {
	if w.Expired(t) {
		return fmt.Errorf("%w: data is older than %s",
			ErrOutsideRetention, w.Start.In(jakarta).Format(time.RFC3339))
	}
	return nil
}

// StartMillis is the epoch-millisecond lower bound used by event_at_ms queries.
func (w Window) StartMillis() int64 { return w.Start.UnixMilli() }
