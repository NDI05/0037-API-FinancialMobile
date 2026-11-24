package retention

import (
	"errors"
	"testing"
	"time"
)

func wib(year int, month time.Month, day, hour, minute int) time.Time {
	return time.Date(year, month, day, hour, minute, 0, 0, Jakarta())
}

func TestNewWindowRollingYear(t *testing.T) {
	cases := []struct {
		name string
		now  time.Time
		want time.Time
	}{
		{"same day and month", wib(2026, time.November, 24, 13, 26), wib(2025, time.November, 24, 0, 0)},
		{"first minute of the day", wib(2026, time.November, 24, 0, 0), wib(2025, time.November, 24, 0, 0)},
		{"last minute of the day", wib(2026, time.November, 24, 23, 59), wib(2025, time.November, 24, 0, 0)},
		{"month boundary", wib(2026, time.December, 1, 0, 0), wib(2025, time.December, 1, 0, 0)},
		{"year boundary", wib(2027, time.January, 1, 0, 0), wib(2026, time.January, 1, 0, 0)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			window := NewWindow(tc.now)
			if !window.Start.Equal(tc.want) {
				t.Fatalf("start = %s, want %s", window.Start, tc.want)
			}
			if !window.End.Equal(tc.now) {
				t.Fatalf("end = %s, want %s", window.End, tc.now)
			}
			if window.Start.Location().String() != "Asia/Jakarta" {
				t.Fatalf("start location = %s, want Asia/Jakarta", window.Start.Location())
			}
			if window.Start.Hour() != 0 || window.Start.Minute() != 0 || window.Start.Second() != 0 {
				t.Fatalf("start is not WIB midnight: %s", window.Start)
			}
		})
	}
}

func TestNewWindowLeapDay(t *testing.T) {
	// A leap year read on 29 February must clamp the one-year-earlier start to 28 February: a
	// calendar subtraction that normalizes forward would lose a day of retained data.
	cases := []struct {
		name string
		now  time.Time
		want time.Time
	}{
		{"leap day 2024", wib(2024, time.February, 29, 12, 0), wib(2023, time.February, 28, 0, 0)},
		{"leap day 2028", wib(2028, time.February, 29, 12, 0), wib(2027, time.February, 28, 0, 0)},
		{"leap day 2004", wib(2004, time.February, 29, 0, 0), wib(2003, time.February, 28, 0, 0)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			window := NewWindow(tc.now)
			if !window.Start.Equal(tc.want) {
				t.Fatalf("start = %s, want %s", window.Start, tc.want)
			}
		})
	}
}

func TestNewWindowNonLeapFebruaryAndMarch(t *testing.T) {
	if got := NewWindow(wib(2025, time.February, 28, 9, 0)).Start; !got.Equal(wib(2024, time.February, 28, 0, 0)) {
		t.Fatalf("28 Feb 2025 start = %s", got)
	}
	if got := NewWindow(wib(2025, time.March, 1, 9, 0)).Start; !got.Equal(wib(2024, time.March, 1, 0, 0)) {
		t.Fatalf("1 Mar 2025 start = %s", got)
	}
}

func TestWindowEventBoundaries(t *testing.T) {
	now := wib(2026, time.November, 24, 13, 26)
	window := NewWindow(now)

	in := []time.Time{
		window.Start,
		window.Start.Add(time.Millisecond),
		now,
		window.Start.In(time.UTC),
	}
	for _, t0 := range in {
		if err := window.ValidateEventAt(t0); err != nil {
			t.Fatalf("%s should be inside the window: %v", t0, err)
		}
	}
	out := []time.Time{
		window.Start.Add(-time.Millisecond),
		window.Start.Add(-time.Hour),
		now.Add(time.Nanosecond),
		now.Add(48 * time.Hour),
	}
	for _, t0 := range out {
		err := window.ValidateEventAt(t0)
		if err == nil {
			t.Fatalf("%s should be outside the window", t0)
		}
		if !errors.Is(err, ErrOutsideRetention) {
			t.Fatalf("%s error = %v, want ErrOutsideRetention", t0, err)
		}
	}
}

func TestWindowMonthBoundaries(t *testing.T) {
	now := wib(2026, time.November, 24, 13, 26) // start 2025-11-24
	window := NewWindow(now)

	month := func(year int, m time.Month) (time.Time, time.Time) {
		start := time.Date(year, m, 1, 0, 0, 0, 0, Jakarta())
		return start, start.AddDate(0, 1, 0)
	}

	// The boundary month is partially retained and must be accepted.
	for _, m := range []struct {
		year  int
		month time.Month
	}{
		{2025, time.November},
		{2025, time.December},
		{2026, time.January},
		{2026, time.November},
	} {
		start, end := month(m.year, m.month)
		if err := window.ValidateMonth(start, end); err != nil {
			t.Fatalf("%04d-%02d should be inside the window: %v", m.year, m.month, err)
		}
	}

	// A fully expired month and a future month are rejected.
	for _, m := range []struct {
		year  int
		month time.Month
	}{
		{2025, time.October},
		{2024, time.November},
		{2026, time.December},
		{2027, time.January},
	} {
		start, end := month(m.year, m.month)
		err := window.ValidateMonth(start, end)
		if !errors.Is(err, ErrOutsideRetention) {
			t.Fatalf("%04d-%02d error = %v, want ErrOutsideRetention", m.year, m.month, err)
		}
	}
}

func TestWindowMonthBoundaryAtExactMidnight(t *testing.T) {
	// At exactly 1 December 00:00 WIB, December is the current month and must be allowed, while
	// November is fully expired (its end equals the window start).
	now := wib(2026, time.December, 1, 0, 0)
	window := NewWindow(now)
	decemberStart, decemberEnd := time.Date(2026, time.December, 1, 0, 0, 0, 0, Jakarta()),
		time.Date(2027, time.January, 1, 0, 0, 0, 0, Jakarta())
	if err := window.ValidateMonth(decemberStart, decemberEnd); err != nil {
		t.Fatalf("current month rejected at midnight: %v", err)
	}
	novemberStart, novemberEnd := time.Date(2025, time.November, 1, 0, 0, 0, 0, Jakarta()),
		time.Date(2025, time.December, 1, 0, 0, 0, 0, Jakarta())
	if err := window.ValidateMonth(novemberStart, novemberEnd); !errors.Is(err, ErrOutsideRetention) {
		t.Fatalf("expired month accepted: %v", err)
	}
}

func TestClampMonthStart(t *testing.T) {
	now := wib(2026, time.November, 24, 13, 26)
	window := NewWindow(now)
	boundary := time.Date(2025, time.November, 1, 0, 0, 0, 0, Jakarta())
	if got := window.ClampMonthStart(boundary); !got.Equal(window.Start) {
		t.Fatalf("boundary clamp = %s, want %s", got, window.Start)
	}
	inside := time.Date(2026, time.October, 1, 0, 0, 0, 0, Jakarta())
	if got := window.ClampMonthStart(inside); !got.Equal(inside) {
		t.Fatalf("inside clamp = %s, want unchanged %s", got, inside)
	}
}

func TestWindowIDsAndMillis(t *testing.T) {
	now := wib(2026, time.November, 24, 13, 26)
	window := NewWindow(now)
	if got := window.StartMonthID(); got != "2025-11" {
		t.Fatalf("StartMonthID = %s", got)
	}
	if got := window.EndMonthID(); got != "2026-11" {
		t.Fatalf("EndMonthID = %s", got)
	}
	if got := window.ExpiredBeforeMonthID(); got != "2025-11" {
		t.Fatalf("ExpiredBeforeMonthID = %s", got)
	}
	if window.StartMillis() != window.Start.UnixMilli() {
		t.Fatalf("StartMillis mismatch")
	}
	if !window.Start.In(Jakarta()).Equal(window.Start) {
		t.Fatalf("policy start must already be in Asia/Jakarta")
	}
}
