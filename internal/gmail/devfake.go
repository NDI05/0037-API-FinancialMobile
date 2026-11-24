package gmail

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Dev-only fake Gmail provider.
//
// This file exists so physical-phone UAT can exercise the polling flow without an owner Google
// account. It is NEVER compiled into a production behaviour: the config loader only builds it when
// APP_ENV=development, GMAIL_ALLOW_LOOPBACK_REDIRECT=true and GMAIL_PROVIDER=fake. It serves
// synthetic Livin notifications from a JSON fixture outside the repository and counts the provider
// calls the contract asserts on (watch/stop must stay at zero in polling).

// DevFixture is the JSON schema of GMAIL_DEV_FIXTURE_FILE:
//
//	{"profile":{"emailAddress":"...","historyId":"1000"},
//	 "messages":[{"id":"...","eventAt":"RFC3339","amountMinor":100000,
//	              "direction":"DEBIT","merchantLabel":"...","rawBase64":"optional"}],
//	 "messagesByMonth":{"2026-11":{"pages":[["id1","id2"],["id3"]]}},
//	 "historyPages":[{"messageIds":["id"],"nextPageToken":"","latestHistoryId":"1010"}]}
type DevFixture struct {
	Profile struct {
		EmailAddress string `json:"emailAddress"`
		HistoryID    string `json:"historyId"`
	} `json:"profile"`
	Messages []DevFixtureMessage `json:"messages"`
	// MessagesByMonth drives messages.list pagination. Each inner page is one messages.list page.
	MessagesByMonth map[string]struct {
		Pages [][]string `json:"pages"`
	} `json:"messagesByMonth"`
	HistoryPages []struct {
		MessageIDs      []string `json:"messageIds"`
		NextPageToken   string   `json:"nextPageToken"`
		LatestHistoryID string   `json:"latestHistoryId"`
	} `json:"historyPages"`
}

// DevFixtureMessage is one synthetic notification. One fixture message maps to one transaction.
type DevFixtureMessage struct {
	ID            string `json:"id"`
	EventAt       string `json:"eventAt"`
	AmountMinor   int64  `json:"amountMinor"`
	Direction     string `json:"direction"`
	MerchantLabel string `json:"merchantLabel"`
	// RawBase64 optionally supplies a complete RFC 822 message; otherwise a deterministic Livin
	// notification body is synthesised from the fields above.
	RawBase64 string `json:"rawBase64"`
}

// DevProviderCounters is the JSON body of GET /v1/gmail/dev/stats. Only counters: no ids, emails
// or tokens.
type DevProviderCounters struct {
	WatchCalls    int `json:"watchCalls"`
	StopCalls     int `json:"stopCalls"`
	ListCalls     int `json:"listCalls"`
	GetCalls      int `json:"getCalls"`
	HistoryCalls  int `json:"historyCalls"`
	RefreshCalls  int `json:"refreshCalls"`
	CategoryCalls int `json:"categoryCalls"`
	Exchanges     int `json:"exchanges"`
}

// DevFakeProvider serves one fixture. It is safe for concurrent use (the worker and HTTP stats
// endpoint can touch it together).
type DevFakeProvider struct {
	mu       sync.Mutex
	fixture  DevFixture
	scenario string
	// RateLimitFailures is how many provider calls fail with rate_limited before recovering. The
	// rate_limit scenario uses a small number so the bounded retry wrapper can prove recovery.
	rateLimitBudget int
	historyExpired  bool

	counters DevProviderCounters
}

// DevScenario names accepted by GMAIL_DEV_SCENARIO.
const (
	DevScenarioNormal         = "normal"
	DevScenarioHistoryExpired = "history_expired"
	DevScenarioRateLimit      = "rate_limit"
)

// LoadDevFixture reads the fixture file and builds the fake provider for a scenario. The file must
// live outside the repository (the caller enforces that when validating config).
func LoadDevFixture(path, scenario string) (*DevFakeProvider, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("gmail dev fixture: %w", err)
	}
	fixture := DevFixture{}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		return nil, fmt.Errorf("gmail dev fixture: invalid json")
	}
	if fixture.Profile.EmailAddress == "" {
		return nil, fmt.Errorf("gmail dev fixture: profile.emailAddress is required")
	}
	if fixture.Profile.HistoryID == "" {
		return nil, fmt.Errorf("gmail dev fixture: profile.historyId is required")
	}
	provider := &DevFakeProvider{fixture: fixture, scenario: scenario}
	if scenario == DevScenarioRateLimit {
		provider.rateLimitBudget = 1
	}
	return provider, nil
}

// DevScenarioValid reports whether the configured development scenario is known.
func DevScenarioValid(scenario string) bool {
	switch scenario {
	case DevScenarioNormal, DevScenarioHistoryExpired, DevScenarioRateLimit:
		return true
	}
	return false
}

func (p *DevFakeProvider) messageByID(id string) (DevFixtureMessage, bool) {
	for _, message := range p.fixture.Messages {
		if message.ID == id {
			return message, true
		}
	}
	return DevFixtureMessage{}, false
}

func (p *DevFakeProvider) rateLimited() error {
	if p.rateLimitBudget > 0 {
		p.rateLimitBudget--
		return &APIError{Status: 429, Code: "rate_limited"}
	}
	return nil
}

var (
	devDateQuery = regexp.MustCompile(`after:(\d{4})/(\d{2})/(\d{2})`)
	devUnixQuery = regexp.MustCompile(`after:(\d{9,})`)
)

func (p *DevFakeProvider) ListMessages(ctx context.Context, accessToken, query, pageToken string,
	max int) (MessageList, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.counters.ListCalls++
	if err := p.rateLimited(); err != nil {
		return MessageList{}, err
	}
	ids := []string{}
	if match := devDateQuery.FindStringSubmatch(query); match != nil {
		month := match[1] + "-" + match[2]
		bucket, ok := p.fixture.MessagesByMonth[month]
		if !ok {
			return MessageList{}, nil
		}
		index, _ := strconv.Atoi(pageToken)
		if index < 0 || index >= len(bucket.Pages) {
			return MessageList{}, nil
		}
		ids = append(ids, bucket.Pages[index]...)
		next := ""
		if index+1 < len(bucket.Pages) {
			next = strconv.Itoa(index + 1)
		}
		return devPage(ids, next, max), nil
	}
	// Recovery scans use absolute unix bounds (after:<unix> before:<unix>); filter by eventAt.
	var from, to int64
	if match := devUnixQuery.FindStringSubmatch(query); match != nil {
		from, _ = strconv.ParseInt(match[1], 10, 64)
	}
	if match := regexp.MustCompile(`before:(\d{9,})`).FindStringSubmatch(query); match != nil {
		to, _ = strconv.ParseInt(match[1], 10, 64)
	}
	for _, message := range p.fixture.Messages {
		at, err := time.Parse(time.RFC3339, message.EventAt)
		if err != nil {
			continue
		}
		unix := at.Unix()
		if from > 0 && unix < from {
			continue
		}
		if to > 0 && unix > to {
			continue
		}
		ids = append(ids, message.ID)
	}
	sort.Strings(ids)
	index, _ := strconv.Atoi(pageToken)
	pageSize := 100
	if max > 0 && max < pageSize {
		pageSize = max
	}
	start := index * pageSize
	if start >= len(ids) {
		return MessageList{}, nil
	}
	end := start + pageSize
	if end > len(ids) {
		end = len(ids)
	}
	next := ""
	if end < len(ids) {
		next = strconv.Itoa(index + 1)
	}
	return devPage(ids[start:end], next, max), nil
}

func devPage(ids []string, next string, max int) MessageList {
	if max > 0 && len(ids) > max {
		ids = ids[:max]
	}
	refs := make([]MessageRef, 0, len(ids))
	for _, id := range ids {
		refs = append(refs, MessageRef{ID: id})
	}
	return MessageList{Messages: refs, NextPageToken: next}
}

func (p *DevFakeProvider) GetMessage(ctx context.Context, accessToken, id string) (RawMessage, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.counters.GetCalls++
	if err := p.rateLimited(); err != nil {
		return RawMessage{}, err
	}
	message, ok := p.messageByID(id)
	if !ok {
		return RawMessage{}, &APIError{Status: 404, Code: "not_found"}
	}
	if message.RawBase64 != "" {
		decoded, err := base64.StdEncoding.DecodeString(message.RawBase64)
		if err != nil {
			return RawMessage{}, &APIError{Status: 500, Code: "provider_error"}
		}
		return RawMessage{ID: id, Raw: decoded}, nil
	}
	return RawMessage{ID: id, Raw: devSyntheticEmail(message)}, nil
}

// devSyntheticEmail renders a deterministic Livin-style notification. The parser (not the fake)
// decides the transaction fields from this body, so a fixture cannot bypass parsing.
func devSyntheticEmail(message DevFixtureMessage) []byte {
	at, err := time.Parse(time.RFC3339, message.EventAt)
	if err != nil {
		at = time.Now()
	}
	local := at.In(jakarta)
	merchant := message.MerchantLabel
	if merchant == "" {
		merchant = "QA MERCHANT"
	}
	reference := "DEV" + strings.ReplaceAll(strings.ReplaceAll(message.ID, "-", ""), "_", "")
	body := "Pembayaran Berhasil\r\n" +
		"Penerima: " + merchant + "\r\n" +
		"Jumlah: Rp " + devThousands(message.AmountMinor) + "\r\n" +
		"Tanggal: " + local.Format("02 Jan 2006 15:04:05") + "\r\n" +
		"No. Referensi: " + reference + "\r\n"
	return []byte("From: Livin <no-reply@livin.co.id>\r\n" +
		"To: pilot@pam.test\r\n" +
		"Subject: Pembayaran Berhasil!\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: text/plain; charset=utf-8\r\n" +
		"Content-Transfer-Encoding: quoted-printable\r\n" +
		"\r\n" + body)
}

// devThousands renders minor units as the Indonesian "Rp 25.000" grouping the parser accepts.
func devThousands(amountMinor int64) string {
	digits := strconv.FormatInt(amountMinor, 10)
	parts := []string{}
	for len(digits) > 3 {
		parts = append([]string{digits[len(digits)-3:]}, parts...)
		digits = digits[:len(digits)-3]
	}
	parts = append([]string{digits}, parts...)
	return strings.Join(parts, ".")
}

func (p *DevFakeProvider) Watch(ctx context.Context, accessToken, topic string) (WatchState, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.counters.WatchCalls++
	return WatchState{}, &APIError{Status: 500, Code: "provider_error"}
}

func (p *DevFakeProvider) StopWatch(ctx context.Context, accessToken string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.counters.StopCalls++
	return nil
}

func (p *DevFakeProvider) Profile(ctx context.Context, accessToken string) (Profile, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.rateLimited(); err != nil {
		return Profile{}, err
	}
	return Profile{EmailAddress: p.fixture.Profile.EmailAddress,
		HistoryID: p.fixture.Profile.HistoryID}, nil
}

func (p *DevFakeProvider) History(ctx context.Context, accessToken, startHistoryID, pageToken string,
	max int) (HistoryPage, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.counters.HistoryCalls++
	if p.scenario == DevScenarioHistoryExpired && !p.historyExpired {
		p.historyExpired = true
		return HistoryPage{}, &APIError{Status: 404, Code: "not_found", Expired: true}
	}
	if err := p.rateLimited(); err != nil {
		return HistoryPage{}, err
	}
	index, _ := strconv.Atoi(pageToken)
	if index < 0 || index >= len(p.fixture.HistoryPages) {
		return HistoryPage{LatestHistoryID: startHistoryID}, nil
	}
	page := p.fixture.HistoryPages[index]
	return HistoryPage{MessageIDs: page.MessageIDs, NextPageToken: page.NextPageToken,
		LatestHistoryID: page.LatestHistoryID}, nil
}

// Counters returns a copy of the call counters.
func (p *DevFakeProvider) Counters() DevProviderCounters {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.counters
}
