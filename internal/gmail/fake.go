package gmail

import (
	"context"
	"sync"
	"time"
)

// FakeProvider is a deterministic Provider for tests. Every method can be replaced by a hook;
// without a hook it serves the configured pages/messages.
type FakeProvider struct {
	mu sync.Mutex

	Pages        []MessageList
	ListCalls    int
	ListQueries  []string
	RawByID      map[string]RawMessage
	ProfileValue Profile
	HistoryPages []HistoryPage
	HistoryCalls int
	WatchState   WatchState
	WatchCalls   int
	StopCalls    int

	ListErr    error
	GetErr     error
	ProfileErr error
	WatchErr   error
	HistoryErr error
	StopErr    error

	OnList    func(ctx context.Context, query, pageToken string) (MessageList, error)
	OnProfile func(ctx context.Context) (Profile, error)
	OnGet     func(ctx context.Context, id string) (RawMessage, error)
	OnHistory func(ctx context.Context, start, pageToken string) (HistoryPage, error)
}

func (f *FakeProvider) ListMessages(ctx context.Context, accessToken, query, pageToken string,
	max int) (MessageList, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	index := f.ListCalls
	f.ListCalls++
	f.ListQueries = append(f.ListQueries, query)
	if f.OnList != nil {
		return f.OnList(ctx, query, pageToken)
	}
	if f.ListErr != nil {
		return MessageList{}, f.ListErr
	}
	if index >= len(f.Pages) {
		return MessageList{}, nil
	}
	return f.Pages[index], nil
}

func (f *FakeProvider) GetMessage(ctx context.Context, accessToken, id string) (RawMessage, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.OnGet != nil {
		return f.OnGet(ctx, id)
	}
	if f.GetErr != nil {
		return RawMessage{}, f.GetErr
	}
	message, ok := f.RawByID[id]
	if !ok {
		return RawMessage{}, &APIError{Status: 404, Code: "not_found", Expired: true}
	}
	return message, nil
}

func (f *FakeProvider) Watch(ctx context.Context, accessToken, topic string) (WatchState, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.WatchCalls++
	if f.WatchErr != nil {
		return WatchState{}, f.WatchErr
	}
	state := f.WatchState
	if state.Expiration.IsZero() {
		state.Expiration = time.Now().Add(6 * 24 * time.Hour)
	}
	return state, nil
}

func (f *FakeProvider) StopWatch(ctx context.Context, accessToken string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.StopCalls++
	return f.StopErr
}

func (f *FakeProvider) Profile(ctx context.Context, accessToken string) (Profile, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.OnProfile != nil {
		return f.OnProfile(ctx)
	}
	if f.ProfileErr != nil {
		return Profile{}, f.ProfileErr
	}
	return f.ProfileValue, nil
}

func (f *FakeProvider) History(ctx context.Context, accessToken, startHistoryID, pageToken string,
	max int) (HistoryPage, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	index := f.HistoryCalls
	f.HistoryCalls++
	if f.OnHistory != nil {
		return f.OnHistory(ctx, startHistoryID, pageToken)
	}
	if f.HistoryErr != nil {
		return HistoryPage{}, f.HistoryErr
	}
	if index >= len(f.HistoryPages) {
		return HistoryPage{LatestHistoryID: startHistoryID}, nil
	}
	return f.HistoryPages[index], nil
}

// FakeExchanger is a deterministic TokenExchanger.
type FakeExchanger struct {
	mu sync.Mutex

	ByCode    map[string]TokenSet
	ByRefresh map[string]TokenSet
	Exchanges int
	Refreshes int
	Revokes   int
	Revoked   []string

	// AcceptAnyCode is the development fixture flow: the backend-served consent page returns a
	// one-time code it generated itself, so no Google code map is needed. It never applies to the
	// real OAuth exchanger.
	AcceptAnyCode bool
	DefaultTokens TokenSet

	ExchangeErr error
	RefreshErr  error
	RevokeErr   error
}

func (f *FakeExchanger) Exchange(ctx context.Context, code, verifier, redirectURI string) (TokenSet, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Exchanges++
	if f.ExchangeErr != nil {
		return TokenSet{}, f.ExchangeErr
	}
	if f.AcceptAnyCode && code != "" {
		tokens := f.DefaultTokens
		if tokens.AccessToken == "" {
			tokens.AccessToken = "dev-access-token"
		}
		if tokens.RefreshToken == "" {
			tokens.RefreshToken = "dev-refresh-token"
		}
		if tokens.Expiry.IsZero() {
			tokens.Expiry = time.Now().Add(time.Hour)
		}
		if tokens.Scope == "" {
			tokens.Scope = "https://www.googleapis.com/auth/gmail.readonly"
		}
		return tokens, nil
	}
	token, ok := f.ByCode[code]
	if !ok {
		return TokenSet{}, ErrUnauthorized
	}
	return token, nil
}

func (f *FakeExchanger) Refresh(ctx context.Context, refreshToken string) (TokenSet, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Refreshes++
	if f.RefreshErr != nil {
		return TokenSet{}, f.RefreshErr
	}
	token, ok := f.ByRefresh[refreshToken]
	if !ok {
		return TokenSet{}, ErrUnauthorized
	}
	return token, nil
}

func (f *FakeExchanger) Revoke(ctx context.Context, token string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Revokes++
	f.Revoked = append(f.Revoked, token)
	return f.RevokeErr
}

// Counters returns the exchange/refresh/revoke counts for the dev stats endpoint.
func (f *FakeExchanger) Counters() (exchanges, refreshes, revokes int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.Exchanges, f.Refreshes, f.Revokes
}

// FakePushVerifier accepts exactly the configured token.
type FakePushVerifier struct {
	Token  string
	Claims PushClaims
	Err    error
}

func (f *FakePushVerifier) Verify(ctx context.Context, authorization string) (PushClaims, error) {
	if f.Err != nil {
		return PushClaims{}, f.Err
	}
	if f.Token != "" && bearerRaw(authorization) != f.Token {
		return PushClaims{}, ErrPushUnauthorized
	}
	return f.Claims, nil
}
