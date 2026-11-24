// Package gmail owns the Gmail API workflow: OAuth connect, Pub/Sub push verification, the
// rolling one-year backfill and the history-based delta sync.
//
// It deliberately has no knowledge of HTTP handlers or Google credentials in tests: a Provider
// interface (messages.list/get, users.watch/stop, history.list) and a TokenExchanger interface make
// the whole workflow runnable with deterministic fakes, so no network or real Google account is
// needed to prove the contract.
package gmail

import (
	"context"
	"errors"
	"time"
)

// ErrHistoryExpired reports a Gmail history cursor that can no longer be replayed. The coordinator
// recovers with a staged re-scan instead of failing the connection.
var ErrHistoryExpired = errors.New("gmail history cursor expired")

// ErrUnauthorized reports a revoked or invalid Google grant.
var ErrUnauthorized = errors.New("gmail authorization rejected")

// APIError is a typed provider failure. It never carries request bodies or tokens.
type APIError struct {
	Status  int
	Code    string
	Expired bool
}

func (e *APIError) Error() string {
	if e.Code != "" {
		return "gmail provider error: " + e.Code
	}
	return "gmail provider error"
}

// TokenSet is the OAuth result. The refresh token is only ever handed to the store, which seals it.
type TokenSet struct {
	AccessToken  string
	RefreshToken string
	Expiry       time.Time
	Scope        string
}

// MessageRef is one id from messages.list. Gmail ids are opaque; they are never logged.
type MessageRef struct {
	ID string
}

type MessageList struct {
	Messages      []MessageRef
	NextPageToken string
}

// RawMessage is the raw RFC 822 payload. It is decoded in memory only and never persisted.
type RawMessage struct {
	ID  string
	Raw []byte
}

type Profile struct {
	EmailAddress string
	HistoryID    string
}

type WatchState struct {
	Expiration time.Time
	HistoryID  string
}

// HistoryPage flattens history.list to the message ids added since the cursor.
type HistoryPage struct {
	MessageIDs      []string
	NextPageToken   string
	LatestHistoryID string
}

// Provider is the Gmail REST surface the coordinator needs.
type Provider interface {
	ListMessages(ctx context.Context, accessToken, query, pageToken string, max int) (MessageList, error)
	GetMessage(ctx context.Context, accessToken, id string) (RawMessage, error)
	Watch(ctx context.Context, accessToken, topic string) (WatchState, error)
	StopWatch(ctx context.Context, accessToken string) error
	Profile(ctx context.Context, accessToken string) (Profile, error)
	History(ctx context.Context, accessToken, startHistoryID, pageToken string, max int) (HistoryPage, error)
}

// TokenExchanger is the OAuth code/refresh/revoke surface.
type TokenExchanger interface {
	Exchange(ctx context.Context, code, verifier, redirectURI string) (TokenSet, error)
	Refresh(ctx context.Context, refreshToken string) (TokenSet, error)
	Revoke(ctx context.Context, token string) error
}

// PushClaims are the verified claims of a Pub/Sub push OIDC token.
type PushClaims struct {
	Email    string
	Audience string
	Issuer   string
}

// PushVerifier validates the Authorization header of the Pub/Sub push request.
type PushVerifier interface {
	Verify(ctx context.Context, authorization string) (PushClaims, error)
}
