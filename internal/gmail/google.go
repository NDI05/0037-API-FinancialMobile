package gmail

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// GoogleProvider is the production adapter for the Gmail REST API.
type GoogleProvider struct {
	BaseURL string
	Client  *http.Client
}

func NewGoogleProvider(client *http.Client) *GoogleProvider {
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	return &GoogleProvider{BaseURL: "https://gmail.googleapis.com/gmail/v1", Client: client}
}

func (p *GoogleProvider) endpoint(path string, query url.Values) string {
	base := strings.TrimRight(p.BaseURL, "/")
	if query != nil {
		return base + path + "?" + query.Encode()
	}
	return base + path
}

func (p *GoogleProvider) do(ctx context.Context, method, target, accessToken string,
	body any) ([]byte, error) {
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		reader = strings.NewReader(string(raw))
	}
	request, err := http.NewRequestWithContext(ctx, method, target, reader)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Authorization", "Bearer "+accessToken)
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := p.Client.Do(request)
	if err != nil {
		return nil, err
	}
	defer func() { _ = response.Body.Close() }()
	payload, err := io.ReadAll(io.LimitReader(response.Body, 8<<20))
	if err != nil {
		return nil, err
	}
	if response.StatusCode >= 300 {
		return nil, providerError(response.StatusCode)
	}
	return payload, nil
}

// providerError maps HTTP status to a typed, body-free error.
func providerError(status int) error {
	switch status {
	case http.StatusUnauthorized, http.StatusForbidden:
		return ErrUnauthorized
	case http.StatusNotFound:
		return &APIError{Status: status, Code: "not_found", Expired: true}
	case http.StatusTooManyRequests, http.StatusInternalServerError, http.StatusBadGateway,
		http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return &APIError{Status: status, Code: "provider_unavailable"}
	}
	return &APIError{Status: status, Code: "provider_error"}
}

// IsHistoryExpired reports a 404 from history.list, which means the cursor fell out of Gmail's
// retention window and the coordinator must fall back to a staged re-scan.
func IsHistoryExpired(err error) bool {
	var apiErr *APIError
	if AsAPIError(err, &apiErr) {
		return apiErr.Expired
	}
	return false
}

// AsAPIError is a small errors.As wrapper kept local so callers do not import errors twice.
func AsAPIError(err error, target **APIError) bool {
	for err != nil {
		if typed, ok := err.(*APIError); ok {
			*target = typed
			return true
		}
		unwrapper, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = unwrapper.Unwrap()
	}
	return false
}

func (p *GoogleProvider) ListMessages(ctx context.Context, accessToken, query, pageToken string,
	max int) (MessageList, error) {
	values := url.Values{}
	values.Set("maxResults", fmt.Sprintf("%d", max))
	if query != "" {
		values.Set("q", query)
	}
	if pageToken != "" {
		values.Set("pageToken", pageToken)
	}
	payload, err := p.do(ctx, http.MethodGet, p.endpoint("/users/me/messages", values),
		accessToken, nil)
	if err != nil {
		return MessageList{}, err
	}
	var body struct {
		Messages []struct {
			ID string `json:"id"`
		} `json:"messages"`
		NextPageToken string `json:"nextPageToken"`
	}
	if err := json.Unmarshal(payload, &body); err != nil {
		return MessageList{}, fmt.Errorf("messages.list response is not JSON")
	}
	result := MessageList{NextPageToken: body.NextPageToken}
	for _, message := range body.Messages {
		if message.ID != "" {
			result.Messages = append(result.Messages, MessageRef{ID: message.ID})
		}
	}
	return result, nil
}

func (p *GoogleProvider) GetMessage(ctx context.Context, accessToken, id string) (RawMessage, error) {
	values := url.Values{"format": {"raw"}}
	payload, err := p.do(ctx, http.MethodGet,
		p.endpoint("/users/me/messages/"+url.PathEscape(id), values), accessToken, nil)
	if err != nil {
		return RawMessage{}, err
	}
	var body struct {
		ID  string `json:"id"`
		Raw string `json:"raw"`
	}
	if err := json.Unmarshal(payload, &body); err != nil {
		return RawMessage{}, fmt.Errorf("messages.get response is not JSON")
	}
	decoded, err := base64.RawURLEncoding.DecodeString(body.Raw)
	if err != nil {
		decoded, err = base64.URLEncoding.DecodeString(body.Raw)
		if err != nil {
			return RawMessage{}, fmt.Errorf("messages.get raw payload is not base64url")
		}
	}
	messageID := body.ID
	if messageID == "" {
		messageID = id
	}
	return RawMessage{ID: messageID, Raw: decoded}, nil
}

func (p *GoogleProvider) Profile(ctx context.Context, accessToken string) (Profile, error) {
	payload, err := p.do(ctx, http.MethodGet, p.endpoint("/users/me/profile", nil), accessToken, nil)
	if err != nil {
		return Profile{}, err
	}
	var body struct {
		EmailAddress string `json:"emailAddress"`
		HistoryID    string `json:"historyId"`
	}
	if err := json.Unmarshal(payload, &body); err != nil {
		return Profile{}, fmt.Errorf("profile response is not JSON")
	}
	if body.EmailAddress == "" {
		return Profile{}, fmt.Errorf("profile response has no email address")
	}
	return Profile{EmailAddress: body.EmailAddress, HistoryID: body.HistoryID}, nil
}

func (p *GoogleProvider) Watch(ctx context.Context, accessToken, topic string) (WatchState, error) {
	payload, err := p.do(ctx, http.MethodPost, p.endpoint("/users/me/watch", nil), accessToken,
		map[string]string{"topicName": topic})
	if err != nil {
		return WatchState{}, err
	}
	var body struct {
		Expiration string `json:"expiration"`
		HistoryID  string `json:"historyId"`
	}
	if err := json.Unmarshal(payload, &body); err != nil {
		return WatchState{}, fmt.Errorf("watch response is not JSON")
	}
	state := WatchState{HistoryID: body.HistoryID}
	if epochMillis, err := parseInt64(body.Expiration); err == nil {
		state.Expiration = time.UnixMilli(epochMillis)
	}
	if state.Expiration.IsZero() {
		// Gmail returns expiration as milliseconds since epoch; a missing value must not disable
		// renewal, so fall back to the documented maximum watch lifetime minus a safety margin.
		state.Expiration = time.Now().Add(6 * 24 * time.Hour)
	}
	return state, nil
}

func (p *GoogleProvider) StopWatch(ctx context.Context, accessToken string) error {
	_, err := p.do(ctx, http.MethodPost, p.endpoint("/users/me/stop", nil), accessToken,
		map[string]any{})
	if err != nil && IsHistoryExpired(err) {
		// users.stop reports 404 when no watch exists; that already satisfies the disconnect goal.
		return nil
	}
	return err
}

func (p *GoogleProvider) History(ctx context.Context, accessToken, startHistoryID, pageToken string,
	max int) (HistoryPage, error) {
	values := url.Values{}
	values.Set("startHistoryId", startHistoryID)
	values.Set("maxResults", fmt.Sprintf("%d", max))
	values.Add("historyTypes", "messageAdded")
	if pageToken != "" {
		values.Set("pageToken", pageToken)
	}
	payload, err := p.do(ctx, http.MethodGet, p.endpoint("/users/me/history", values), accessToken, nil)
	if err != nil {
		return HistoryPage{}, err
	}
	var body struct {
		History []struct {
			Messages []struct {
				ID string `json:"id"`
			} `json:"messagesAdded"`
		} `json:"history"`
		NextPageToken string `json:"nextPageToken"`
		HistoryID     string `json:"historyId"`
	}
	if err := json.Unmarshal(payload, &body); err != nil {
		return HistoryPage{}, fmt.Errorf("history response is not JSON")
	}
	page := HistoryPage{NextPageToken: body.NextPageToken, LatestHistoryID: body.HistoryID}
	seen := map[string]bool{}
	for _, record := range body.History {
		// messagesAdded is an array of {message:{id}}; flatten and dedupe within the page.
		for _, entry := range record.Messages {
			if entry.ID == "" || seen[entry.ID] {
				continue
			}
			seen[entry.ID] = true
			page.MessageIDs = append(page.MessageIDs, entry.ID)
		}
	}
	return page, nil
}

func parseInt64(raw string) (int64, error) {
	var value int64
	for _, r := range raw {
		if r < '0' || r > '9' {
			return 0, fmt.Errorf("not an integer")
		}
		value = value*10 + int64(r-'0')
	}
	if raw == "" {
		return 0, fmt.Errorf("empty")
	}
	return value, nil
}
