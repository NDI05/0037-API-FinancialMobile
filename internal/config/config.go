// Package config loads the PAM backend configuration from the environment.
//
// Development/test has deterministic defaults so a local run needs no external service.
// Production refuses the development secrets instead of silently using them.
package config

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"math"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	DefaultPort           = 8080
	DefaultAccessTTL      = 15 * time.Minute
	DefaultRefreshTTLDays = 30
	DefaultDataKeyVersion = 1
	defaultInviteCode     = "pam-dev"
	defaultJWTSecret      = "dev-jwt-secret-not-for-production-use-32b"
	defaultRefreshPepper  = "dev-refresh-pepper-not-for-production-use"
	defaultDatabaseURL    = "file:./data/pam.db"
)

// Config is the complete runtime configuration. Secrets are kept only in this process.
type Config struct {
	Env                string
	Port               int
	LogLevel           string
	Database           Database
	InviteCode         string
	InternalSweepToken string
	JWT                JWT
	DataKey            []byte
	KeyVersion         int
	LLM                LLM
	CategoryLLM        CategoryLLM
	Gmail              Gmail
	Retention          Retention
	Limits             Limits
	Warnings           []string
}

type Database struct {
	URL       string
	AuthToken string
}

type JWT struct {
	Secret        []byte
	Issuer        string
	Audience      string
	AccessTTL     time.Duration
	RefreshTTL    time.Duration
	RefreshPepper string
}

type LLM struct {
	Provider       string
	BaseURL        string
	APIKey         string
	Model          string
	MaxTokens      int
	MaxInputTokens int
	Timeout        time.Duration
	FakeScenario   string
}

type CategoryLLM struct {
	Enabled            bool
	Provider           string
	BaseURL            string
	APIKey             string
	Deployment         string
	Model              string
	ModelVersion       string
	Region             string
	DeploymentType     string
	Timeout            time.Duration
	DailyCeilingUSD    float64
	MonthlyCeilingUSD  float64
	OwnerAttemptsDay   int
	InstallAttemptsDay int
	PromptPer1K        float64
	CompletionPer1K    float64
}

// Gmail is the Gmail API integration policy. It is disabled by default so a backend without
// Google Cloud credentials still runs every other feature.
type Gmail struct {
	Enabled bool
	// Mode selects the transport. "polling" (default) runs OAuth, backfill and delta without
	// Pub/Sub; "push" is the opt-in rollback that keeps the old watch + Pub/Sub behaviour.
	Mode               string
	ClientID           string
	ClientSecret       string
	RedirectURI        string
	TopicName          string
	PushAudience       string
	PushServiceAccount string
	AppDeepLink        string
	AuthURL            string
	TokenURL           string
	RevokeURL          string
	JWKSURL            string
	Scope              string
	StateTTL           time.Duration
	BackfillMonths     int
	WatchRenewBefore   time.Duration
	WorkerInterval     time.Duration
	PageSize           int
	MaxPagesPerRun     int
	// DeltaInterval is the minimum automatic delta cadence per owner (contract §9.4: 900 s).
	DeltaInterval time.Duration
	// SyncCooldown throttles manual POST /v1/gmail/sync requests from the same owner.
	SyncCooldown time.Duration
	// AllowLoopbackRedirect permits the exact local Android UAT callback over HTTP. It is only
	// honoured for APP_ENV=development/uat-local and host 127.0.0.1.
	AllowLoopbackRedirect bool
	// Provider selects the Gmail adapter: "google" (real API) or "fake" (dev/UAT fixture only).
	Provider string
	// DevFixtureFile is the JSON fixture served by the fake provider. Dev-only, outside the repo.
	DevFixtureFile string
	// DevScenario selects the fake provider script: normal, history_expired or rate_limit.
	DevScenario string
}

// Retention controls the scheduled CR-005 cleanup. Both switches default to off: the server never
// scans or deletes financial data unless an operator explicitly turns it on. REPORT_ONLY is the
// default mode; deletion additionally needs DeleteEnabled and INTERNAL_SWEEP_TOKEN.
type Retention struct {
	SweepEnabled  bool
	DeleteEnabled bool
	SweepInterval time.Duration
}

type Limits struct {
	AnalysesPerHour int
	AnalysesPerDay  int
	DailyCeilingUSD float64
	PromptPer1K     float64
	CompletionPer1K float64
	UnknownCallUSD  float64
	MaxCallCostUSD  float64
}

// Load parses env. It returns an error for invalid values and production-unsafe secrets.
// gmailCallbackPath is the only HTTP-clearable callback path (local Android UAT loopback).
const gmailCallbackPath = "/v1/gmail/connect/callback"

// gmailRedirectURIProblem validates GMAIL_REDIRECT_URI and returns "" when it is acceptable.
func gmailRedirectURIProblem(cfg *Config) string {
	parsed, err := url.Parse(cfg.Gmail.RedirectURI)
	if err != nil || parsed.Hostname() == "" || parsed.RawQuery != "" || parsed.Fragment != "" ||
		parsed.User != nil {
		return "GMAIL_REDIRECT_URI must be an absolute URL without credentials, query or fragment"
	}
	if parsed.Scheme == "https" {
		return ""
	}
	loopbackProfile := cfg.Env == "development" || cfg.Env == "uat-local"
	if parsed.Scheme == "http" && loopbackProfile && cfg.Gmail.AllowLoopbackRedirect &&
		parsed.Hostname() == "127.0.0.1" && parsed.Path == gmailCallbackPath {
		// Port intentionally not pinned: the UAT profile uses 18090, the QA harness uses an
		// ephemeral port. No wildcard host/path and no public HTTP callback is accepted.
		return ""
	}
	return "GMAIL_REDIRECT_URI must be HTTPS (HTTP is allowed only for APP_ENV=development/uat-local " +
		"with GMAIL_ALLOW_LOOPBACK_REDIRECT=true, host 127.0.0.1 and path " + gmailCallbackPath + ")"
}

func Load(env map[string]string) (*Config, error) {
	if env == nil {
		env = environ()
	}
	cfg := &Config{
		Env:                get(env, "APP_ENV", get(env, "NODE_ENV", "development")),
		LogLevel:           get(env, "LOG_LEVEL", "info"),
		InviteCode:         get(env, "REGISTRATION_INVITE_CODE", ""),
		InternalSweepToken: get(env, "INTERNAL_SWEEP_TOKEN", ""),
		Database: Database{
			URL:       normalizeDatabaseURL(get(env, "DATABASE_URL", defaultDatabaseURL)),
			AuthToken: get(env, "DATABASE_AUTH_TOKEN", ""),
		},
		JWT: JWT{
			Issuer:        get(env, "JWT_ISSUER", "pam-api"),
			Audience:      get(env, "JWT_AUDIENCE", "pam-android"),
			RefreshPepper: get(env, "REFRESH_PEPPER", ""),
		},
		KeyVersion: intValue(env, "DATA_KEY_VERSION", DefaultDataKeyVersion),
		LLM: LLM{
			Provider:       get(env, "LLM_PROVIDER", "fake"),
			BaseURL:        get(env, "LLM_BASE_URL", "https://api.openai.com/v1"),
			APIKey:         get(env, "LLM_API_KEY", ""),
			Model:          get(env, "LLM_MODEL", "gpt-4o-mini"),
			MaxTokens:      intValue(env, "LLM_MAX_OUTPUT_TOKENS", 800),
			MaxInputTokens: intValue(env, "LLM_MAX_INPUT_TOKENS", 4000),
			Timeout:        time.Duration(intValue(env, "LLM_TIMEOUT_MS", 45000)) * time.Millisecond,
			FakeScenario:   get(env, "FAKE_LLM_SCENARIO", "valid"),
		},
		CategoryLLM: CategoryLLM{
			Enabled:            boolValue(env, "CATEGORY_LLM_ENABLED", false),
			Provider:           get(env, "CATEGORY_LLM_PROVIDER", "azure"),
			BaseURL:            get(env, "AZURE_CLASSIFIER_BASE_URL", ""),
			APIKey:             get(env, "AZURE_CLASSIFIER_API_KEY", ""),
			Deployment:         get(env, "AZURE_CLASSIFIER_DEPLOYMENT", ""),
			Model:              get(env, "AZURE_CLASSIFIER_MODEL", ""),
			ModelVersion:       get(env, "AZURE_CLASSIFIER_MODEL_VERSION", ""),
			Region:             get(env, "AZURE_CLASSIFIER_REGION", ""),
			DeploymentType:     get(env, "AZURE_CLASSIFIER_DEPLOYMENT_TYPE", ""),
			Timeout:            time.Duration(intValue(env, "CATEGORY_LLM_TIMEOUT_MS", 20000)) * time.Millisecond,
			DailyCeilingUSD:    floatValue(env, "CATEGORY_LLM_DAILY_CEILING_USD", 0.10),
			MonthlyCeilingUSD:  floatValue(env, "CATEGORY_LLM_MONTHLY_CEILING_USD", 2.00),
			OwnerAttemptsDay:   intValue(env, "CATEGORY_LLM_OWNER_ATTEMPTS_DAY", 20),
			InstallAttemptsDay: intValue(env, "CATEGORY_LLM_INSTALL_ATTEMPTS_DAY", 100),
			PromptPer1K:        floatValue(env, "CATEGORY_LLM_PRICE_PROMPT_PER_1K_USD", 0),
			CompletionPer1K:    floatValue(env, "CATEGORY_LLM_PRICE_COMPLETION_PER_1K_USD", 0),
		},
		Gmail: Gmail{
			Enabled:               boolValue(env, "GMAIL_ENABLED", false),
			Mode:                  strings.ToLower(get(env, "GMAIL_MODE", "polling")),
			Provider:              strings.ToLower(get(env, "GMAIL_PROVIDER", "google")),
			ClientID:              get(env, "GMAIL_CLIENT_ID", ""),
			ClientSecret:          get(env, "GMAIL_CLIENT_SECRET", ""),
			RedirectURI:           get(env, "GMAIL_REDIRECT_URI", ""),
			TopicName:             get(env, "GMAIL_PUBSUB_TOPIC", ""),
			PushAudience:          get(env, "GMAIL_PUSH_AUDIENCE", ""),
			PushServiceAccount:    get(env, "GMAIL_PUSH_SERVICE_ACCOUNT", ""),
			AppDeepLink:           get(env, "GMAIL_APP_DEEP_LINK", "pam://gmail/connected"),
			AuthURL:               get(env, "GMAIL_AUTH_URL", "https://accounts.google.com/o/oauth2/v2/auth"),
			TokenURL:              get(env, "GMAIL_TOKEN_URL", "https://oauth2.googleapis.com/token"),
			RevokeURL:             get(env, "GMAIL_REVOKE_URL", "https://oauth2.googleapis.com/revoke"),
			JWKSURL:               get(env, "GMAIL_JWKS_URL", "https://www.googleapis.com/oauth2/v3/certs"),
			Scope:                 get(env, "GMAIL_SCOPE", "https://www.googleapis.com/auth/gmail.readonly"),
			StateTTL:              time.Duration(intValue(env, "GMAIL_STATE_TTL_SECONDS", 600)) * time.Second,
			BackfillMonths:        intValue(env, "GMAIL_BACKFILL_MONTHS", 12),
			WatchRenewBefore:      time.Duration(intValue(env, "GMAIL_WATCH_RENEW_BEFORE_HOURS", 24)) * time.Hour,
			WorkerInterval:        time.Duration(intValue(env, "GMAIL_WORKER_INTERVAL_SECONDS", 60)) * time.Second,
			PageSize:              intValue(env, "GMAIL_PAGE_SIZE", 50),
			MaxPagesPerRun:        intValue(env, "GMAIL_MAX_PAGES_PER_RUN", 5),
			DeltaInterval:         time.Duration(intValue(env, "GMAIL_DELTA_INTERVAL_SECONDS", 900)) * time.Second,
			SyncCooldown:          time.Duration(intValue(env, "GMAIL_SYNC_COOLDOWN_SECONDS", 60)) * time.Second,
			AllowLoopbackRedirect: boolValue(env, "GMAIL_ALLOW_LOOPBACK_REDIRECT", false),
			DevFixtureFile:        get(env, "GMAIL_DEV_FIXTURE_FILE", ""),
			DevScenario:           strings.ToLower(get(env, "GMAIL_DEV_SCENARIO", "normal")),
		},
		Retention: Retention{
			SweepEnabled:  boolValue(env, "RETENTION_SWEEP_ENABLED", false),
			DeleteEnabled: boolValue(env, "RETENTION_DELETE_ENABLED", false),
			SweepInterval: time.Duration(intValue(env, "RETENTION_SWEEP_INTERVAL_HOURS", 24)) * time.Hour,
		},
		Limits: Limits{
			AnalysesPerHour: intValue(env, "RATE_LIMIT_ANALYSES_PER_HOUR", 10),
			AnalysesPerDay:  intValue(env, "RATE_LIMIT_ANALYSES_PER_DAY", 40),
			DailyCeilingUSD: floatValue(env, "DAILY_AI_CEILING_USD", 1),
			PromptPer1K:     floatValue(env, "PRICE_PROMPT_PER_1K_USD", 0.00015),
			CompletionPer1K: floatValue(env, "PRICE_COMPLETION_PER_1K_USD", 0.0006),
			UnknownCallUSD:  floatValue(env, "UNKNOWN_AI_CALL_COST_USD", 0.001),
		},
	}
	port, err := strconv.Atoi(get(env, "PORT", strconv.Itoa(DefaultPort)))
	if err != nil || port < 0 || port > 65535 {
		return nil, fmt.Errorf("PORT must be an integer 0..65535")
	}
	cfg.Port = port

	retentionHours := 24
	if raw := get(env, "RETENTION_SWEEP_INTERVAL_HOURS", ""); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil {
			return nil, fmt.Errorf("RETENTION_SWEEP_INTERVAL_HOURS must be 1..168")
		}
		retentionHours = parsed
	}
	if retentionHours < 1 || retentionHours > 168 {
		return nil, fmt.Errorf("RETENTION_SWEEP_INTERVAL_HOURS must be 1..168")
	}
	cfg.Retention.SweepInterval = time.Duration(retentionHours) * time.Hour
	if cfg.Retention.DeleteEnabled {
		// Deletion is only reachable through the same token as the existing internal sweep. A
		// delete-enabled schedule without a token would be an unauthenticated destructive path, so
		// the configuration fails closed instead of silently downgrading to report-only.
		if cfg.InternalSweepToken == "" {
			return nil, fmt.Errorf("RETENTION_DELETE_ENABLED requires INTERNAL_SWEEP_TOKEN")
		}
		cfg.Retention.SweepEnabled = true
	}

	accessSeconds := intValue(env, "ACCESS_TOKEN_TTL_SECONDS", int(DefaultAccessTTL/time.Second))
	if accessSeconds < 60 || accessSeconds > 900 {
		return nil, fmt.Errorf("ACCESS_TOKEN_TTL_SECONDS must be 60..900 (target <=15 minutes)")
	}
	cfg.JWT.AccessTTL = time.Duration(accessSeconds) * time.Second
	refreshDays := intValue(env, "REFRESH_TOKEN_TTL_DAYS", DefaultRefreshTTLDays)
	if refreshDays < 1 || refreshDays > 365 {
		return nil, fmt.Errorf("REFRESH_TOKEN_TTL_DAYS must be 1..365")
	}
	cfg.JWT.RefreshTTL = time.Duration(refreshDays) * 24 * time.Hour

	rawJWT := get(env, "JWT_SECRET", "")
	rawRefresh := get(env, "REFRESH_PEPPER", "")
	rawDataKey := get(env, "DATA_ENCRYPTION_KEY", "")
	dataKey, dataKeyErr := decodeDataKeyStrict(rawDataKey)
	if rawDataKey != "" && dataKeyErr != nil {
		return nil, fmt.Errorf("DATA_ENCRYPTION_KEY is invalid: %w", dataKeyErr)
	}
	devKeySum := sha256.Sum256([]byte("pam-dev-data-key"))
	devKey := devKeySum[:]

	if cfg.CategoryLLM.Enabled {
		if cfg.CategoryLLM.Provider != "azure" || cfg.CategoryLLM.BaseURL == "" ||
			cfg.CategoryLLM.Deployment == "" || cfg.CategoryLLM.APIKey == "" ||
			cfg.CategoryLLM.PromptPer1K <= 0 || cfg.CategoryLLM.CompletionPer1K <= 0 {
			return nil, fmt.Errorf("invalid category LLM configuration: enabled requires azure endpoint/key and verified prices")
		}
	}
	if cfg.Gmail.Enabled {
		problems := []string{}
		if cfg.Gmail.Mode != "polling" && cfg.Gmail.Mode != "push" {
			problems = append(problems, "GMAIL_MODE must be polling or push")
		}
		if cfg.Gmail.Provider != "google" && cfg.Gmail.Provider != "fake" {
			problems = append(problems, "GMAIL_PROVIDER must be google or fake")
		}
		if cfg.Gmail.ClientID == "" || cfg.Gmail.ClientSecret == "" {
			problems = append(problems, "GMAIL_CLIENT_ID and GMAIL_CLIENT_SECRET are required when GMAIL_ENABLED=true")
		}
		// The OAuth callback is HTTPS in every profile. The single exception is the local Android
		// UAT loopback: HTTP, APP_ENV development/uat-local, explicit flag, host exactly 127.0.0.1
		// and the exact callback path. The port is free so the QA harness can use an ephemeral one.
		if redirectProblem := gmailRedirectURIProblem(cfg); redirectProblem != "" {
			problems = append(problems, redirectProblem)
		}
		// Pub/Sub settings are only needed by the opt-in push mode. In polling mode they are
		// ignored (and may stay empty) so a zero-cost deployment starts without Google Cloud.
		if cfg.Gmail.Mode == "push" {
			if cfg.Gmail.TopicName == "" {
				problems = append(problems, "GMAIL_PUBSUB_TOPIC is required when GMAIL_MODE=push")
			}
			if cfg.Gmail.PushAudience == "" || cfg.Gmail.PushServiceAccount == "" {
				problems = append(problems, "GMAIL_PUSH_AUDIENCE and GMAIL_PUSH_SERVICE_ACCOUNT are required when GMAIL_MODE=push")
			}
		}
		// The fake provider is a development/UAT fixture only; it must never be reachable from a
		// production profile even if every other flag is set.
		if cfg.Gmail.Provider == "fake" {
			if cfg.Env != "development" {
				problems = append(problems, "GMAIL_PROVIDER=fake is only allowed when APP_ENV=development")
			}
			if !cfg.Gmail.AllowLoopbackRedirect {
				problems = append(problems, "GMAIL_PROVIDER=fake requires GMAIL_ALLOW_LOOPBACK_REDIRECT=true")
			}
			if cfg.Gmail.DevFixtureFile == "" {
				problems = append(problems, "GMAIL_DEV_FIXTURE_FILE is required when GMAIL_PROVIDER=fake")
			}
			if cfg.Gmail.DevScenario != "normal" && cfg.Gmail.DevScenario != "history_expired" &&
				cfg.Gmail.DevScenario != "rate_limit" {
				problems = append(problems, "GMAIL_DEV_SCENARIO must be normal, history_expired or rate_limit")
			}
		}
		if len(problems) > 0 {
			return nil, fmt.Errorf("invalid Gmail configuration: %s", strings.Join(problems, "; "))
		}
		if cfg.Gmail.Mode == "polling" && cfg.Gmail.TopicName != "" {
			cfg.Warnings = append(cfg.Warnings,
				"GMAIL_MODE=polling ignores GMAIL_PUBSUB_TOPIC/GMAIL_PUSH_*; set GMAIL_MODE=push to re-enable")
		}
	}
	if cfg.Env == "production" {
		problems := []string{}
		if cfg.InviteCode == "" || cfg.InviteCode == defaultInviteCode {
			problems = append(problems, "REGISTRATION_INVITE_CODE must be set to a non-development value")
		}
		if len(rawJWT) < 32 || rawJWT == defaultJWTSecret {
			problems = append(problems, "JWT_SECRET must be at least 32 bytes and not the development value")
		}
		if len(rawRefresh) < 32 || rawRefresh == defaultRefreshPepper {
			problems = append(problems, "REFRESH_PEPPER must be at least 32 bytes and not the development value")
		}
		if rawDataKey == "" || dataKeyErr != nil {
			problems = append(problems, "DATA_ENCRYPTION_KEY is required and must be base64 for exactly 32 bytes")
		} else if bytes.Equal(dataKey, devKey) {
			problems = append(problems, "DATA_ENCRYPTION_KEY must not be the known development key")
		}
		if len(cfg.Database.AuthToken) == 0 && strings.HasPrefix(cfg.Database.URL, "libsql://") {
			problems = append(problems, "DATABASE_AUTH_TOKEN is required for a libsql:// URL")
		}
		if len(problems) > 0 {
			return nil, fmt.Errorf("invalid production configuration: %s", strings.Join(problems, "; "))
		}
	}
	if cfg.InviteCode == "" {
		cfg.InviteCode = defaultInviteCode
		cfg.Warnings = append(cfg.Warnings, "REGISTRATION_INVITE_CODE missing: using the development invite code")
	}
	if cfg.Env != "production" {
		cfg.Warnings = append(cfg.Warnings, "development secrets are in use; do not run this configuration in production")
	}
	cfg.JWT.Secret = []byte(rawJWT)
	if rawJWT == "" {
		cfg.JWT.Secret = []byte(defaultJWTSecret)
	} else if len(rawJWT) < 32 {
		return nil, fmt.Errorf("JWT_SECRET must be at least 32 bytes")
	}
	cfg.JWT.RefreshPepper = rawRefresh
	if rawRefresh == "" {
		cfg.JWT.RefreshPepper = defaultRefreshPepper
	} else if len(rawRefresh) < 32 {
		return nil, fmt.Errorf("REFRESH_PEPPER must be at least 32 bytes")
	}
	if rawDataKey == "" {
		cfg.DataKey = devKey
		cfg.Warnings = append(cfg.Warnings, "DATA_ENCRYPTION_KEY missing: using the development key")
	} else {
		cfg.DataKey = dataKey
	}
	if cfg.KeyVersion < 1 {
		cfg.KeyVersion = 1
	}
	if cfg.LogLevel != "debug" && cfg.LogLevel != "info" && cfg.LogLevel != "warn" && cfg.LogLevel != "error" {
		return nil, fmt.Errorf("LOG_LEVEL must be debug|info|warn|error")
	}
	switch cfg.LLM.Provider {
	case "fake", "openai":
	case "azure":
		endpoint, err := url.Parse(cfg.LLM.BaseURL)
		if err != nil || endpoint.Scheme != "https" || endpoint.Hostname() == "" ||
			endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" ||
			strings.TrimRight(endpoint.Path, "/") != "/openai/v1" ||
			strings.TrimSpace(cfg.LLM.APIKey) == "" || get(env, "LLM_MODEL", "") == "" ||
			get(env, "PRICE_PROMPT_PER_1K_USD", "") == "" || get(env, "PRICE_COMPLETION_PER_1K_USD", "") == "" ||
			cfg.Limits.PromptPer1K <= 0 || cfg.Limits.CompletionPer1K <= 0 {
			return nil, fmt.Errorf("invalid Azure analysis configuration: requires HTTPS /openai/v1 endpoint, API key, deployment and verified prices")
		}
	default:
		return nil, fmt.Errorf("LLM_PROVIDER must be fake|openai|azure")
	}
	if cfg.LLM.MaxTokens < 1 || cfg.LLM.MaxTokens > 100_000 {
		return nil, fmt.Errorf("LLM_MAX_OUTPUT_TOKENS must be 1..100000")
	}
	if cfg.LLM.MaxInputTokens < 1 || cfg.LLM.MaxInputTokens > 1_000_000 {
		return nil, fmt.Errorf("LLM_MAX_INPUT_TOKENS must be 1..1000000")
	}
	cfg.Limits.MaxCallCostUSD = float64(cfg.LLM.MaxInputTokens)/1000*cfg.Limits.PromptPer1K +
		float64(cfg.LLM.MaxTokens)/1000*cfg.Limits.CompletionPer1K
	for name, value := range map[string]float64{
		"DAILY_AI_CEILING_USD":        cfg.Limits.DailyCeilingUSD,
		"UNKNOWN_AI_CALL_COST_USD":    cfg.Limits.UnknownCallUSD,
		"PRICE_PROMPT_PER_1K_USD":     cfg.Limits.PromptPer1K,
		"PRICE_COMPLETION_PER_1K_USD": cfg.Limits.CompletionPer1K,
	} {
		if math.IsNaN(value) || math.IsInf(value, 0) || value < 0 {
			return nil, fmt.Errorf("%s must be a finite non-negative number", name)
		}
	}
	if cfg.Limits.DailyCeilingUSD <= 0 || cfg.Limits.UnknownCallUSD <= 0 ||
		cfg.Limits.MaxCallCostUSD <= 0 {
		return nil, fmt.Errorf("AI cost limits and prices must be positive")
	}
	return cfg, nil
}

func normalizeDatabaseURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if strings.HasPrefix(raw, "turso://") {
		return "libsql://" + strings.TrimPrefix(raw, "turso://")
	}
	return raw
}

func decodeDataKeyStrict(raw string) ([]byte, error) {
	decoded, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return nil, fmt.Errorf("must be base64")
	}
	if len(decoded) != 32 {
		return nil, fmt.Errorf("must decode to 32 bytes")
	}
	return decoded, nil
}

func environ() map[string]string {
	m := make(map[string]string, len(os.Environ()))
	for _, entry := range os.Environ() {
		key, value, ok := strings.Cut(entry, "=")
		if ok {
			m[key] = value
		}
	}
	return m
}

func get(env map[string]string, key, fallback string) string {
	if v, ok := env[key]; ok && strings.TrimSpace(v) != "" {
		return strings.TrimSpace(v)
	}
	return fallback
}

func boolValue(env map[string]string, key string, fallback bool) bool {
	value, ok := env[key]
	if !ok || value == "" {
		return fallback
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func intValue(env map[string]string, key string, fallback int) int {
	raw := get(env, key, "")
	if raw == "" {
		return fallback
	}
	v, err := strconv.Atoi(raw)
	if err != nil {
		return fallback
	}
	return v
}

func floatValue(env map[string]string, key string, fallback float64) float64 {
	raw := get(env, key, "")
	if raw == "" {
		return fallback
	}
	v, err := strconv.ParseFloat(raw, 64)
	if err != nil {
		return fallback
	}
	return v
}
