package config

import (
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

func productionEnv() map[string]string {
	key := sha256.Sum256([]byte("synthetic-production-data-key"))
	return map[string]string{
		"APP_ENV": "production", "DATABASE_URL": "file:./data/prod-test.db",
		"REGISTRATION_INVITE_CODE": "production-invite",
		"JWT_SECRET":               "synthetic-production-jwt-secret-32-bytes",
		"REFRESH_PEPPER":           "synthetic-production-refresh-pepper-32",
		"DATA_ENCRYPTION_KEY":      base64.StdEncoding.EncodeToString(key[:]),
	}
}

func TestProductionRequiresRealEncryptionKey(t *testing.T) {
	valid := productionEnv()
	if _, err := Load(valid); err != nil {
		t.Fatalf("valid production config rejected: %v", err)
	}
	cases := []struct {
		name   string
		mutate func(map[string]string)
	}{
		{"missing", func(env map[string]string) { delete(env, "DATA_ENCRYPTION_KEY") }},
		{"bad base64", func(env map[string]string) { env["DATA_ENCRYPTION_KEY"] = "not-base64!" }},
		{"wrong length", func(env map[string]string) {
			env["DATA_ENCRYPTION_KEY"] = base64.StdEncoding.EncodeToString([]byte("short"))
		}},
		{"development key", func(env map[string]string) {
			sum := sha256.Sum256([]byte("pam-dev-data-key"))
			env["DATA_ENCRYPTION_KEY"] = base64.StdEncoding.EncodeToString(sum[:])
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := productionEnv()
			tc.mutate(env)
			_, err := Load(env)
			if err == nil {
				t.Fatal("production accepted an unsafe encryption key")
			}
			if !strings.Contains(err.Error(), "DATA_ENCRYPTION_KEY") {
				t.Fatalf("error must name the setting: %v", err)
			}
		})
	}
}

func TestProductionRejectsDevelopmentAuthConstants(t *testing.T) {
	cases := []struct {
		name  string
		key   string
		value string
	}{
		{"jwt default", "JWT_SECRET", defaultJWTSecret},
		{"jwt short", "JWT_SECRET", "short"},
		{"refresh default", "REFRESH_PEPPER", defaultRefreshPepper},
		{"invite default", "REGISTRATION_INVITE_CODE", defaultInviteCode},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := productionEnv()
			env[tc.key] = tc.value
			if _, err := Load(env); err == nil {
				t.Fatalf("production accepted unsafe %s", tc.key)
			}
		})
	}
}

func TestDevelopmentUsesExplicitDefaultsAndWarns(t *testing.T) {
	cfg, err := Load(map[string]string{"APP_ENV": "development"})
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.DataKey) != 32 {
		t.Fatalf("data key length = %d", len(cfg.DataKey))
	}
	if len(cfg.Warnings) == 0 {
		t.Fatal("development should warn about default secrets")
	}
	if cfg.Limits.UnknownCallUSD <= 0 {
		t.Fatal("unknown provider usage must have a conservative cost")
	}
}

func TestCostConfigurationRejectsInvalidValues(t *testing.T) {
	cases := []map[string]string{
		{"DAILY_AI_CEILING_USD": "0"},
		{"DAILY_AI_CEILING_USD": "NaN"},
		{"UNKNOWN_AI_CALL_COST_USD": "-1"},
		{"PRICE_PROMPT_PER_1K_USD": "+Inf"},
		{"LLM_MAX_INPUT_TOKENS": "0"},
		{"LLM_MAX_OUTPUT_TOKENS": "100001"},
	}
	for _, extra := range cases {
		env := map[string]string{"APP_ENV": "test"}
		for k, v := range extra {
			env[k] = v
		}
		if _, err := Load(env); err == nil {
			t.Fatalf("accepted invalid cost configuration %v", extra)
		}
	}
	cfg, err := Load(map[string]string{"APP_ENV": "test"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Limits.MaxCallCostUSD <= 0 {
		t.Fatalf("max call cost = %f", cfg.Limits.MaxCallCostUSD)
	}
}

func TestCategoryLLMFailsClosedWithoutVerifiedPrices(t *testing.T) {
	env := map[string]string{"CATEGORY_LLM_ENABLED": "true", "AZURE_CLASSIFIER_BASE_URL": "https://example.test/openai/v1",
		"AZURE_CLASSIFIER_DEPLOYMENT": "d", "AZURE_CLASSIFIER_API_KEY": "k"}
	if _, err := Load(env); err == nil {
		t.Fatal("enabled category LLM accepted without verified prices")
	}
	env["CATEGORY_LLM_PRICE_PROMPT_PER_1K_USD"] = "0.001"
	env["CATEGORY_LLM_PRICE_COMPLETION_PER_1K_USD"] = "0.002"
	if _, err := Load(env); err != nil {
		t.Fatalf("valid category LLM config rejected: %v", err)
	}
}

func TestGmailConfigurationDefaultsAndValidation(t *testing.T) {
	base := map[string]string{"APP_ENV": "test", "DATABASE_URL": "file:./data/gmail-test.db"}
	cfg, err := Load(base)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Gmail.Enabled {
		t.Fatal("Gmail must be opt-in")
	}
	if cfg.Gmail.Scope != "https://www.googleapis.com/auth/gmail.readonly" ||
		cfg.Gmail.StateTTL != 10*time.Minute || cfg.Gmail.BackfillMonths != 12 ||
		cfg.Gmail.PageSize != 50 || cfg.Gmail.MaxPagesPerRun != 5 ||
		cfg.Gmail.AppDeepLink != "pam://gmail/connected" {
		t.Fatalf("unexpected Gmail defaults: %+v", cfg.Gmail)
	}

	enabled := map[string]string{}
	for key, value := range base {
		enabled[key] = value
	}
	enabled["GMAIL_ENABLED"] = "true"
	if _, err := Load(enabled); err == nil {
		t.Fatal("enabled Gmail without credentials must fail closed")
	}

	enabled["GMAIL_CLIENT_ID"] = "client-id.apps.googleusercontent.com"
	enabled["GMAIL_CLIENT_SECRET"] = "client-secret"
	enabled["GMAIL_REDIRECT_URI"] = "https://api.example.test/v1/gmail/connect/callback"
	enabled["GMAIL_PUBSUB_TOPIC"] = "projects/pam-uat/topics/gmail-push"
	enabled["GMAIL_PUSH_AUDIENCE"] = "https://api.example.test/v1/internal/gmail/push"
	enabled["GMAIL_PUSH_SERVICE_ACCOUNT"] = "pubsub-push@pam-uat.iam.gserviceaccount.com"
	enabled["GMAIL_BACKFILL_MONTHS"] = "12"
	enabled["GMAIL_WORKER_INTERVAL_SECONDS"] = "45"
	cfg, err = Load(enabled)
	if err != nil {
		t.Fatalf("valid Gmail configuration rejected: %v", err)
	}
	if !cfg.Gmail.Enabled || cfg.Gmail.WorkerInterval != 45*time.Second ||
		cfg.Gmail.PushServiceAccount != "pubsub-push@pam-uat.iam.gserviceaccount.com" {
		t.Fatalf("Gmail configuration not mapped: %+v", cfg.Gmail)
	}

	enabled["GMAIL_REDIRECT_URI"] = "http://api.example.test/v1/gmail/connect/callback"
	if _, err := Load(enabled); err == nil {
		t.Fatal("a plain-HTTP redirect URI must be rejected")
	}
}

func TestGmailPollingModeDefaultsAndFakeGuard(t *testing.T) {
	development := map[string]string{
		"APP_ENV": "development", "DATABASE_URL": "file:./data/gmail-polling-test.db",
		"GMAIL_ENABLED": "true", "GMAIL_CLIENT_ID": "client-id.apps.googleusercontent.com",
		"GMAIL_CLIENT_SECRET": "client-secret",
		// Polling is the default and must not require Pub/Sub settings.
		"GMAIL_REDIRECT_URI": "https://api.example.test/v1/gmail/connect/callback",
	}
	cfg, err := Load(development)
	if err != nil {
		t.Fatalf("polling config without Pub/Sub rejected: %v", err)
	}
	if cfg.Gmail.Mode != "polling" || cfg.Gmail.Provider != "google" ||
		cfg.Gmail.DeltaInterval != 15*time.Minute || cfg.Gmail.SyncCooldown != 60*time.Second {
		t.Fatalf("unexpected polling defaults: %+v", cfg.Gmail)
	}

	push := map[string]string{}
	for key, value := range development {
		push[key] = value
	}
	push["GMAIL_MODE"] = "push"
	if _, err := Load(push); err == nil {
		t.Fatal("push mode without topic/audience/service account must fail closed")
	}
	push["GMAIL_PUBSUB_TOPIC"] = "projects/pam-uat/topics/gmail-push"
	push["GMAIL_PUSH_AUDIENCE"] = "https://api.example.test/v1/internal/gmail/push"
	push["GMAIL_PUSH_SERVICE_ACCOUNT"] = "pubsub-push@pam-uat.iam.gserviceaccount.com"
	if _, err := Load(push); err != nil {
		t.Fatalf("complete push config rejected: %v", err)
	}

	loopback := map[string]string{}
	for key, value := range development {
		loopback[key] = value
	}
	loopback["GMAIL_ALLOW_LOOPBACK_REDIRECT"] = "true"
	loopback["GMAIL_REDIRECT_URI"] = "http://127.0.0.1:18099/v1/gmail/connect/callback"
	if _, err := Load(loopback); err != nil {
		t.Fatalf("loopback HTTP on an ephemeral port rejected: %v", err)
	}
	for name, uri := range map[string]string{
		"localhost host":    "http://localhost:18099/v1/gmail/connect/callback",
		"public host":       "http://api.example.test/v1/gmail/connect/callback",
		"other path":        "http://127.0.0.1:18099/v1/gmail/status",
		"other scheme":      "ftp://127.0.0.1/v1/gmail/connect/callback",
		"query parameter":   "http://127.0.0.1:18099/v1/gmail/connect/callback?x=1",
		"embedded userinfo": "http://user@127.0.0.1:18099/v1/gmail/connect/callback",
	} {
		changed := map[string]string{}
		for key, value := range loopback {
			changed[key] = value
		}
		changed["GMAIL_REDIRECT_URI"] = uri
		if _, err := Load(changed); err == nil {
			t.Fatalf("%s must be rejected", name)
		}
	}

	production := productionEnv()
	production["GMAIL_ENABLED"] = "true"
	production["GMAIL_CLIENT_ID"] = "client-id.apps.googleusercontent.com"
	production["GMAIL_CLIENT_SECRET"] = "client-secret"
	production["GMAIL_ALLOW_LOOPBACK_REDIRECT"] = "true"
	production["GMAIL_REDIRECT_URI"] = "http://127.0.0.1:18090/v1/gmail/connect/callback"
	if _, err := Load(production); err == nil {
		t.Fatal("production must never accept an HTTP loopback callback")
	}

	fake := map[string]string{}
	for key, value := range loopback {
		fake[key] = value
	}
	fake["GMAIL_PROVIDER"] = "fake"
	fake["GMAIL_DEV_FIXTURE_FILE"] = "/tmp/pam-dev-fixture.json"
	if _, err := Load(fake); err != nil {
		t.Fatalf("valid fake provider config rejected: %v", err)
	}
	fake["APP_ENV"] = "production"
	productionFake := productionEnv()
	for key, value := range fake {
		productionFake[key] = value
	}
	productionFake["APP_ENV"] = "production"
	if _, err := Load(productionFake); err == nil {
		t.Fatal("fake provider must be rejected outside development")
	}
}
