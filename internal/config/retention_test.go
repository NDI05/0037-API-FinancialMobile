package config

import (
	"strings"
	"testing"
	"time"
)

func TestRetentionDefaultsOffAndIntervalBounds(t *testing.T) {
	cfg, err := Load(map[string]string{"APP_ENV": "development"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Retention.SweepEnabled || cfg.Retention.DeleteEnabled {
		t.Fatalf("retention must be opt-in: %+v", cfg.Retention)
	}
	if cfg.Retention.SweepInterval != 24*time.Hour {
		t.Fatalf("default sweep interval = %s, want 24h", cfg.Retention.SweepInterval)
	}

	for _, hours := range []string{"0", "169", "-1", "not-a-number"} {
		_, err := Load(map[string]string{
			"APP_ENV": "development", "RETENTION_SWEEP_INTERVAL_HOURS": hours,
		})
		if err == nil || !strings.Contains(err.Error(), "RETENTION_SWEEP_INTERVAL_HOURS") {
			t.Fatalf("interval %q accepted or wrong error: %v", hours, err)
		}
	}
	for _, hours := range []string{"1", "168", "48"} {
		cfg, err := Load(map[string]string{
			"APP_ENV": "development", "RETENTION_SWEEP_INTERVAL_HOURS": hours,
		})
		if err != nil {
			t.Fatalf("interval %q rejected: %v", hours, err)
		}
		if cfg.Retention.SweepInterval <= 0 {
			t.Fatalf("interval %q produced %s", hours, cfg.Retention.SweepInterval)
		}
	}
}

func TestRetentionDeleteRequiresTokenAndImpliesSweep(t *testing.T) {
	_, err := Load(map[string]string{
		"APP_ENV": "development", "RETENTION_DELETE_ENABLED": "true",
	})
	if err == nil || !strings.Contains(err.Error(), "INTERNAL_SWEEP_TOKEN") {
		t.Fatalf("delete without internal token must be rejected: %v", err)
	}

	cfg, err := Load(map[string]string{
		"APP_ENV": "development", "RETENTION_DELETE_ENABLED": "true",
		"INTERNAL_SWEEP_TOKEN": "synthetic-token",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Retention.DeleteEnabled || !cfg.Retention.SweepEnabled {
		t.Fatalf("delete implies the sweep schedule: %+v", cfg.Retention)
	}
}
