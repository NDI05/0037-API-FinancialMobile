package store

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/pam/recap/backend-go/internal/config"
)

// TestUpgradeRepairsLegacyEmailAmounts proves migration 022 scales only the rows written by the
// buggy rupiah parser: EMAIL rows from gmail-livin-v1/v2 are multiplied by 100 once, while MANUAL
// rows and rows already written in minor units (v3) are untouched. It also proves the owner/month
// revision is bumped so cached summaries cannot keep serving the old total.
func TestUpgradeRepairsLegacyEmailAmounts(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "pam.db")
	raw, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.ExecContext(ctx, `CREATE TABLE schema_migrations (
		version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	migrations, err := LoadMigrations()
	if err != nil {
		t.Fatal(err)
	}
	for _, migration := range migrations {
		if migration.Version > 21 {
			continue
		}
		for _, statement := range migration.Statements {
			if _, err := raw.ExecContext(ctx, statement); err != nil {
				t.Fatalf("migration %03d: %v", migration.Version, err)
			}
		}
		if _, err := raw.ExecContext(ctx,
			`INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)`,
			migration.Version, nowString(time.Now())); err != nil {
			t.Fatal(err)
		}
	}
	now := nowString(time.Now())
	if _, err := raw.ExecContext(ctx, `INSERT INTO users
		(owner_id, email, display_name, salt, password_hash, kdf, created_at, last_seen_at)
		VALUES ('owner-repair', 'repair@example.test', 'Repair', x'00', x'00', 'scrypt',
		        ?, ?)`, now, now); err != nil {
		t.Fatal(err)
	}
	insert := func(id, source string, amount int64, parserVersion any, month string) {
		fingerprint := fmt.Sprintf("%032d", len(id)+int(amount))
		if _, err := raw.ExecContext(ctx, `INSERT INTO transactions
			(id, owner_id, direction, source, amount_minor, event_at_ms, month_id, fingerprint,
			 sensitive_ciphertext, sensitive_iv, sensitive_tag, key_version, created_at, updated_at,
			 parser_version)
			VALUES (?, 'owner-repair', 'DEBIT', ?, ?, 1700000000000, ?, ?, x'00', x'00', x'00', 1, ?, ?, ?)`,
			id, source, amount, month, fingerprint, now, now, parserVersion); err != nil {
			t.Fatal(err)
		}
	}
	insert("tx_legacy_v1__", "EMAIL", 15000, "gmail-livin-v1", "2026-09")
	insert("tx_legacy_v2__", "EMAIL", 123000, "gmail-livin-v2", "2026-10")
	insert("tx_manual______", "MANUAL", 12345, nil, "2026-11")
	insert("tx_new_v3______", "EMAIL", 2500000, "gmail-livin-v3", "2026-11")
	raw.Close()

	db, err := Open(ctx, config.Database{URL: "file:" + path})
	if err != nil {
		t.Fatalf("upgrade from 021 failed: %v", err)
	}
	defer db.Close()
	want := map[string]int64{
		"tx_legacy_v1__":  1_500_000,
		"tx_legacy_v2__":  12_300_000,
		"tx_manual______": 12345,
		"tx_new_v3______": 2_500_000,
	}
	for id, expected := range want {
		var got int64
		if err := db.QueryRowContext(ctx,
			`SELECT amount_minor FROM transactions WHERE id = ?`, id).Scan(&got); err != nil {
			t.Fatalf("%s: %v", id, err)
		}
		if got != expected {
			t.Fatalf("%s amount = %d, want %d", id, got, expected)
		}
	}
	for month, expected := range map[string]int64{"2026-09": 1, "2026-10": 1} {
		var revision int64
		if err := db.QueryRowContext(ctx, `SELECT revision FROM month_revisions
			WHERE owner_id = 'owner-repair' AND month_id = ?`, month).Scan(&revision); err != nil {
			t.Fatalf("%s revision: %v", month, err)
		}
		if revision != expected {
			t.Fatalf("%s revision = %d, want %d", month, revision, expected)
		}
	}
	var manualMonth int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM month_revisions
		WHERE owner_id = 'owner-repair' AND month_id = '2026-11'`).Scan(&manualMonth); err != nil {
		t.Fatal(err)
	}
	if manualMonth != 0 {
		t.Fatal("migration bumped a month revision without repaired rows")
	}
}
