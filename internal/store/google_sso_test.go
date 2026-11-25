package store

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/pam/recap/backend-go/internal/config"
)

func newSSOStore(t *testing.T) (*Store, context.Context) {
	t.Helper()
	ctx := context.Background()
	db, err := Open(ctx, config.Database{URL: "file:" + filepath.Join(t.TempDir(), "pam.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return New(db, make([]byte, 32), 1), ctx
}

func TestSchemaHasExactly21Migrations(t *testing.T) {
	ctx := context.Background()
	db, err := Open(ctx, config.Database{URL: "file:" + filepath.Join(t.TempDir(), "pam.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var count int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM schema_migrations`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 22 {
		t.Fatalf("migration count = %d, want 22", count)
	}
}

// TestUpgradeFrom020AppliesGoogleSSO proves migration 021 is additive: a database that stopped at
// 020 upgrades on boot and can immediately use the new tables.
func TestUpgradeFrom020AppliesGoogleSSO(t *testing.T) {
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
		if migration.Version > 20 {
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
	raw.Close()

	db, err := Open(ctx, config.Database{URL: "file:" + path})
	if err != nil {
		t.Fatalf("upgrade from 020 failed: %v", err)
	}
	defer db.Close()
	var count int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM schema_migrations`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 22 {
		t.Fatalf("upgraded migrations = %d, want 22", count)
	}
	s := New(db, make([]byte, 32), 1)
	owner := OwnerIDForEmail("upgrade@example.test")
	digest := PasswordDigest{Salt: []byte("salt"), Hash: []byte("hash"), KDF: "scrypt:N=32768,r=8,p=1"}
	if _, err := s.CreateAccount(ctx, "upgrade@example.test", "Upgrade", digest, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := s.LinkGoogleIdentity(ctx, owner, "https://accounts.google.com", "sub-upgrade",
		"upgrade@example.test", time.Now()); err != nil {
		t.Fatalf("link after upgrade: %v", err)
	}
	if linked, err := s.GoogleLinked(ctx, owner); err != nil || !linked {
		t.Fatalf("linked = %v err=%v", linked, err)
	}
}

func TestGoogleNonceIsSingleUseAndExpires(t *testing.T) {
	store, ctx := newSSOStore(t)
	now := time.Now().UTC()
	if err := store.CreateGoogleNonce(ctx, "nonce-1", now.Add(10*time.Minute), now); err != nil {
		t.Fatal(err)
	}
	if err := store.ConsumeGoogleNonce(ctx, "nonce-1", now); err != nil {
		t.Fatal(err)
	}
	if err := store.ConsumeGoogleNonce(ctx, "nonce-1", now); !errors.Is(err, ErrGoogleNonceInvalid) {
		t.Fatalf("replay consume error = %v", err)
	}
	if err := store.ConsumeGoogleNonce(ctx, "unknown", now); !errors.Is(err, ErrGoogleNonceInvalid) {
		t.Fatalf("unknown nonce error = %v", err)
	}
	if err := store.CreateGoogleNonce(ctx, "nonce-expired", now.Add(time.Minute), now); err != nil {
		t.Fatal(err)
	}
	if err := store.ConsumeGoogleNonce(ctx, "nonce-expired", now.Add(2*time.Minute)); !errors.Is(err,
		ErrGoogleNonceInvalid) {
		t.Fatalf("expired nonce error = %v", err)
	}
}

func TestGoogleIdentityLinkRulesAndCascade(t *testing.T) {
	store, ctx := newSSOStore(t)
	now := time.Now().UTC()
	digest := PasswordDigest{Salt: []byte("salt"), Hash: []byte("hash"), KDF: "scrypt:N=32768,r=8,p=1"}
	alice, err := store.CreateAccount(ctx, "alice@example.test", "Alice", digest, now)
	if err != nil {
		t.Fatal(err)
	}
	bob, err := store.CreateAccount(ctx, "bob@example.test", "Bob", digest, now)
	if err != nil {
		t.Fatal(err)
	}
	issuer, subject := "https://accounts.google.com", "google-sub-alice"
	if err := store.LinkGoogleIdentity(ctx, alice.OwnerID, issuer, subject, "alice@example.test", now); err != nil {
		t.Fatal(err)
	}
	// Relinking the same identity is idempotent and must not flip ownership.
	if err := store.LinkGoogleIdentity(ctx, alice.OwnerID, issuer, subject, "alice@example.test", now); err != nil {
		t.Fatalf("idempotent relink: %v", err)
	}
	if err := store.LinkGoogleIdentity(ctx, alice.OwnerID, issuer, "other-sub", "other@example.test",
		now); !errors.Is(err, ErrGoogleAlreadyLinked) {
		t.Fatalf("second identity for one owner = %v", err)
	}
	if err := store.LinkGoogleIdentity(ctx, bob.OwnerID, issuer, subject, "alice@example.test",
		now); !errors.Is(err, ErrGoogleIdentityConflict) {
		t.Fatalf("cross-owner identity = %v", err)
	}
	identity, err := store.FindGoogleIdentity(ctx, issuer, subject)
	if err != nil || identity.OwnerID != alice.OwnerID {
		t.Fatalf("find identity = %#v err=%v", identity, err)
	}
	if linked, err := store.GoogleLinked(ctx, bob.OwnerID); err != nil || linked {
		t.Fatalf("bob linked = %v err=%v", linked, err)
	}
	// Deleting the owner must remove the identity so an old Google token cannot resurrect it.
	if _, err := store.DB.ExecContext(ctx, `DELETE FROM users WHERE owner_id = ?`, alice.OwnerID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.FindGoogleIdentity(ctx, issuer, subject); !errors.Is(err,
		ErrGoogleIdentityNotLinked) {
		t.Fatalf("identity survived account deletion: %v", err)
	}
}

func TestConcurrentGoogleLinkHasExactlyOneWinner(t *testing.T) {
	store, ctx := newSSOStore(t)
	now := time.Now().UTC()
	digest := PasswordDigest{Salt: []byte("salt"), Hash: []byte("hash"), KDF: "scrypt:N=32768,r=8,p=1"}
	owners := make([]string, 2)
	for index, email := range []string{"one@example.test", "two@example.test"} {
		account, err := store.CreateAccount(ctx, email, email, digest, now)
		if err != nil {
			t.Fatal(err)
		}
		owners[index] = account.OwnerID
	}
	var wg sync.WaitGroup
	results := make([]error, len(owners))
	for index, owner := range owners {
		wg.Add(1)
		go func(index int, owner string) {
			defer wg.Done()
			results[index] = store.LinkGoogleIdentity(ctx, owner, "https://accounts.google.com",
				"shared-sub", "winner@example.test", now)
		}(index, owner)
	}
	wg.Wait()
	winners := 0
	for _, result := range results {
		switch {
		case result == nil:
			winners++
		case errors.Is(result, ErrGoogleIdentityConflict):
		default:
			t.Fatalf("unexpected link error: %v", result)
		}
	}
	if winners != 1 {
		t.Fatalf("concurrent links winners = %d, want exactly 1 (%v)", winners, results)
	}
	identity, err := store.FindGoogleIdentity(ctx, "https://accounts.google.com", "shared-sub")
	if err != nil {
		t.Fatal(err)
	}
	if identity.OwnerID != owners[0] && identity.OwnerID != owners[1] {
		t.Fatalf("winner owner = %q", identity.OwnerID)
	}
}

func TestGoogleLinkUniqueViolationClassification(t *testing.T) {
	cases := []struct {
		name                    string
		message                 string
		ownerConflict, identity bool
	}{
		{"owner unique", "UNIQUE constraint failed: google_identities.owner_id", true, false},
		{"identity pk", "UNIQUE constraint failed: google_identities.issuer, google_identities.subject",
			false, true},
		{"libsql owner", "constraint failed: UNIQUE constraint failed: google_identities.owner_id (1555)",
			true, false},
		{"non-unique", "constraint failed: FOREIGN KEY constraint failed (787)", false, false},
		{"unique without columns", "UNIQUE constraint failed", false, false},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			ownerConflict, identityConflict := googleLinkUniqueViolation(test.message)
			if ownerConflict != test.ownerConflict || identityConflict != test.identity {
				t.Fatalf("classification = (%v,%v), want (%v,%v)", ownerConflict, identityConflict,
					test.ownerConflict, test.identity)
			}
		})
	}
}

// TestConcurrentGoogleLinkSameOwnerDifferentSubjects is the P2 regression: two simultaneous links
// for one owner with different Google identities used to surface a 500 because the UNIQUE(owner_id)
// failure was mistaken for an unknown identity. Exactly one insert must win and the loser must be a
// clean ErrGoogleAlreadyLinked, with one row and no partial write.
func TestConcurrentGoogleLinkSameOwnerDifferentSubjects(t *testing.T) {
	store, ctx := newSSOStore(t)
	now := time.Now().UTC()
	digest := PasswordDigest{Salt: []byte("salt"), Hash: []byte("hash"), KDF: "scrypt:N=32768,r=8,p=1"}
	account, err := store.CreateAccount(ctx, "owner@example.test", "Owner", digest, now)
	if err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	results := make([]error, 2)
	var wg sync.WaitGroup
	for index, subject := range []string{"concurrent-sub-a", "concurrent-sub-b"} {
		wg.Add(1)
		go func(index int, subject string) {
			defer wg.Done()
			<-start
			results[index] = store.LinkGoogleIdentity(ctx, account.OwnerID,
				"https://accounts.google.com", subject, "owner@example.test", now)
		}(index, subject)
	}
	close(start)
	wg.Wait()
	winners, alreadyLinked := 0, 0
	for _, result := range results {
		switch {
		case result == nil:
			winners++
		case errors.Is(result, ErrGoogleAlreadyLinked):
			alreadyLinked++
		default:
			t.Fatalf("concurrent link error = %v", result)
		}
	}
	if winners != 1 || alreadyLinked != 1 {
		t.Fatalf("winners=%d alreadyLinked=%d results=%v", winners, alreadyLinked, results)
	}
	var count int
	if err := store.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM google_identities
		WHERE owner_id = ?`, account.OwnerID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("identity rows = %d, want 1", count)
	}
	// A later sequential attempt with yet another subject is still already_linked, not conflict.
	if err := store.LinkGoogleIdentity(ctx, account.OwnerID, "https://accounts.google.com",
		"concurrent-sub-c", "owner@example.test", now); !errors.Is(err, ErrGoogleAlreadyLinked) {
		t.Fatalf("third identity link error = %v, want ErrGoogleAlreadyLinked", err)
	}
}
