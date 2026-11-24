package store

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pam/recap/backend-go/internal/config"
)

func gmailTestStore(t *testing.T) *Store {
	t.Helper()
	path := filepath.Join(t.TempDir(), "pam.db")
	ctx := context.Background()
	db, err := Open(ctx, config.Database{URL: "file:" + path})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return New(db, []byte("0123456789abcdef0123456789abcdef"), 1)
}

func gmailTestOwner(t *testing.T, s *Store, email string) string {
	t.Helper()
	now := time.Date(2026, 11, 24, 6, 0, 0, 0, time.UTC)
	if _, err := s.CreateAccount(context.Background(), email, "Uji",
		PasswordDigest{Salt: []byte("salt"), Hash: []byte("hash"), KDF: "scrypt:N=32768,r=8,p=1"},
		now); err != nil {
		t.Fatal(err)
	}
	return OwnerIDForEmail(email)
}

func TestGmailConnectionSealsTokenAndEnforcesOneOwner(t *testing.T) {
	s := gmailTestStore(t)
	ctx := context.Background()
	owner := gmailTestOwner(t, s, "gmail-one@example.test")
	other := gmailTestOwner(t, s, "gmail-two@example.test")
	now := time.Date(2026, 11, 24, 6, 0, 0, 0, time.UTC)

	connection, err := s.SaveGmailConnection(ctx, GmailConnectionInput{
		OwnerID: owner, AccountEmail: "one@gmail.test", Scope: "scope-readonly",
		RefreshToken: "refresh-secret-value", WatchExpiresAt: now.Add(6 * 24 * time.Hour),
		HistoryCursor: "100", Now: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	if connection.RefreshToken != "refresh-secret-value" || connection.AccountEmail != "one@gmail.test" {
		t.Fatalf("round trip mismatch: %+v", connection)
	}

	// The raw row must not contain the mailbox or the token in clear.
	var emailCipher, tokenCipher string
	if err := s.DB.QueryRowContext(ctx, `SELECT CAST(account_email_ciphertext AS TEXT),
		CAST(refresh_token_ciphertext AS TEXT) FROM gmail_connections WHERE owner_id = ?`,
		owner).Scan(&emailCipher, &tokenCipher); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(emailCipher, "one@gmail.test") || strings.Contains(tokenCipher, "refresh-secret-value") {
		t.Fatal("connection secrets were stored in clear")
	}

	if _, err := s.GetGmailConnection(ctx, other); !errors.Is(err, ErrGmailNotConnected) {
		t.Fatalf("owner isolation broken: %v", err)
	}
	if _, err := s.SaveGmailConnection(ctx, GmailConnectionInput{
		OwnerID: other, AccountEmail: "one@gmail.test", Scope: "scope-readonly",
		RefreshToken: "other-refresh", Now: now,
	}); !errors.Is(err, ErrGmailMailboxTaken) {
		t.Fatalf("a mailbox must not be linked to two owners: %v", err)
	}

	// Reconnect replaces the row (still exactly one connection per owner).
	if _, err := s.SaveGmailConnection(ctx, GmailConnectionInput{
		OwnerID: owner, AccountEmail: "one@gmail.test", Scope: "scope-readonly",
		RefreshToken: "refresh-rotated", HistoryCursor: "200", Now: now.Add(time.Minute),
	}); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM gmail_connections WHERE owner_id = ?`,
		owner).Scan(&count); err != nil || count != 1 {
		t.Fatalf("expected exactly one connection, got %d (%v)", count, err)
	}
	reconnected, err := s.GetGmailConnection(ctx, owner)
	if err != nil || reconnected.RefreshToken != "refresh-rotated" {
		t.Fatalf("reconnect did not replace the token: %+v %v", reconnected, err)
	}
	if _, err := s.GmailConnectionByEmailHash(ctx, s.GmailEmailHash("one@gmail.test")); err != nil {
		t.Fatalf("push lookup must resolve the active mailbox: %v", err)
	}

	if err := s.DisconnectGmail(ctx, owner, now.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	disconnected, err := s.GetGmailConnection(ctx, owner)
	if err != nil || disconnected.State != "DISCONNECTED" || disconnected.RefreshToken != "" {
		t.Fatalf("disconnect must clear the sealed token: %+v %v", disconnected, err)
	}
	if _, err := s.GmailConnectionByEmailHash(ctx, s.GmailEmailHash("one@gmail.test")); !errors.Is(err, ErrGmailNotConnected) {
		t.Fatalf("a disconnected mailbox must not resolve push events: %v", err)
	}
}

func TestGmailOAuthStateSingleUseAndExpiry(t *testing.T) {
	s := gmailTestStore(t)
	ctx := context.Background()
	owner := gmailTestOwner(t, s, "gmail-state@example.test")
	now := time.Date(2026, 11, 24, 6, 0, 0, 0, time.UTC)

	if err := s.CreateGmailOAuthState(ctx, owner, "state-hash", "verifier-1",
		"https://api.example.test/v1/gmail/connect/callback", now.Add(5*time.Minute), now); err != nil {
		t.Fatal(err)
	}
	consumedOwner, verifier, redirect, err := s.ConsumeGmailOAuthState(ctx, "state-hash", now)
	if err != nil || consumedOwner != owner || verifier != "verifier-1" ||
		redirect != "https://api.example.test/v1/gmail/connect/callback" {
		t.Fatalf("consume failed: %v %q %q", err, verifier, redirect)
	}
	if _, _, _, err := s.ConsumeGmailOAuthState(ctx, "state-hash", now); !errors.Is(err, ErrGmailStateInvalid) {
		t.Fatalf("state replay must fail closed: %v", err)
	}
	if err := s.CreateGmailOAuthState(ctx, owner, "short-state", "verifier-2",
		"https://api.example.test/cb", now.Add(time.Minute), now); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := s.ConsumeGmailOAuthState(ctx, "short-state", now.Add(2*time.Minute)); !errors.Is(err, ErrGmailStateExpired) {
		t.Fatalf("expired state must fail: %v", err)
	}
	if err := s.CreateGmailOAuthState(ctx, owner, "long-state", "verifier-3",
		"https://api.example.test/cb", now.Add(11*time.Minute), now); err == nil {
		t.Fatal("state ttl above ten minutes must be rejected")
	}
}

func TestGmailPushEventsAreIdempotent(t *testing.T) {
	s := gmailTestStore(t)
	ctx := context.Background()
	owner := gmailTestOwner(t, s, "gmail-push@example.test")
	now := time.Date(2026, 11, 24, 6, 0, 0, 0, time.UTC)
	connection, err := s.SaveGmailConnection(ctx, GmailConnectionInput{
		OwnerID: owner, AccountEmail: "push@gmail.test", Scope: "scope",
		RefreshToken: "refresh", Now: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	payload := `{"emailAddress":"push@gmail.test","historyId":"500"}`
	created, err := s.RecordGmailPushEvent(ctx, owner, connection.ID, "event-key-1", payload, "now", now)
	if err != nil || !created {
		t.Fatalf("first event must be created: %v %v", created, err)
	}
	created, err = s.RecordGmailPushEvent(ctx, owner, connection.ID, "event-key-1",
		`{"emailAddress":"push@gmail.test","historyId":"500"}`, "now", now)
	if err != nil || created {
		t.Fatalf("duplicate event must be a no-op: %v %v", created, err)
	}
	events, err := s.PendingGmailPushEvents(ctx, owner, 10)
	if err != nil || len(events) != 1 || events[0].Payload != payload {
		t.Fatalf("durable payload mismatch: %+v %v", events, err)
	}
	var raw string
	if err := s.DB.QueryRowContext(ctx, `SELECT CAST(payload_ciphertext AS TEXT) FROM gmail_push_events`).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(raw, "push@gmail.test") {
		t.Fatal("push payload was stored in clear")
	}
	if err := s.FinishGmailPushEvent(ctx, events[0].ID, "PROCESSED", "", now); err != nil {
		t.Fatal(err)
	}
	remaining, err := s.PendingGmailPushEvents(ctx, owner, 10)
	if err != nil || len(remaining) != 0 {
		t.Fatalf("processed events must leave the queue: %+v %v", remaining, err)
	}
}

func TestGmailBackfillJobRetriesAndCheckpoint(t *testing.T) {
	s := gmailTestStore(t)
	ctx := context.Background()
	owner := gmailTestOwner(t, s, "gmail-job@example.test")
	now := time.Date(2026, 11, 24, 6, 0, 0, 0, time.UTC)
	month := "2026-11"
	start, end, err := ParseMonth(month)
	if err != nil {
		t.Fatal(err)
	}
	job, err := s.EnsureGmailBackfillJob(ctx, owner, month, start, end, now)
	if err != nil {
		t.Fatal(err)
	}
	again, err := s.EnsureGmailBackfillJob(ctx, owner, month, start, end, now)
	if err != nil || again.ID != job.ID {
		t.Fatalf("one job per owner+month: %v %q %q", err, job.ID, again.ID)
	}
	job, err = s.StartGmailSyncJob(ctx, owner, job.ID, now)
	if err != nil || job.State != "RUNNING" {
		t.Fatalf("start job: %+v %v", job, err)
	}
	if err := s.CheckpointGmailSyncJob(ctx, owner, job.ID, "page-2", 10, 8, 1, 1, 3, now); err != nil {
		t.Fatal(err)
	}
	if err := s.FinishGmailSyncJob(ctx, owner, job.ID, "FAILED", "provider_unavailable", now); err != nil {
		t.Fatal(err)
	}
	// A failed month must be retried with the same row and keep its page checkpoint.
	retried, err := s.EnsureGmailBackfillJob(ctx, owner, month, start, end, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if retried.ID != job.ID || retried.State != "CREATED" {
		t.Fatalf("failed job must be reusable: %+v", retried)
	}
	resumed, err := s.StartGmailSyncJob(ctx, owner, retried.ID, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if resumed.PageToken != "page-2" || resumed.Seen != 10 || resumed.Imported != 8 {
		t.Fatalf("checkpoint lost: %+v", resumed)
	}
	if err := s.FinishGmailSyncJob(ctx, owner, job.ID, "COMPLETE", "", now.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	completed, err := s.CompletedGmailBackfillMonths(ctx, owner, start.AddDate(0, -11, 0))
	if err != nil || !completed[month] {
		t.Fatalf("completed month missing: %+v %v", completed, err)
	}
}
