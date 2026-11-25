package httpapi

import (
	"context"
	"database/sql"
	"testing"
	"time"
)

// CR-009 owner decision: invite-gated registration is retired. Public registration is open for any
// valid email+password and always creates a plain USER account, so no invite code is sent at all.
func TestPublicRegistrationNeedsNoInviteCode(t *testing.T) {
	h := newHarness(t)
	status, body := h.request("POST", "/v1/accounts", "", map[string]any{
		"email": "open@example.test", "password": testPassword, "displayName": "Open",
	})
	if status != 201 {
		t.Fatalf("register without invite code: %d %#v", status, body)
	}
	if body["role"] != "USER" {
		t.Fatalf("role = %v, want USER", body["role"])
	}
	access, _ := h.login("open@example.test")
	status, me := h.request("GET", "/v1/me", access, nil)
	if status != 200 || me["role"] != "USER" || me["googleLinked"] != false {
		t.Fatalf("session after open registration: %d %#v", status, me)
	}
}

// The retired invite fields are gone from the public registration contract entirely, so the strict
// JSON decoder rejects them: a leaked admin invitation token cannot be redeemed through public
// registration and the one-time invitation stays unconsumed.
func TestPublicRegistrationRejectsRetiredInviteFields(t *testing.T) {
	h := newHarness(t)
	h.register("inviter@example.test")
	actor := h.ownerIDOf("inviter@example.test")
	ctx := context.Background()
	now := time.Now()
	invitation, adminToken, err := h.store.CreateAdminInvitation(ctx, actor,
		"invited-admin@example.test", "ADMIN", 2*time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	for name, extra := range map[string]map[string]any{
		"invite code":      {"inviteCode": "pam-test"},
		"invitation token": {"invitationToken": adminToken},
	} {
		body := map[string]any{
			"email": "invited-admin@example.test", "password": testPassword, "displayName": "Undangan",
		}
		for key, value := range extra {
			body[key] = value
		}
		status, response := h.request("POST", "/v1/accounts", "", body)
		if status != 400 || response["code"] != "invalid_request" {
			t.Fatalf("%s: %d %#v, want 400 invalid_request", name, status, response)
		}
	}
	var accountCount int
	if err := h.store.DB.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM users WHERE email = ?`, "invited-admin@example.test").
		Scan(&accountCount); err != nil {
		t.Fatal(err)
	}
	if accountCount != 0 {
		t.Fatalf("retired invite fields still created %d accounts", accountCount)
	}
	var usedAt sql.NullString
	if err := h.store.DB.QueryRowContext(ctx, `SELECT used_at FROM admin_invitations
		WHERE id = ?`, invitation.ID).Scan(&usedAt); err != nil {
		t.Fatal(err)
	}
	if usedAt.Valid {
		t.Fatalf("public registration consumed an admin invitation: %v", usedAt.String)
	}
}
