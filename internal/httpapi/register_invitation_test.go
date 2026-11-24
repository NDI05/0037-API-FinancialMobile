package httpapi

import (
	"context"
	"testing"
	"time"
)

// P2-3 regression: the legacy invitationToken acceptance path is still supported, but only after the
// production inviteCode gate passes. The role always comes from the one-time invitation, never from
// the request body, and invalid/expired/consumed tokens do not create accounts.
func TestInvitationTokenAcceptanceRegression(t *testing.T) {
	h := newHarness(t)
	h.register("inviter@example.test")
	actor := h.ownerIDOf("inviter@example.test")
	ctx := context.Background()
	now := time.Now()
	inviteCode := "pam-test"

	register := func(email, display, code, token string) (int, map[string]any) {
		body := map[string]any{"email": email, "password": testPassword, "displayName": display}
		if code != "" {
			body["inviteCode"] = code
		}
		if token != "" {
			body["invitationToken"] = token
		}
		return h.request("POST", "/v1/accounts", "", body)
	}

	// The invite-code gate is evaluated before the invitation branch: a wrong code must not consume
	// the one-time token.
	_, adminToken, err := h.store.CreateAdminInvitation(ctx, actor, "invited-admin@example.test",
		"ADMIN", 2*time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	if status, body := register("invited-admin@example.test", "Undangan Satu", "wrong", adminToken); status != 403 ||
		body["message"] != "invalid_invite" {
		t.Fatalf("wrong invite code with token: %d %#v", status, body)
	}
	status, accepted := register("invited-admin@example.test", "Undangan Satu", inviteCode, adminToken)
	if status != 201 || accepted["role"] != "ADMIN" {
		t.Fatalf("valid invitation acceptance: %d %#v", status, accepted)
	}
	invitedOwner := h.ownerIDOf("invited-admin@example.test")
	if invitedOwner == actor {
		t.Fatal("invited account reused the inviter owner")
	}
	// Owner isolation: a fresh invited owner sees an empty ledger, not the inviter's data.
	invitedAccess, _ := h.login("invited-admin@example.test")
	if status, list := h.request("GET", "/v1/transactions?month=2026-11", invitedAccess, nil); status != 200 ||
		len(list["items"].([]any)) != 0 {
		t.Fatalf("invited owner leaked transactions: %d %#v", status, list)
	}

	// A consumed token is rejected even for the same invited email.
	if status, body := register("invited-admin@example.test", "Undangan Satu", inviteCode, adminToken); status != 409 ||
		body["code"] != "invitation_used" {
		t.Fatalf("reused invitation: %d %#v", status, body)
	}

	// Invalid, mismatched and expired tokens never create an account.
	if status, body := register("bad-token@example.test", "Bad", inviteCode, "not-a-real-token"); status != 400 ||
		body["code"] != "invalid_invitation" {
		t.Fatalf("invalid token: %d %#v", status, body)
	}
	_, boundToken, err := h.store.CreateAdminInvitation(ctx, actor, "token-bound@example.test",
		"USER", 2*time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	if status, body := register("other-email@example.test", "Other", inviteCode, boundToken); status != 400 ||
		body["code"] != "invalid_invitation" {
		t.Fatalf("token bound to another email: %d %#v", status, body)
	}
	_, expiredToken, err := h.store.CreateAdminInvitation(ctx, actor, "expired-invite@example.test",
		"USER", 2*time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.store.DB.ExecContext(ctx, `UPDATE admin_invitations SET expires_at=? WHERE email=?`,
		now.Add(-2*time.Hour).UTC().Format(time.RFC3339Nano), "expired-invite@example.test"); err != nil {
		t.Fatal(err)
	}
	if status, body := register("expired-invite@example.test", "Expired", inviteCode, expiredToken); status != 410 ||
		body["code"] != "invitation_expired" {
		t.Fatalf("expired token: %d %#v", status, body)
	}
	// A token without the production invite code is still rejected.
	_, noCodeToken, err := h.store.CreateAdminInvitation(ctx, actor, "no-code@example.test",
		"USER", 2*time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	if status, body := register("no-code@example.test", "NoCode", "", noCodeToken); status != 403 ||
		body["message"] != "invalid_invite" {
		t.Fatalf("token without invite code: %d %#v", status, body)
	}
	if status, body := register("expired-invite@example.test", "Expired Again", inviteCode, expiredToken); status != 403 &&
		status != 410 {
		t.Fatalf("rejected token unexpectedly accepted: %d %#v", status, body)
	}
}
