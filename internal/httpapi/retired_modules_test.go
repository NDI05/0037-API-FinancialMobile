package httpapi

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

// CR-008 retires the admin/invitations/audit, attachment and budget modules from the build target.
// The routes must be gone from the mux (404 even with a valid session), while the legacy tables and
// their rows stay in the schema so no data is destroyed by the scope reduction.
func TestRetiredModulesAreNotRouted(t *testing.T) {
	h := newHarness(t)
	h.register("retired@example.test")
	token, _ := h.login("retired@example.test")

	paths := []string{
		"/v1/admin/invitations",
		"/v1/admin/accounts",
		"/v1/admin/accounts/owner-legacy",
		"/v1/admin/audit",
		"/v1/attachments",
		"/v1/attachments/att_legacy",
		"/v1/budget-plans",
		"/v1/budget-plans/2026-11",
	}
	for _, path := range paths {
		for _, method := range []string{http.MethodGet, http.MethodPost, http.MethodPut,
			http.MethodPatch, http.MethodDelete} {
			if status, body := h.request(method, path, token, nil); status != http.StatusNotFound {
				t.Fatalf("%s %s = %d %#v, want 404", method, path, status, body)
			}
			// No auth required to prove the route does not exist: an unauthenticated request is
			// also a plain 404, not a 401 from a registered-but-guarded handler.
			if status, _ := h.request(method, path, "", nil); status != http.StatusNotFound {
				t.Fatalf("%s %s unauthenticated = %d, want 404", method, path, status)
			}
		}
	}
}

func TestRetiredModuleDataIsRetained(t *testing.T) {
	h := newHarness(t)
	h.register("legacy-data@example.test")
	token, _ := h.login("legacy-data@example.test")
	ownerID := ownerIDForEmail(t, h, "legacy-data@example.test")

	ctx := context.Background()
	now := "2026-11-24T12:00:00Z"
	blob := []byte{1, 2, 3}
	if _, err := h.store.DB.ExecContext(ctx, `INSERT INTO budget_plans
		(id, owner_id, month_id, ciphertext, iv, tag, key_version, created_at, updated_at,
		 revision, expected_income_minor, planned_savings_minor)
		VALUES ('legacy-plan', ?, '2026-10', ?, ?, ?, 1, ?, ?, 3, 1000, 100)`,
		ownerID, blob, blob, blob, now, now); err != nil {
		t.Fatalf("legacy budget row: %v", err)
	}
	if _, err := h.store.DB.ExecContext(ctx, `INSERT INTO admin_invitations
		(id, created_by, email, role, token_hash, expires_at, created_at)
		VALUES ('legacy-invite', ?, 'legacy@example.test', 'USER', 'legacy-hash', ?, ?)`,
		ownerID, now, now); err != nil {
		t.Fatalf("legacy invitation row: %v", err)
	}
	if _, err := h.store.DB.ExecContext(ctx, `INSERT INTO admin_audit
		(id, actor_owner_id, target_owner_id, action, metadata_json, created_at)
		VALUES ('legacy-audit', ?, ?, 'admin.invitation.create', '{}', ?)`,
		ownerID, ownerID, now); err != nil {
		t.Fatalf("legacy audit row: %v", err)
	}
	status, created := h.request("POST", "/v1/transactions", token, map[string]any{
		"direction": "DEBIT", "amountMinor": 1000, "currency": "IDR",
		"eventAt": "2026-11-20T04:00:00Z",
	})
	if status != 201 {
		t.Fatalf("transaction for legacy attachment: %d %#v", status, created)
	}
	if _, err := h.store.DB.ExecContext(ctx, `INSERT INTO attachments
		(id, owner_id, transaction_id, mime, size_bytes, sha256, storage_ref,
		 sensitive_ciphertext, sensitive_iv, sensitive_tag, key_version, created_at_ms,
		 created_at, updated_at)
		VALUES ('legacy-attachment', ?, ?, 'application/pdf', 12, ?, 'attachments/legacy/a.pdf',
		 ?, ?, ?, 1, 1763985600000, ?, ?)`,
		ownerID, created["id"], strings.Repeat("a", 64), blob, blob, blob, now, now); err != nil {
		t.Fatalf("legacy attachment row: %v", err)
	}

	// The retired endpoints must not touch the retained rows.
	for _, request := range []struct{ method, path string }{
		{"GET", "/v1/budget-plans"}, {"DELETE", "/v1/budget-plans/2026-10"},
		{"GET", "/v1/attachments"}, {"DELETE", "/v1/attachments/legacy-attachment"},
		{"GET", "/v1/admin/invitations"}, {"DELETE", "/v1/admin/accounts/" + ownerID},
	} {
		if status, _ := h.request(request.method, request.path, token, nil); status != 404 {
			t.Fatalf("%s %s = %d, want 404", request.method, request.path, status)
		}
	}
	for table, want := range map[string]int{
		"budget_plans": 1, "budget_limits": 0, "attachments": 1,
		"admin_invitations": 1, "admin_audit": 1,
	} {
		var count int
		if err := h.store.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM `+table).Scan(&count); err != nil {
			t.Fatalf("%s table missing: %v", table, err)
		}
		if count != want {
			t.Fatalf("%s rows = %d, want %d", table, count, want)
		}
	}
}
