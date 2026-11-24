package httpapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"

	"github.com/pam/recap/backend-go/internal/llm"
	"github.com/pam/recap/backend-go/internal/store"
)

// retentionTestNow is a fixed wall clock so period boundaries are deterministic in HTTP tests.
var retentionTestNow = time.Date(2026, 11, 24, 6, 0, 0, 0, time.UTC) // 13:00 WIB

func pinRetentionClock(h *harness) {
	h.t.Helper()
	h.api.Now = func() time.Time { return retentionTestNow }
	h.store.Now = func() time.Time { return retentionTestNow }
}

func ownerIDForEmail(t *testing.T, h *harness, email string) string {
	t.Helper()
	var ownerID string
	if err := h.store.DB.QueryRowContext(context.Background(),
		`SELECT owner_id FROM users WHERE email = ?`, email).Scan(&ownerID); err != nil {
		t.Fatal(err)
	}
	return ownerID
}

// insertExpiredTransaction writes an expired row directly: the public API correctly refuses to
// create one, so a policy/sweep test needs the pre-existing-row scenario.
func grantRetentionConsent(t *testing.T, h *harness, token, purpose string) {
	t.Helper()
	if status, _ := h.request("POST", "/v1/consents", token, map[string]any{
		"purpose": purpose, "decision": "GRANTED", "noticeVersion": "v0.4-review",
	}); status != 201 {
		t.Fatalf("consent %s status %d", purpose, status)
	}
}

func insertExpiredTransaction(t *testing.T, h *harness, ownerID, id string, eventAt time.Time) {
	t.Helper()
	sum := sha256.Sum256([]byte(id))
	fingerprint := hex.EncodeToString(sum[:])[:32]
	if _, err := h.store.DB.ExecContext(context.Background(), `INSERT INTO transactions
		(id, owner_id, direction, source, amount_minor, currency, event_at_ms, month_id,
		 fingerprint, category_origin, sensitive_ciphertext, sensitive_iv, sensitive_tag,
		 key_version, created_at, updated_at)
		VALUES (?, ?, 'DEBIT', 'MANUAL', 1000, 'IDR', ?, ?, ?, 'USER', x'01', x'02', x'03',
		        1, ?, ?)`,
		id, ownerID, eventAt.UnixMilli(), eventAt.UTC().Format("2006-01"),
		fingerprint, retentionTestNow.UTC().Format(time.RFC3339Nano),
		retentionTestNow.UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
}

func insertExpiredSummary(t *testing.T, h *harness, ownerID, id, monthID string) {
	t.Helper()
	if _, err := h.store.DB.ExecContext(context.Background(), `INSERT INTO summaries
		(id, owner_id, month_id, input_revision, coverage, ciphertext, iv, tag, key_version,
		 created_at, updated_at)
		VALUES (?, ?, ?, 1, 'FULL', x'01', x'02', x'03', 1, ?, ?)`,
		id, ownerID, monthID, retentionTestNow.UTC().Format(time.RFC3339Nano),
		retentionTestNow.UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
}

func TestRetentionInfoAndPeriodGuards(t *testing.T) {
	h := newHarness(t)
	pinRetentionClock(h)
	h.register("retention-guard@example.test")
	token, _ := h.login("retention-guard@example.test")
	if status, _ := h.request("POST", "/v1/consents", token, map[string]any{
		"purpose": "GMAIL_READ", "decision": "GRANTED", "noticeVersion": "v0.4-review",
	}); status != 201 {
		t.Fatalf("consent status %d", status)
	}

	status, info := h.request("GET", "/v1/retention", token, nil)
	if status != 200 {
		t.Fatalf("GET /v1/retention = %d %#v", status, info)
	}
	if info["timezone"] != "Asia/Jakarta" || info["startMonthId"] != "2025-11" ||
		info["endMonthId"] != "2026-11" {
		t.Fatalf("retention window = %#v", info)
	}
	if _, ok := info["windowStart"].(string); !ok {
		t.Fatalf("windowStart must be an RFC3339 string: %#v", info["windowStart"])
	}

	for _, path := range []string{
		"/v1/transactions?month=2024-01",
		"/v1/transactions?month=2027-01",
		"/v1/summaries/2024-01",
		"/v1/analyses/2024-01",
	} {
		status, body := h.request("GET", path, token, nil)
		if status != 400 || body["code"] != "outside_retention" {
			t.Fatalf("%s = %d %#v, want 400 outside_retention", path, status, body)
		}
	}

	// The boundary month is partially retained and must stay selectable (it is clamped, not
	// rejected) so an app opening the current rolling year does not hit an error.
	if status, body := h.request("GET", "/v1/transactions?month=2025-11", token, nil); status != 200 {
		t.Fatalf("boundary month list = %d %#v", status, body)
	}

	// Backfill older than the window is a safe 4xx, not a 500.
	status, body := h.request("POST", "/v1/transactions", token, map[string]any{
		"direction": "DEBIT", "amountMinor": 1000, "currency": "IDR",
		"eventAt": "2024-01-15T00:00:00Z",
	})
	if status != 400 || body["code"] != "outside_retention" {
		t.Fatalf("expired transaction create = %d %#v, want 400 outside_retention", status, body)
	}
	status, body = h.request("PUT", "/v1/summaries/2024-01", token, map[string]any{
		"inputRevision": 1, "payload": map[string]any{"monthId": "2024-01"},
	})
	if status != 400 || body["code"] != "outside_retention" {
		t.Fatalf("expired summary put = %d %#v, want 400 outside_retention", status, body)
	}
	if status, body := h.request("POST", "/v1/import-jobs", token, map[string]any{
		"monthId": "2024-01", "templateVersion": "v1",
	}); status != 400 || body["code"] != "outside_retention" {
		t.Fatalf("expired import job = %d %#v, want 400 outside_retention", status, body)
	}
}

func TestRetentionSweepEndpointAuthAndReportOnly(t *testing.T) {
	h := newHarnessWithConfig(t, &llm.Fake{Scenario: "valid"}, map[string]string{
		"INTERNAL_SWEEP_TOKEN": "retention-test-token",
	})
	pinRetentionClock(h)
	h.register("retention-sweep@example.test")
	ownerID := ownerIDForEmail(t, h, "retention-sweep@example.test")
	insertExpiredTransaction(t, h, ownerID, "tx_old_http", time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC))
	insertExpiredSummary(t, h, ownerID, "sum_old_http", "2024-12")

	// No token configured would be 404; here the token is configured, so a missing/wrong header is
	// a 401 and the endpoint never reports success to an unauthenticated caller.
	if status, _ := h.request("POST", "/v1/internal/retention-sweep", "", nil); status != 401 {
		t.Fatalf("missing token = %d, want 401", status)
	}
	status, body := h.requestWithHeaders("POST", "/v1/internal/retention-sweep", "", nil,
		map[string]string{"x-internal-token": "wrong"})
	if status != 401 {
		t.Fatalf("wrong token = %d %#v, want 401", status, body)
	}

	status, body = h.requestWithHeaders("POST", "/v1/internal/retention-sweep", "", nil,
		map[string]string{"x-internal-token": "retention-test-token"})
	if status != 200 {
		t.Fatalf("report sweep = %d %#v", status, body)
	}
	if body["mode"] != "REPORT_ONLY" || body["deleted"] != false {
		t.Fatalf("default sweep must be report-only: %#v", body)
	}
	if eligible, _ := body["eligible"].(float64); eligible < 2 {
		t.Fatalf("report sweep must count the expired rows: %#v", body)
	}
	if !retentionRowExists(t, h, `SELECT COUNT(*) FROM transactions WHERE id = 'tx_old_http'`) ||
		!retentionRowExists(t, h, `SELECT COUNT(*) FROM summaries WHERE id = 'sum_old_http'`) {
		t.Fatal("report-only sweep must delete nothing")
	}

	// Delete is refused unless RETENTION_DELETE_ENABLED is set.
	status, body = h.requestWithHeaders("POST",
		"/v1/internal/retention-sweep?mode=delete&confirm=RETENTION_DELETE", "", nil,
		map[string]string{"x-internal-token": "retention-test-token"})
	if status != 403 || body["code"] != "retention_delete_disabled" {
		t.Fatalf("delete without flag = %d %#v, want 403", status, body)
	}
	if !retentionRowExists(t, h, `SELECT COUNT(*) FROM transactions WHERE id = 'tx_old_http'`) {
		t.Fatal("refused delete must not remove rows")
	}
	status, _ = h.requestWithHeaders("POST", "/v1/internal/retention-sweep?mode=bogus", "", nil,
		map[string]string{"x-internal-token": "retention-test-token"})
	if status != 400 {
		t.Fatalf("unknown mode = %d, want 400", status)
	}
}

func TestRetentionDeleteEndpointRequiresConfirmation(t *testing.T) {
	h := newHarnessWithConfig(t, &llm.Fake{Scenario: "valid"}, map[string]string{
		"INTERNAL_SWEEP_TOKEN":     "retention-delete-token",
		"RETENTION_DELETE_ENABLED": "true",
	})
	pinRetentionClock(h)
	h.register("retention-delete@example.test")
	ownerID := ownerIDForEmail(t, h, "retention-delete@example.test")
	insertExpiredTransaction(t, h, ownerID, "tx_old_delete", time.Date(2025, 2, 1, 0, 0, 0, 0, time.UTC))
	// Retained row at the exact window start (2025-11-24 00:00 WIB).
	insertExpiredTransaction(t, h, ownerID, "tx_boundary_keep",
		time.Date(2025, 11, 23, 17, 0, 0, 0, time.UTC))

	headers := map[string]string{"x-internal-token": "retention-delete-token"}
	status, body := h.requestWithHeaders("POST", "/v1/internal/retention-sweep?mode=delete", "", nil, headers)
	if status != 400 || body["code"] != "confirmation_required" {
		t.Fatalf("delete without confirm = %d %#v, want 400 confirmation_required", status, body)
	}
	if !retentionRowExists(t, h, `SELECT COUNT(*) FROM transactions WHERE id = 'tx_old_delete'`) {
		t.Fatal("unconfirmed delete must not remove rows")
	}

	status, body = h.requestWithHeaders("POST",
		"/v1/internal/retention-sweep?mode=delete&confirm=RETENTION_DELETE", "", nil, headers)
	if status != 200 || body["deleted"] != true {
		t.Fatalf("confirmed delete = %d %#v", status, body)
	}
	if retentionRowExists(t, h, `SELECT COUNT(*) FROM transactions WHERE id = 'tx_old_delete'`) {
		t.Fatal("expired transaction must be deleted")
	}
	if !retentionRowExists(t, h, `SELECT COUNT(*) FROM transactions WHERE id = 'tx_boundary_keep'`) {
		t.Fatal("transaction exactly on the window start must be retained")
	}
}

func retentionRowExists(t *testing.T, h *harness, query string) bool {
	t.Helper()
	var count int
	if err := h.store.DB.QueryRowContext(context.Background(), query).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count > 0
}

// Expired attachment metadata must not stay readable through direct by-id paths, and listings
// without a transaction filter clamp those rows out while keeping in-window rows visible.
func TestRetentionGuardsCoverDerivativeAttachmentPaths(t *testing.T) {
	h := newHarness(t)
	pinRetentionClock(h)
	h.register("retention-attachment@example.test")
	token, _ := h.login("retention-attachment@example.test")
	grantRetentionConsent(t, h, token, "GMAIL_READ")
	ownerID := ownerIDForEmail(t, h, "retention-attachment@example.test")

	insertExpiredTransaction(t, h, ownerID, "tx_expired_att", retentionTestNow.AddDate(-1, -2, 0))
	expiredAttachment, err := h.store.CreateAttachment(context.Background(), ownerID, store.AttachmentInput{
		TransactionID: "tx_expired_att", FileName: "lama.pdf", Mime: "application/pdf",
		SizeBytes: 12, Sha256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		StorageRef: "attachments/2024/01/lama.pdf",
	}, retentionTestNow)
	if err != nil {
		t.Fatal(err)
	}

	// In-window attachment through the public API for the listing contrast.
	status, body := h.request("POST", "/v1/transactions", token, map[string]any{
		"direction": "DEBIT", "amountMinor": 1000, "currency": "IDR",
		"eventAt": "2026-11-18T04:00:00Z",
	})
	if status != 201 {
		t.Fatalf("create transaction = %d %#v", status, body)
	}
	status, created := h.request("POST", "/v1/attachments", token, map[string]any{
		"transactionId": body["id"], "fileName": "baru.pdf", "mimeType": "application/pdf",
		"sizeBytes": 10, "sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		"storageRef": "attachments/2026/11/baru.pdf",
	})
	if status != 201 {
		t.Fatalf("create attachment = %d %#v", status, created)
	}
	knownAttachment := created["id"].(string)

	for _, request := range []struct{ method, path string }{
		{"GET", "/v1/attachments/" + expiredAttachment.ID},
		{"PATCH", "/v1/attachments/" + expiredAttachment.ID},
		{"DELETE", "/v1/attachments/" + expiredAttachment.ID},
	} {
		var payload map[string]any
		if request.method == "PATCH" {
			payload = map[string]any{"fileName": "x.pdf", "revision": 0}
		}
		status, body := h.request(request.method, request.path, token, payload)
		if status != 400 || body["code"] != "outside_retention" {
			t.Fatalf("%s %s = %d %#v, want 400 outside_retention", request.method, request.path, status, body)
		}
	}
	if status, body := h.request("GET", "/v1/attachments/"+knownAttachment, token, nil); status != 200 {
		t.Fatalf("in-window attachment = %d %#v", status, body)
	}

	status, list := h.request("GET", "/v1/attachments", token, nil)
	if status != 200 {
		t.Fatalf("list attachments = %d %#v", status, list)
	}
	items, _ := list["items"].([]any)
	if len(items) != 1 {
		t.Fatalf("unfiltered list = %#v, want only the in-window row", list)
	}
	if got := items[0].(map[string]any)["id"]; got != knownAttachment {
		t.Fatalf("unfiltered list kept %v, want %s", got, knownAttachment)
	}
}

// Import job metadata is period data: reading a job whose month left the window is a 4xx policy
// error, not a successful 200 with stale metadata.
func TestRetentionGuardCoversImportJobRead(t *testing.T) {
	h := newHarness(t)
	pinRetentionClock(h)
	h.register("retention-job@example.test")
	token, _ := h.login("retention-job@example.test")
	grantRetentionConsent(t, h, token, "GMAIL_READ")
	ownerID := ownerIDForEmail(t, h, "retention-job@example.test")

	if _, err := h.store.DB.ExecContext(context.Background(), `INSERT INTO import_jobs
		(id, owner_id, month_id, state, template_version, started_at)
		VALUES ('job_expired', ?, '2024-01', 'COMPLETE', 'v1', ?)`,
		ownerID, retentionTestNow.UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	status, body := h.request("GET", "/v1/import-jobs/job_expired", token, nil)
	if status != 400 || body["code"] != "outside_retention" {
		t.Fatalf("expired import job read = %d %#v, want 400 outside_retention", status, body)
	}

	status, created := h.request("POST", "/v1/import-jobs", token, map[string]any{
		"monthId": "2026-11", "templateVersion": "v1",
	})
	if status != 201 {
		t.Fatalf("in-window import job = %d %#v", status, created)
	}
	if status, _ := h.request("GET", "/v1/import-jobs/"+created["id"].(string), token, nil); status != 200 {
		t.Fatalf("in-window import job read = %d", status)
	}
}
