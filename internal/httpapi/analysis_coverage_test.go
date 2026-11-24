package httpapi

import "testing"

// P2 UAT regression: GET /v1/summaries/2026-11 can report coverage EMPTY/FAILED; the app forwards
// that enum in the analysis payload. POST /v1/analyses must accept it (fake provider, no real call)
// instead of answering 400 payload.coverage is invalid.
func TestAnalysisAcceptsEmptyAndFailedCoverage(t *testing.T) {
	provider := &captureProvider{}
	h := newHarnessWithProvider(t, provider)
	h.register("coverage-payload@example.test")
	token, _ := h.login("coverage-payload@example.test")
	food := h.category(token, "food")
	if status, body := h.request("POST", "/v1/transactions", token, map[string]any{
		"direction": "DEBIT", "amountMinor": 1_000, "currency": "IDR",
		"eventAt": "2026-11-19T04:10:00Z", "categoryId": food,
	}); status != 201 {
		t.Fatalf("seed: %d %#v", status, body)
	}
	if status, _ := h.request("POST", "/v1/consents", token, map[string]any{
		"purpose": "AI_PROCESSING", "decision": "GRANTED", "noticeVersion": "v0.4-review",
	}); status != 201 {
		t.Fatal("AI consent")
	}

	for i, coverage := range []string{"EMPTY", "FAILED"} {
		payload := sampleAnalysisPayload("2026-11")
		payload["coverage"] = coverage
		status, body := h.requestWithHeaders("POST", "/v1/analyses", token, map[string]any{
			"monthId": "2026-11", "inputRevision": 1, "payload": payload,
		}, map[string]string{"Idempotency-Key": "coverage-" + string(rune('a'+i))})
		if status != 200 {
			t.Fatalf("coverage %s: %d %#v", coverage, status, body)
		}
		if body["promptVersion"] != "analysis-v1" {
			t.Fatalf("coverage %s analysis: %#v", coverage, body)
		}
	}

	invalid := sampleAnalysisPayload("2026-11")
	invalid["coverage"] = "TIDAK_VALID"
	status, body := h.requestWithHeaders("POST", "/v1/analyses", token, map[string]any{
		"monthId": "2026-11", "inputRevision": 1, "payload": invalid,
	}, map[string]string{"Idempotency-Key": "coverage-invalid"})
	if status != 400 || body["message"] != "payload.coverage is invalid" {
		t.Fatalf("invalid coverage: %d %#v", status, body)
	}
}
