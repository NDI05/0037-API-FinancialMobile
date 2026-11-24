package analysis

import (
	"fmt"
	"testing"
)

// The analysis payload coverage must accept the same domain enum the summary endpoint returns
// (COMPLETE|PARTIAL|EMPTY|FAILED) so the app can request an analysis for an empty/failed coverage
// month. UNKNOWN is kept for the legacy client envelope.
func TestParseClientPayloadCoverageEnum(t *testing.T) {
	for _, coverage := range []string{"COMPLETE", "PARTIAL", "EMPTY", "FAILED", "UNKNOWN"} {
		raw := []byte(fmt.Sprintf(`{"schemaVersion":1,"monthId":"2026-11","coverage":%q}`, coverage))
		payload, err := ParseClientPayload(raw)
		if err != nil {
			t.Fatalf("coverage %s rejected: %v", coverage, err)
		}
		if payload.Coverage != coverage {
			t.Fatalf("coverage %s parsed as %s", coverage, payload.Coverage)
		}
	}
	for _, coverage := range []string{"", "COMPLETED", "complete", "unknown", "EMPTY_FAILED"} {
		raw := []byte(fmt.Sprintf(`{"schemaVersion":1,"monthId":"2026-11","coverage":%q}`, coverage))
		if _, err := ParseClientPayload(raw); err == nil {
			t.Fatalf("invalid coverage %q accepted", coverage)
		}
	}
}
