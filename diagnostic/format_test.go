package diagnostic

import (
	"strings"
	"testing"
)

func TestFormatEventOmitsZeroFields(t *testing.T) {
	got := FormatEvent(Event{
		Component:   "server",
		Code:        "pair_wait",
		FlowID:      7,
		HalfRole:    "open",
		Transport:   "tcp",
		MissingHalf: "attach",
	})
	for _, part := range []string{
		"nowhere server pair_wait",
		"flow_id=7",
		"half_role=open",
		"transport=tcp",
		"missing_half=attach",
	} {
		if !strings.Contains(got, part) {
			t.Fatalf("FormatEvent() = %q, want substring %q", got, part)
		}
	}
	if strings.Contains(got, "session_id=") || strings.Contains(got, "tls_ms=") {
		t.Fatalf("FormatEvent() included unexpected zero fields: %q", got)
	}
}
