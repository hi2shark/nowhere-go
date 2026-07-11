package diagnostic

import (
	"fmt"
	"strings"

	"github.com/hi2shark/nowhere-go/wire"
)

// FormatEvent renders a structured Event as a single log line.
// Zero-valued optional fields are omitted. Host adapters should prefer this
// helper so client and server logs stay correlatable.
func FormatEvent(event Event) string {
	parts := []string{"nowhere", event.Component, event.Code}
	if event.Source != nil {
		parts = append(parts, fmt.Sprintf("source=%v", event.Source))
	}
	if event.Target != "" {
		parts = append(parts, fmt.Sprintf("target=%s", event.Target))
	}
	if event.SessionID != (wire.SessionID{}) {
		parts = append(parts, fmt.Sprintf("session_id=%x", event.SessionID))
	}
	if event.FlowID != 0 {
		parts = append(parts, fmt.Sprintf("flow_id=%d", event.FlowID))
	}
	if event.CarrierID != 0 {
		parts = append(parts, fmt.Sprintf("carrier_id=%d", event.CarrierID))
	}
	if event.HalfRole != "" {
		parts = append(parts, fmt.Sprintf("half_role=%s", event.HalfRole))
	}
	if event.Transport != "" {
		parts = append(parts, fmt.Sprintf("transport=%s", event.Transport))
	}
	if event.Stage != "" {
		parts = append(parts, fmt.Sprintf("stage=%s", event.Stage))
	}
	if event.MissingHalf != "" {
		parts = append(parts, fmt.Sprintf("missing_half=%s", event.MissingHalf))
	}
	if event.DialQueueMs != 0 {
		parts = append(parts, fmt.Sprintf("dial_queue_ms=%d", event.DialQueueMs))
	}
	if event.RawDialMs != 0 {
		parts = append(parts, fmt.Sprintf("raw_dial_ms=%d", event.RawDialMs))
	}
	if event.TLSms != 0 {
		parts = append(parts, fmt.Sprintf("tls_ms=%d", event.TLSms))
	}
	if event.AuthMs != 0 {
		parts = append(parts, fmt.Sprintf("auth_ms=%d", event.AuthMs))
	}
	if event.PairWaitMs != 0 {
		parts = append(parts, fmt.Sprintf("pair_wait_ms=%d", event.PairWaitMs))
	}
	if event.ContextCause != "" {
		parts = append(parts, fmt.Sprintf("context_cause=%q", event.ContextCause))
	}
	if event.Outcome != "" {
		parts = append(parts, fmt.Sprintf("outcome=%s", event.Outcome))
	}
	if event.Count != 0 {
		parts = append(parts, fmt.Sprintf("count=%d", event.Count))
	}
	if event.Err != nil {
		parts = append(parts, fmt.Sprintf("error=%q", event.Err.Error()))
	}
	return strings.Join(parts, " ")
}
