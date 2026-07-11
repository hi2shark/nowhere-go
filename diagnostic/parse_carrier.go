package diagnostic

import (
	"strconv"
	"strings"
)

// ParseCarrierLog converts legacy "[Nowhere] [carrier] <event> k=v ..." printf
// lines into a structured Event skeleton (Code + common fields).
func ParseCarrierLog(msg string) Event {
	msg = strings.TrimSpace(msg)
	for _, prefix := range []string{"[Nowhere] [carrier] ", "[Nowhere] "} {
		msg = strings.TrimPrefix(msg, prefix)
	}
	msg = strings.TrimSpace(msg)
	ev := Event{
		Level:     LevelDebug,
		Component: "tcptls",
		Carrier:   CarrierTCPTLS,
	}
	if msg == "" {
		ev.Code = "carrier_debug"
		return ev
	}
	fields := strings.Fields(msg)
	if len(fields) == 0 {
		ev.Code = "carrier_debug"
		return ev
	}
	ev.Code = fields[0]
	for _, field := range fields[1:] {
		key, val, ok := strings.Cut(field, "=")
		if !ok {
			continue
		}
		switch key {
		case "flow_id":
			ev.FlowID = parseUint(val)
		case "carrier_id":
			ev.CarrierID = parseUint(val)
		case "target":
			ev.Target = val
		case "network":
			ev.Transport = val
		case "stage":
			ev.Stage = val
		case "outcome":
			ev.Outcome = val
			ev.Result = mapOutcomeResult(val)
		case "raw_dial_ms":
			ev.RawDialMs = parseInt64(val)
		case "tls_ms":
			ev.TLSms = parseInt64(val)
		case "auth_write_ms", "auth_ms":
			ev.AuthMs = parseInt64(val)
		case "rx_bytes":
			ev.RxBytes = parseUint(val)
		case "tx_bytes":
			ev.TxBytes = parseUint(val)
		case "first_byte_ms":
			ev.FirstByteMs = parseInt64(val)
		case "close_reason":
			ev.CloseReason = val
			if val == "ok" {
				ev.Result = ResultOK
			} else if val == ErrorClassRemoteClose || val == ErrorClassLocalCancel || val == ErrorClassNetwork || val == ErrorClassProtocol || val == ErrorClassProbeClose {
				ev.ErrorClass = val
				if val == ErrorClassLocalCancel || val == ErrorClassRemoteClose {
					ev.Result = ResultCanceled
				} else {
					ev.Result = ResultFailed
				}
			} else {
				ev.Result, ev.ErrorClass = ClassifyClose(errString(val))
			}
		case "role":
			ev.HalfRole = val
		case "elapsed_ms", "open_total_ms", "delay_ms", "next_retry_ms", "pair_wait_ms":
			if ev.PairWaitMs == 0 && key == "pair_wait_ms" {
				ev.PairWaitMs = parseInt64(val)
			}
		}
	}
	if ev.Result == "" {
		if strings.Contains(ev.Code, "failed") || strings.HasSuffix(ev.Outcome, "_failed") {
			ev.Result = ResultFailed
		}
	}
	return ev
}

type errString string

func (e errString) Error() string { return string(e) }

func parseUint(s string) uint64 {
	n, _ := strconv.ParseUint(s, 10, 64)
	return n
}

func parseInt64(s string) int64 {
	n, _ := strconv.ParseInt(s, 10, 64)
	return n
}

func mapOutcomeResult(outcome string) string {
	switch {
	case outcome == "" || outcome == "warm" || outcome == "fresh" || outcome == "warm_prepare":
		return ResultOK
	case strings.Contains(outcome, "failed"), strings.Contains(outcome, "throttled"):
		if strings.Contains(outcome, "cancel") {
			return ResultCanceled
		}
		return ResultFailed
	case strings.Contains(outcome, "cancel"):
		return ResultCanceled
	default:
		return ""
	}
}
