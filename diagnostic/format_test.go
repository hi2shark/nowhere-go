package diagnostic

import (
	"strings"
	"testing"
)

func TestFormatEventOmitsZeroFields(t *testing.T) {
	got := FormatEvent(Event{
		Component:   "server",
		Code:        "pair_wait",
		Carrier:     CarrierTCPTLS,
		FlowID:      7,
		HalfRole:    "open",
		Transport:   "tcp",
		MissingHalf: "attach",
		Result:      ResultOK,
	})
	for _, part := range []string{
		"nowhere",
		"component=server",
		"carrier=tcp_tls",
		"event=pair_wait",
		"flow_id=7",
		"received_half=open",
		"received_transport=tcp",
		"missing_half=attach",
		"result=ok",
	} {
		if !strings.Contains(got, part) {
			t.Fatalf("FormatEvent() = %q, want substring %q", got, part)
		}
	}
	if strings.Contains(got, "session_id=") || strings.Contains(got, "tls_ms=") {
		t.Fatalf("FormatEvent() included unexpected zero fields: %q", got)
	}
}

func TestParseCarrierLogStripsPrefix(t *testing.T) {
	ev := ParseCarrierLog("[Nowhere] [carrier] relay_end flow_id=9 carrier_id=3 network=tcp target=h:1 first_byte_ms=12 rx_bytes=10 tx_bytes=20 close_reason=ok")
	if ev.Code != "relay_end" || ev.FlowID != 9 || ev.CarrierID != 3 || ev.Result != ResultOK {
		t.Fatalf("ParseCarrierLog = %+v", ev)
	}
	if ev.FirstByteMs != 12 || ev.RxBytes != 10 || ev.TxBytes != 20 {
		t.Fatalf("byte fields = %+v", ev)
	}
	if ev.Component != "tcptls" || ev.Carrier != CarrierTCPTLS {
		t.Fatalf("carrier meta = component=%s carrier=%s", ev.Component, ev.Carrier)
	}
}

func TestFormatEventPairTimeoutKeys(t *testing.T) {
	got := FormatEvent(Event{
		Component:         "server",
		Code:              "pair_timeout",
		Carrier:           CarrierTCPTLS,
		FlowID:            3,
		ReceivedHalf:      "open",
		MissingHalf:       "attach",
		Transport:         "tcp",
		ExpectedTransport: "quic",
		Result:            ResultTimeout,
		ErrorClass:        ErrorClassNetwork,
		PairWaitMs:        5000,
	})
	for _, part := range []string{
		"event=pair_timeout",
		"received_half=open",
		"missing_half=attach",
		"received_transport=tcp",
		"expected_transport=quic",
		"result=timeout",
		"error_class=network",
		"pair_wait_ms=5000",
	} {
		if !strings.Contains(got, part) {
			t.Fatalf("FormatEvent() = %q, want %q", got, part)
		}
	}
}

func TestClassifyCloseLocalCancel(t *testing.T) {
	result, class := ClassifyClose(errString("stream 5 canceled by local with error code 256"))
	if result != ResultCanceled || class != ErrorClassLocalCancel {
		t.Fatalf("ClassifyClose = %s/%s", result, class)
	}
}
