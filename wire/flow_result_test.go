package wire

import (
	"bytes"
	"errors"
	"testing"

	"github.com/hi2shark/nowhere-go/internal/vectors"
)

func TestFlowCorpusResults(t *testing.T) {
	corpus, err := vectors.LoadFlow()
	if err != nil {
		t.Fatalf("LoadFlow: %v", err)
	}
	for _, tc := range corpus.Cases {
		if tc.Operation != "flow_result" {
			continue
		}
		t.Run(tc.ID, func(t *testing.T) {
			frame, err := vectors.DecodeHex(tc.FrameHex)
			if err != nil {
				t.Fatalf("DecodeHex: %v", err)
			}
			if !tc.Valid {
				if _, err := ReadFlowResult(bytes.NewReader(frame)); err == nil {
					t.Fatal("ReadFlowResult accepted invalid corpus frame")
				}
				return
			}
			result := FlowResult{Status: parseFlowStatus(t, tc.Status), Code: FlowErrorCode(tc.Code)}
			encoded, err := WriteFlowResult(result)
			if err != nil {
				t.Fatalf("WriteFlowResult: %v", err)
			}
			if !bytes.Equal(encoded[:], frame) {
				t.Fatalf("encoded = %x, want corpus %x", encoded, frame)
			}
			decoded, err := ReadFlowResult(bytes.NewReader(frame))
			if err != nil {
				t.Fatalf("ReadFlowResult: %v", err)
			}
			if decoded != result {
				t.Fatalf("decoded = %+v, want %+v", decoded, result)
			}
		})
	}

	if FlowResultLen != 4 {
		t.Fatalf("FlowResultLen = %d, want 4", FlowResultLen)
	}
	smoke, err := WriteFlowResult(FlowResult{Status: FlowStatusReady})
	if err != nil {
		t.Fatal(err)
	}
	if smoke[0] != 0xf2 {
		t.Fatalf("result magic = %#x, want 0xf2", smoke[0])
	}
}

func TestFlowResultRejectsInvalidStatusCode(t *testing.T) {
	cases := []FlowResult{
		{Status: FlowStatusReady, Code: FlowErrorCodeInvalidRequest},
		{Status: FlowStatusReject, Code: 0},
		{Status: FlowStatusReject, Code: 8},
		{Status: 9, Code: 0},
	}
	for _, result := range cases {
		if _, err := WriteFlowResult(result); err == nil {
			t.Fatalf("WriteFlowResult accepted %+v", result)
		}
	}
}

func TestFlowErrorSupportsErrorsAsAndUnwrap(t *testing.T) {
	if err := (FlowResult{Status: FlowStatusReady}).Err(true); err != nil {
		t.Fatalf("ready Err = %v, want nil", err)
	}

	err := (FlowResult{Status: FlowStatusReject, Code: FlowErrorCodePairTimeout}).Err(true)
	var flowErr *FlowError
	if !errors.As(err, &flowErr) {
		t.Fatalf("errors.As(%T) failed", err)
	}
	if flowErr.Code != FlowErrorCodePairTimeout || !flowErr.Remote {
		t.Fatalf("FlowError = %+v", flowErr)
	}

	cause := errors.New("dial failed")
	wrapped := &FlowError{Code: FlowErrorCodeDialFailed, Cause: cause}
	if !errors.Is(wrapped, cause) {
		t.Fatal("FlowError does not unwrap Cause")
	}
}

func TestFlowResultErrRejectsInvalidResultBeforeTyping(t *testing.T) {
	cases := []FlowResult{
		{Status: FlowStatusReady, Code: FlowErrorCodeInvalidRequest},
		{Status: FlowStatusReject, Code: 0},
		{Status: FlowStatusReject, Code: 8},
		{Status: 9, Code: FlowErrorCodePairTimeout},
	}
	for _, result := range cases {
		err := result.Err(true)
		if !errors.Is(err, ErrInvalidFlowResult) {
			t.Fatalf("%+v Err = %v, want ErrInvalidFlowResult", result, err)
		}
		var flowErr *FlowError
		if errors.As(err, &flowErr) {
			t.Fatalf("%+v Err exposed malformed result as FlowError: %+v", result, flowErr)
		}
	}
}

func parseFlowStatus(t *testing.T, value string) FlowStatus {
	t.Helper()
	switch value {
	case "ready":
		return FlowStatusReady
	case "reject":
		return FlowStatusReject
	default:
		t.Fatalf("unknown flow status %q", value)
		return 0
	}
}
