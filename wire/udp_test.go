package wire

import (
	"bytes"
	"strconv"
	"testing"

	"github.com/hi2shark/nowhere-go/internal/vectors"
)

func TestUDPDataFragmentsMatchCorpus(t *testing.T) {
	corpus, err := vectors.LoadUDP()
	if err != nil {
		t.Fatalf("LoadUDP: %v", err)
	}
	for _, tc := range corpus.Cases {
		if tc.Operation != "data" {
			continue
		}
		t.Run(tc.ID, func(t *testing.T) {
			if !tc.Valid {
				t.Skip("negative cases covered by TestDecodeUDPFrameRejectsCorpusNegatives")
			}
			flowID, err := strconv.ParseUint(tc.FlowID, 10, 64)
			if err != nil {
				t.Fatalf("flow_id %q: %v", tc.FlowID, err)
			}
			payload, err := vectors.DecodeHex(tc.PayloadHex)
			if err != nil {
				t.Fatalf("DecodeHex payload: %v", err)
			}
			frames, err := EncodeUDPDataFragments(flowID, tc.PacketID, payload, tc.MaxDatagramSize)
			if err != nil {
				t.Fatalf("EncodeUDPDataFragments: %v", err)
			}
			if len(frames) != len(tc.FramesHex) {
				t.Fatalf("frames = %d, want %d", len(frames), len(tc.FramesHex))
			}
			for i, encoded := range frames {
				want, err := vectors.DecodeHex(tc.FramesHex[i])
				if err != nil {
					t.Fatalf("DecodeHex expected frame: %v", err)
				}
				if !bytes.Equal(encoded, want) {
					t.Fatalf("frame %d = %x, want %x", i, encoded, want)
				}
			}
		})
	}
}

func TestUDPDataFragmentsSplitByDatagramLimit(t *testing.T) {
	payload := bytes.Repeat([]byte{0x5a}, 2500)
	frames, err := EncodeUDPDataFragments(11, 0x10203040, payload, 1200)
	if err != nil {
		t.Fatalf("EncodeUDPDataFragments: %v", err)
	}
	if len(frames) != 3 {
		t.Fatalf("frames = %d, want 3", len(frames))
	}
	var assembled []byte
	for i, frame := range frames {
		if len(frame) > 1200 {
			t.Fatalf("frame %d length %d exceeds limit", i, len(frame))
		}
		decoded, err := DecodeUDPFrame(frame)
		if err != nil {
			t.Fatalf("DecodeUDPFrame frame %d: %v", i, err)
		}
		if decoded.Fragment.FragmentID != uint8(i) {
			t.Fatalf("frame %d id = %d", i, decoded.Fragment.FragmentID)
		}
		if decoded.Fragment.FragmentCount != uint8(len(frames)) {
			t.Fatalf("frame %d count = %d", i, decoded.Fragment.FragmentCount)
		}
		if int(decoded.Fragment.TotalLen) != len(payload) {
			t.Fatalf("frame %d total_len = %d", i, decoded.Fragment.TotalLen)
		}
		assembled = append(assembled, decoded.Fragment.Payload...)
	}
	if !bytes.Equal(assembled, payload) {
		t.Fatal("reassembled payload mismatch")
	}
}

func TestUDPDataFragmentsPreserveEmptyPacket(t *testing.T) {
	frames, err := EncodeUDPDataFragments(5, 6, []byte{}, 64)
	if err != nil {
		t.Fatalf("EncodeUDPDataFragments: %v", err)
	}
	if len(frames) != 1 {
		t.Fatalf("frames = %d, want 1", len(frames))
	}
	decoded, err := DecodeUDPFrame(frames[0])
	if err != nil {
		t.Fatalf("DecodeUDPFrame: %v", err)
	}
	if decoded.Type != UDPFrameData {
		t.Fatalf("type = %d, want DATA", decoded.Type)
	}
	if decoded.Fragment.FragmentCount != 1 || decoded.Fragment.FragmentID != 0 {
		t.Fatalf("fragment metadata wrong: %+v", decoded.Fragment)
	}
	if decoded.Fragment.TotalLen != 0 || len(decoded.Fragment.Payload) != 0 {
		t.Fatalf("empty packet not preserved: %+v", decoded.Fragment)
	}
}

func TestUDPEncodeRejectsInvalidInput(t *testing.T) {
	if _, err := EncodeUDPDataFragments(0, 1, []byte("x"), 64); err == nil {
		t.Fatal("accepted zero flow id")
	}
	if _, err := EncodeUDPDataFragments(1, 0, []byte("x"), 64); err == nil {
		t.Fatal("accepted zero packet id")
	}
	if _, err := EncodeUDPDataFragments(1, 1, bytes.Repeat([]byte{1}, UDPMaxPacketSize+1), 1500); err == nil {
		t.Fatal("accepted oversized payload")
	}
	if _, err := EncodeUDPDataFragments(1, 1, []byte("x"), 21); err == nil {
		t.Fatal("accepted datagram limit smaller than data header")
	}
	if _, err := EncodeUDPClose(0); err == nil {
		t.Fatal("accepted zero flow id for close")
	}
}

func TestDecodeUDPFrameRejectsCorpusNegatives(t *testing.T) {
	corpus, err := vectors.LoadUDP()
	if err != nil {
		t.Fatalf("LoadUDP: %v", err)
	}
	for _, tc := range corpus.Cases {
		if tc.Operation != "decode" {
			continue
		}
		t.Run(tc.ID, func(t *testing.T) {
			if tc.Valid {
				t.Skip("positive decode cases covered by corpus data tests")
			}
			raw, err := vectors.DecodeHex(tc.RawHex)
			if err != nil {
				t.Fatalf("DecodeHex raw: %v", err)
			}
			if _, err := DecodeUDPFrame(raw); err == nil {
				t.Fatalf("DecodeUDPFrame accepted invalid frame (error_code %s)", tc.ErrorCode)
			}
		})
	}
}
