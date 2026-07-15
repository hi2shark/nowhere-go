package wire

import (
	"bytes"
	"errors"
	"io"
	"testing"

	"github.com/hi2shark/nowhere-go/internal/vectors"
)

func TestUOTFramesMatchCorpus(t *testing.T) {
	corpus, err := vectors.LoadUOT()
	if err != nil {
		t.Fatalf("LoadUOT: %v", err)
	}
	for _, tc := range corpus.Cases {
		t.Run(tc.ID, func(t *testing.T) {
			want, err := vectors.DecodeHex(tc.FrameHex)
			if err != nil {
				t.Fatalf("DecodeHex: %v", err)
			}
			if !tc.Valid {
				if _, err := ReadUOTFrame(bytes.NewReader(want)); err == nil {
					t.Fatal("ReadUOTFrame accepted invalid corpus frame")
				}
				return
			}
			payload, err := vectors.DecodeHex(tc.PayloadHex)
			if err != nil {
				t.Fatalf("DecodeHex payload: %v", err)
			}
			frame := UOTFrame{Kind: parseUOTKind(t, tc.Kind), Payload: payload, Code: FlowErrorCode(tc.Code)}
			encoded, err := EncodeUOTFrame(frame)
			if err != nil {
				t.Fatalf("EncodeUOTFrame: %v", err)
			}
			if !bytes.Equal(encoded, want) {
				t.Fatalf("encoded = %x, want %x", encoded, want)
			}
			decoded, err := ReadUOTFrame(bytes.NewReader(want))
			if err != nil {
				t.Fatalf("ReadUOTFrame: %v", err)
			}
			if decoded.Kind != frame.Kind || decoded.Code != frame.Code {
				t.Fatalf("decoded = %+v, want %+v", decoded, frame)
			}
			if frame.Kind == UOTFrameData && !bytes.Equal(decoded.Payload, frame.Payload) {
				t.Fatalf("decoded payload = %x, want %x", decoded.Payload, frame.Payload)
			}
		})
	}
}

func TestReadUOTFrameDistinguishesEmptyDataReadyRejectCloseAndEOF(t *testing.T) {
	cases := []struct {
		frame UOTFrame
	}{
		{UOTFrame{Kind: UOTFrameData}},
		{UOTFrame{Kind: UOTFrameReady}},
		{UOTFrame{Kind: UOTFrameClose}},
		{UOTFrame{Kind: UOTFrameReject, Code: FlowErrorCodeDialFailed}},
	}
	var buf bytes.Buffer
	for _, c := range cases {
		if err := WriteUOTFrame(&buf, c.frame); err != nil {
			t.Fatalf("WriteUOTFrame %+v: %v", c.frame, err)
		}
	}

	for i, want := range cases {
		decoded, err := ReadUOTFrame(&buf)
		if err != nil {
			t.Fatalf("case %d ReadUOTFrame: %v", i, err)
		}
		if decoded.Kind != want.frame.Kind {
			t.Fatalf("case %d kind = %d, want %d", i, decoded.Kind, want.frame.Kind)
		}
	}
	if _, err := ReadUOTFrame(&buf); !errors.Is(err, io.EOF) {
		t.Fatalf("clean EOF = %v, want io.EOF", err)
	}
}

func TestReadUOTFrameTruncationIsUnexpectedEOF(t *testing.T) {
	_, err := ReadUOTFrame(bytes.NewReader([]byte{}))
	if !errors.Is(err, io.EOF) {
		t.Fatalf("empty reader err = %v, want io.EOF", err)
	}
	for _, raw := range [][]byte{
		{byte(UOTFrameData)},
		{byte(UOTFrameData), 0},
		{byte(UOTFrameData), 0, 1},
	} {
		_, err := ReadUOTFrame(bytes.NewReader(raw))
		if !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Fatalf("raw %x err = %v, want io.ErrUnexpectedEOF", raw, err)
		}
	}
	if _, err := ReadUOTFrame(bytes.NewReader([]byte{byte(UOTFrameReject), 0, 0})); err == nil {
		t.Fatal("accepted REJECT with zero length")
	}
}

func TestUOTFrameRejectsInvalidControlPayloads(t *testing.T) {
	cases := []UOTFrame{
		{Kind: 9},
		{Kind: UOTFrameReady, Payload: []byte{1}},
		{Kind: UOTFrameClose, Payload: []byte{1}},
		{Kind: UOTFrameReject},
		{Kind: UOTFrameReject, Code: 0},
		{Kind: UOTFrameReject, Code: 8},
		{Kind: UOTFrameReject, Payload: []byte{1, 2}, Code: FlowErrorCodeDialFailed},
	}
	for _, frame := range cases {
		if _, err := EncodeUOTFrame(frame); err == nil {
			t.Fatalf("EncodeUOTFrame accepted %+v", frame)
		}
	}
}

func parseUOTKind(t *testing.T, value string) UOTFrameKind {
	t.Helper()
	switch value {
	case "data":
		return UOTFrameData
	case "ready":
		return UOTFrameReady
	case "close":
		return UOTFrameClose
	case "reject":
		return UOTFrameReject
	default:
		t.Fatalf("unknown uot kind %q", value)
		return 0
	}
}
