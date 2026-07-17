package wire

import (
	"bytes"
	"testing"
)

func FuzzValidateAuthFrame(f *testing.F) {
	credentials, err := NewCredentials("fuzz-secret")
	if err != nil {
		f.Fatal(err)
	}
	var exporter TLSExporter
	for index := range exporter {
		exporter[index] = byte(index)
	}
	frame := EncodeAuthFrame(credentials, AuthTransportTLSTCP, exporter, SessionID{1})
	f.Add(frame[:])
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, input []byte) {
		_, _ = ValidateAuthFrame(input, credentials, AuthTransportTLSTCP, exporter)
	})
}

func FuzzReadFlowHeader(f *testing.F) {
	f.Add([]byte{0, 0, 0, 0, 1})
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, input []byte) {
		_, _ = ReadFlowHeader(bytes.NewReader(input))
	})
}

func FuzzDecodeUDPFrame(f *testing.F) {
	f.Add([]byte{byte(UDPFrameTypeData), 0, 0, 0, 1})
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, input []byte) {
		_, _ = DecodeUDPFrame(input)
	})
}

func FuzzReadUDPPacket(f *testing.F) {
	f.Add([]byte{0, 0})
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, input []byte) {
		_, _ = ReadUDPPacket(bytes.NewReader(input))
	})
}
