package bundle

import (
	"bytes"
	"context"
	"errors"
	"net"
	"sync"
	"testing"

	"github.com/hi2shark/nowhere-go/carrier"
	"github.com/hi2shark/nowhere-go/carrier/quic"
	"github.com/hi2shark/nowhere-go/wire"
)

func TestUOTDataPlaneRejectsPostSetupControl(t *testing.T) {
	paths := []struct {
		name string
		read func(net.Conn) error
	}{
		{
			name: "symmetric",
			read: func(conn net.Conn) error {
				pc := newUOTPacketConn(conn, &net.UDPAddr{})
				_, _, err := pc.ReadFrom(make([]byte, 16))
				return err
			},
		},
		{
			name: "mixed",
			read: func(conn net.Conn) error {
				lane := &uotLaneDownlink{raw: conn}
				_, err := lane.ReadPacket(make([]byte, 16))
				return err
			},
		},
	}
	controls := []struct {
		name  string
		frame wire.UOTFrame
	}{
		{name: "ready", frame: wire.UOTFrame{Kind: wire.UOTFrameReady}},
		{name: "reject", frame: wire.UOTFrame{Kind: wire.UOTFrameReject, Code: wire.FlowErrorCodeDialFailed}},
	}

	for _, path := range paths {
		for _, control := range controls {
			t.Run(path.name+"/"+control.name, func(t *testing.T) {
				conn := task5UOTFrameConn(t, control.frame)
				if err := path.read(conn); !errors.Is(err, wire.ErrInvalidUOTFrame) {
					t.Fatalf("data-plane %s error = %v, want ErrInvalidUOTFrame", control.name, err)
				}
			})
		}
	}
}

func TestUOTDataPlanePreservesEmptyData(t *testing.T) {
	for _, path := range []string{"symmetric", "mixed"} {
		t.Run(path, func(t *testing.T) {
			conn := task5UOTFrameConn(t, wire.UOTFrame{Kind: wire.UOTFrameData, Payload: []byte{}})
			var (
				n   int
				err error
			)
			switch path {
			case "symmetric":
				pc := newUOTPacketConn(conn, &net.UDPAddr{})
				n, _, err = pc.ReadFrom(make([]byte, 16))
			case "mixed":
				lane := &uotLaneDownlink{raw: conn}
				n, err = lane.ReadPacket(make([]byte, 16))
			}
			if err != nil || n != 0 {
				t.Fatalf("empty DATA read = (%d, %v), want (0, nil)", n, err)
			}
		})
	}
}

func TestUOTDataPlaneWritesEmptyDataFrame(t *testing.T) {
	for _, path := range []string{"symmetric", "mixed"} {
		t.Run(path, func(t *testing.T) {
			conn := &task5RecordingConn{}
			var (
				n   int
				err error
			)
			switch path {
			case "symmetric":
				pc := newUOTPacketConn(conn, &net.UDPAddr{})
				n, err = pc.WriteTo([]byte{}, nil)
			case "mixed":
				lane := &uotLaneUplink{raw: conn}
				n, err = lane.WritePacket([]byte{})
			}
			if err != nil || n != 0 {
				t.Fatalf("empty DATA write = (%d, %v), want (0, nil)", n, err)
			}
			writes, _ := conn.snapshot()
			if len(writes) != 1 {
				t.Fatalf("UoT writes = %d, want one DATA frame", len(writes))
			}
			frame, err := wire.ReadUOTFrame(bytes.NewReader(writes[0]))
			if err != nil {
				t.Fatalf("ReadUOTFrame: %v", err)
			}
			if frame.Kind != wire.UOTFrameData || len(frame.Payload) != 0 {
				t.Fatalf("empty UoT frame = kind %d payload %x", frame.Kind, frame.Payload)
			}
		})
	}
}

func task5UOTFrameConn(t *testing.T, frame wire.UOTFrame) net.Conn {
	t.Helper()
	encoded, err := wire.EncodeUOTFrame(frame)
	if err != nil {
		t.Fatalf("EncodeUOTFrame: %v", err)
	}
	client, server := net.Pipe()
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})
	go func() {
		_, _ = server.Write(encoded)
		_ = server.Close()
	}()
	return client
}

func TestQUICUDPUplinkRefreshesAndRetries(t *testing.T) {
	for _, path := range []string{"symmetric", "mixed"} {
		t.Run(path, func(t *testing.T) {
			const (
				initialMax   = nowuDataHeaderLen + 4
				refreshedMax = nowuDataHeaderLen + 3
			)
			tooLarge := &quic.DatagramTooLargeError{MaxDatagramSize: refreshedMax, Cause: errors.New("test: pmtu changed")}
			session := &task5PMTUSession{
				maxima:     []int{initialMax, refreshedMax},
				sendErrors: []error{nil, tooLarge},
			}
			write := task5QUICUDPWriter(t, path, session)
			payload := []byte("abcdefghij")
			if n, err := write(payload); err != nil || n != len(payload) {
				t.Fatalf("Write = (%d, %v), want (%d, nil)", n, err, len(payload))
			}

			maxCalls, sent := session.snapshot()
			if maxCalls != 2 {
				t.Fatalf("CurrentMaxDatagramSize calls = %d, want 2", maxCalls)
			}
			assertTask5RetriedPacket(t, sent, payload, initialMax, refreshedMax)
		})
	}
}

func TestQUICUDPUplinkSecondTooLargeDropsOnlyCurrentPacket(t *testing.T) {
	for _, path := range []string{"symmetric", "mixed"} {
		t.Run(path, func(t *testing.T) {
			firstTooLarge := &quic.DatagramTooLargeError{MaxDatagramSize: nowuDataHeaderLen + 2, Cause: errors.New("test: first too large")}
			secondTooLarge := &quic.DatagramTooLargeError{MaxDatagramSize: nowuDataHeaderLen + 1, Cause: errors.New("test: second too large")}
			session := &task5PMTUSession{
				maxima:     []int{nowuDataHeaderLen + 4, nowuDataHeaderLen + 2, nowuDataHeaderLen + 64},
				sendErrors: []error{firstTooLarge, secondTooLarge},
			}
			write := task5QUICUDPWriter(t, path, session)

			dropped := []byte("abcdef")
			if n, err := write(dropped); err != nil || n != len(dropped) {
				t.Fatalf("dropped Write = (%d, %v), want (%d, nil)", n, err, len(dropped))
			}
			next := []byte("next")
			if n, err := write(next); err != nil || n != len(next) {
				t.Fatalf("next Write = (%d, %v), want (%d, nil)", n, err, len(next))
			}

			maxCalls, sent := session.snapshot()
			if maxCalls != 3 {
				t.Fatalf("CurrentMaxDatagramSize calls = %d, want 3", maxCalls)
			}
			if len(sent) != 3 {
				t.Fatalf("SendDatagram calls = %d, want 3", len(sent))
			}
			first := task5DecodeUDPFrame(t, sent[0])
			retry := task5DecodeUDPFrame(t, sent[1])
			after := task5DecodeUDPFrame(t, sent[2])
			if first.Fragment.PacketID == 0 || retry.Fragment.PacketID == 0 || after.Fragment.PacketID == 0 {
				t.Fatalf("packet ids must be nonzero: %d, %d, %d", first.Fragment.PacketID, retry.Fragment.PacketID, after.Fragment.PacketID)
			}
			if first.Fragment.PacketID == retry.Fragment.PacketID || retry.Fragment.PacketID == after.Fragment.PacketID || first.Fragment.PacketID == after.Fragment.PacketID {
				t.Fatalf("packet ids were reused: %d, %d, %d", first.Fragment.PacketID, retry.Fragment.PacketID, after.Fragment.PacketID)
			}
			if string(after.Fragment.Payload) != string(next) {
				t.Fatalf("next packet payload = %q, want %q", after.Fragment.Payload, next)
			}
		})
	}
}

func TestQUICUDPUplinkReturnsOtherErrors(t *testing.T) {
	for _, path := range []string{"symmetric", "mixed"} {
		t.Run(path, func(t *testing.T) {
			wantErr := errors.New("test: send failed")
			session := &task5PMTUSession{
				maxima:     []int{nowuDataHeaderLen + 64},
				sendErrors: []error{wantErr},
			}
			write := task5QUICUDPWriter(t, path, session)
			if n, err := write([]byte("payload")); n != 0 || !errors.Is(err, wantErr) {
				t.Fatalf("Write = (%d, %v), want (0, %v)", n, err, wantErr)
			}
		})
	}
}

func TestQUICUDPUplinkEmptyPacketProducesOneDataFragment(t *testing.T) {
	for _, path := range []string{"symmetric", "mixed"} {
		t.Run(path, func(t *testing.T) {
			session := &task5PMTUSession{maxima: []int{nowuDataHeaderLen + 64}}
			write := task5QUICUDPWriter(t, path, session)
			if n, err := write([]byte{}); err != nil || n != 0 {
				t.Fatalf("empty Write = (%d, %v), want (0, nil)", n, err)
			}
			_, sent := session.snapshot()
			if len(sent) != 1 {
				t.Fatalf("SendDatagram calls = %d, want 1", len(sent))
			}
			frame := task5DecodeUDPFrame(t, sent[0])
			if frame.Fragment.PacketID == 0 || frame.Fragment.FragmentID != 0 || frame.Fragment.FragmentCount != 1 || frame.Fragment.TotalLen != 0 || len(frame.Fragment.Payload) != 0 {
				t.Fatalf("empty DATA fragment = %+v", frame.Fragment)
			}
		})
	}
}

func task5QUICUDPWriter(t *testing.T, path string, session carrier.QuicSession) func([]byte) (int, error) {
	t.Helper()
	const flowID = uint64(41)
	prepared := &quicPreparedStream{session: session, id: flowID}
	handle := &qSessionHandle{quic: prepared, flowID: flowID}
	switch path {
	case "symmetric":
		pc := &quicPacketConn{session: handle, flowID: flowID}
		return func(payload []byte) (int, error) { return pc.WriteTo(payload, nil) }
	case "mixed":
		lane := &quicLaneUplink{prep: handle, flowID: flowID}
		return lane.WritePacket
	default:
		t.Fatalf("unknown QUIC UDP path %q", path)
		return nil
	}
}

func assertTask5RetriedPacket(t *testing.T, sent [][]byte, payload []byte, initialMax, refreshedMax int) {
	t.Helper()
	if len(sent) != 6 {
		t.Fatalf("SendDatagram calls = %d, want 2 initial attempts plus 4 retry fragments", len(sent))
	}
	first := task5DecodeUDPFrame(t, sent[0])
	failed := task5DecodeUDPFrame(t, sent[1])
	if first.Fragment.PacketID == 0 || failed.Fragment.PacketID != first.Fragment.PacketID {
		t.Fatalf("initial packet ids = %d, %d", first.Fragment.PacketID, failed.Fragment.PacketID)
	}
	if first.Fragment.FragmentID != 0 || failed.Fragment.FragmentID != 1 {
		t.Fatalf("initial fragment ids = %d, %d, want 0, 1", first.Fragment.FragmentID, failed.Fragment.FragmentID)
	}
	if first.Fragment.FragmentCount != 3 || failed.Fragment.FragmentCount != 3 {
		t.Fatalf("initial fragment counts = %d, %d, want 3", first.Fragment.FragmentCount, failed.Fragment.FragmentCount)
	}
	if len(sent[0]) > initialMax || len(sent[1]) > initialMax {
		t.Fatalf("initial frame lengths = %d, %d, max %d", len(sent[0]), len(sent[1]), initialMax)
	}

	retryID := uint32(0)
	var assembled []byte
	for i, raw := range sent[2:] {
		frame := task5DecodeUDPFrame(t, raw)
		if frame.Fragment.PacketID == first.Fragment.PacketID {
			t.Fatalf("initial attempt continued with fragment %d after TooLarge", frame.Fragment.FragmentID)
		}
		if i == 0 {
			retryID = frame.Fragment.PacketID
			if retryID == 0 {
				t.Fatal("retry packet id is zero")
			}
		}
		if frame.Fragment.PacketID != retryID {
			t.Fatalf("retry frame %d packet id = %d, want %d", i, frame.Fragment.PacketID, retryID)
		}
		if frame.Fragment.FragmentID != uint8(i) || frame.Fragment.FragmentCount != 4 {
			t.Fatalf("retry fragment = id %d count %d, want id %d count 4", frame.Fragment.FragmentID, frame.Fragment.FragmentCount, i)
		}
		if len(raw) > refreshedMax {
			t.Fatalf("retry frame %d length = %d, max %d", i, len(raw), refreshedMax)
		}
		assembled = append(assembled, frame.Fragment.Payload...)
	}
	if string(assembled) != string(payload) {
		t.Fatalf("retried payload = %q, want %q", assembled, payload)
	}
}

func task5DecodeUDPFrame(t *testing.T, raw []byte) wire.UDPFrame {
	t.Helper()
	frame, err := wire.DecodeUDPFrame(raw)
	if err != nil {
		t.Fatalf("DecodeUDPFrame: %v", err)
	}
	if frame.Type != wire.UDPFrameData {
		t.Fatalf("frame type = %d, want DATA", frame.Type)
	}
	return frame
}

type task5PMTUSession struct {
	mu         sync.Mutex
	maxima     []int
	maxCalls   int
	sendErrors []error
	sent       [][]byte
}

func (*task5PMTUSession) PrepareStream(context.Context) (quic.PreparedStream, error) {
	return nil, errors.New("test: unexpected PrepareStream")
}

func (*task5PMTUSession) ReceiveDatagram(context.Context) ([]byte, error) {
	return nil, errors.New("test: unexpected ReceiveDatagram")
}

func (s *task5PMTUSession) CurrentMaxDatagramSize() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	index := s.maxCalls
	s.maxCalls++
	if len(s.maxima) == 0 {
		return 0
	}
	if index >= len(s.maxima) {
		return s.maxima[len(s.maxima)-1]
	}
	return s.maxima[index]
}

func (s *task5PMTUSession) SendDatagram(frame []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	index := len(s.sent)
	s.sent = append(s.sent, append([]byte(nil), frame...))
	if index < len(s.sendErrors) {
		return s.sendErrors[index]
	}
	return nil
}

func (*task5PMTUSession) LocalAddr() net.Addr { return &net.UDPAddr{} }

func (s *task5PMTUSession) snapshot() (int, [][]byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sent := make([][]byte, len(s.sent))
	for i, frame := range s.sent {
		sent[i] = append([]byte(nil), frame...)
	}
	return s.maxCalls, sent
}

var _ carrier.QuicSession = (*task5PMTUSession)(nil)
