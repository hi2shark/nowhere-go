package server

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/hi2shark/nowhere-go/wire"
)

func BenchmarkFlowPairTCP(b *testing.B) {
	header := wire.FlowHeader{
		Role: wire.FlowRoleOpen, FlowID: 1, Kind: wire.FlowKindTCP,
		Uplink: wire.CarrierTCP, Downlink: wire.CarrierUDP,
	}
	for i := 0; i < b.N; i++ {
		manager := newFlowPairManager(time.Second)
		left1, right1 := net.Pipe()
		left2, right2 := net.Pipe()
		header.FlowID = uint64(i + 1)
		done := make(chan struct{})
		go func() {
			_, _ = manager.SubmitTCP(context.Background(), wire.SessionID{1}, header, "example.com:443", left1)
			close(done)
		}()
		attach := header
		attach.Role = wire.FlowRoleAttach
		paired, _ := manager.SubmitTCP(context.Background(), wire.SessionID{1}, attach, "example.com:443", left2)
		if paired != nil {
			_ = paired.Close()
		}
		<-done
		_ = right1.Close()
		_ = right2.Close()
		manager.Close()
	}
}
