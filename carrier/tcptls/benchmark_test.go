package tcptls

import (
	"context"
	"testing"

	"github.com/hi2shark/go-nowhere/wire"
)

func BenchmarkTCPPoolFreshAcquire(b *testing.B) {
	spec, _ := wire.BuildEffectiveSpec("k", "auto", "now/1")
	config, err := NewConfig(TCPOptions{
		Address: "127.0.0.1:1", Spec: spec, Key: "k",
		Dialer: &recordingTCPDialer{}, TLSDialer: passthroughTLSDialer{},
	})
	if err != nil {
		b.Fatal(err)
	}
	pool := NewTCPPool(config, 0)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		conn, err := pool.Acquire(context.Background(), "example.com:443", TCPRelayTCP)
		if err != nil {
			b.Fatal(err)
		}
		_ = conn.Close()
	}
}
