//go:build !go1.24

package bundle

import (
	"crypto/rand"
	"errors"
	"io"
	"testing"

	"github.com/hi2shark/go-nowhere/wire"
)

func TestCarrierBundleSessionIDRandomErrorPersists(t *testing.T) {
	oldReader := rand.Reader
	wantErr := errors.New("test: random failed")
	rand.Reader = errReader{fill: 0x7f, err: wantErr}
	t.Cleanup(func() { rand.Reader = oldReader })

	bundle, err := NewCarrierBundle(BundleOptions{
		QUIC: &stubQuicBackend{},
		TCP:  testBundleTCPConfig(t),
		Up:   wire.CarrierTCP,
		Down: wire.CarrierUDP,
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("NewCarrierBundle = %v, %v; want error %v", bundle, err, wantErr)
	}
}

type errReader struct {
	fill byte
	err  error
}

func (r errReader) Read(p []byte) (int, error) {
	if len(p) > 0 {
		p[0] = r.fill
		return 1, r.err
	}
	return 0, r.err
}

var _ io.Reader = errReader{}
