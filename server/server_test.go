package server_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/hi2shark/go-nowhere/server"
	"github.com/hi2shark/go-nowhere/wire"
)

func TestServerTCPEchoDialUpstream(t *testing.T) {
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echoLn.Close()
	go func() {
		for {
			c, err := echoLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(c)
		}
	}()

	tlsCfg, err := selfSignedTLS("localhost")
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := server.NewConfig("secret", "auto", "now/1", []string{"tcp"})
	if err != nil {
		t.Fatal(err)
	}
	srv := server.NewServer(cfg, tlsCfg, server.NewDialUpstream(nil))

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = srv.Serve(ctx, ln)
	}()
	defer func() {
		cancel()
		_ = srv.Close()
		wg.Wait()
	}()

	clientTLS := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"now/1"},
		MinVersion:         tls.VersionTLS13,
	}
	raw, err := net.DialTimeout("tcp", ln.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	tlsConn := tls.Client(raw, clientTLS)
	if err := tlsConn.Handshake(); err != nil {
		t.Fatal(err)
	}
	defer tlsConn.Close()

	auth, _, err := wire.MakeAuthFrame("secret", cfg.Spec)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tlsConn.Write(auth); err != nil {
		t.Fatal(err)
	}

	target := echoLn.Addr().String()
	req, err := wire.EncodeTCPRequest(target, cfg.Spec)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tlsConn.Write(req); err != nil {
		t.Fatal(err)
	}

	payload := []byte("hello-nowhere")
	if _, err := tlsConn.Write(payload); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len(payload))
	_ = tlsConn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(tlsConn, buf); err != nil {
		t.Fatalf("echo read: %v", err)
	}
	if string(buf) != string(payload) {
		t.Fatalf("got %q want %q", buf, payload)
	}
}

func selfSignedTLS(serverName string) (*tls.Config, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: serverName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{serverName},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"now/1"},
		MinVersion:   tls.VersionTLS13,
	}, nil
}
