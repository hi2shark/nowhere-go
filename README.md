# Go-Nowhere

Go implementation of the [Nowhere](https://github.com/NodePassProject/Nowhere) v1 protocol — both **outbound** (client) and **inbound** (server).

This is a library, not a standalone proxy. Hosts such as [sing-box](https://github.com/SagerNet/sing-box) or [mihomo](https://github.com/MetaCubeX/mihomo) import it and supply platform pieces: TLS material, dialers, QUIC stacks, and routing.

Protocol behavior follows the official Rust project:

- Spec: [protocol.md](https://github.com/NodePassProject/Nowhere/blob/main/docs/protocol.md)
- Integration notes: [integrations.md](https://github.com/NodePassProject/Nowhere/blob/main/docs/integrations.md)

```text
module github.com/hi2shark/go-nowhere
go 1.20
```

License: **GPL-3.0** (same family as upstream Nowhere).

---

## What you get

| Side | Packages | Responsibility |
|---|---|---|
| Shared wire | `wire` | Spec derivation, auth frames, TCP request, UDP compact, UoT, flow headers |
| Outbound | `carrier/tcptls`, `carrier/quic`, `bundle` | Connection pool, injected QUIC dial backend, four-matrix session orchestration |
| Inbound | `server` | Listen / accept orchestration, auth, asymmetric pairing, UoT, QUIC session loop, upstream handoff |

Hosts keep:

- Concrete QUIC (`quic-go`, `sing-quic`, …) behind injected interfaces
- Product config schemas, listeners, certificates, and routers
- Zero reverse dependency: this module never imports mihomo or sing-box

---

## Package map

```text
go-nowhere/
├── wire/              # codec + EffectiveSpec
├── carrier/
│   ├── tcptls/        # TLS/TCP pool (TCPDialer / TlsDialer injected)
│   └── quic/          # outbound QuicBackend interfaces (no implementation)
├── bundle/            # outbound CarrierBundle (up/down = tcp|udp)
├── server/            # inbound Server / Handler / Upstream
├── cmd/nowhere-check/ # CI helper (vectors / version) — not a proxy
├── testdata/vectors/
└── tests/
```

Prefer importing subpackages. The root package only re-exports a few `wire` symbols for convenience.

---

## Outbound (client)

Typical path used by mihomo / sing-box outbound adapters:

1. Build `wire.EffectiveSpec` from shared password, `spec`, and ALPN.
2. Configure `tcptls.TCPConnConfig` with host dialers.
3. If either direction is UDP, inject a `carrier.QuicBackend`.
4. Open flows through `bundle.CarrierBundle`.

```go
import (
    "github.com/hi2shark/go-nowhere/bundle"
    "github.com/hi2shark/go-nowhere/carrier/tcptls"
    "github.com/hi2shark/go-nowhere/wire"
)

spec, err := wire.BuildEffectiveSpec(password, userSpec, wire.DefaultALPN)
if err != nil {
    return err
}

tcp := &tcptls.TCPConnConfig{
    Addr:      serverAddr,
    Spec:      spec,
    Key:       password,
    Dialer:    hostTCPDialer,
    TLSDialer: hostTLSDialer,
}

b, err := bundle.NewCarrierBundle(&bundle.BundleConfig{
    TCP:      tcp,
    Quic:     hostQuicBackend, // required when Up or Down is "udp"
    PoolSize: pool,            // meaningful for tcp/tcp; UDP matrices use 0
    Up:       "tcp",
    Down:     "udp",
})
if err != nil {
    return err
}
defer b.Close()

conn, err := b.AsymmetricOpenTCP(ctx, "example.com:443")
```

Supported `Up`/`Down` pairs: `tcp/tcp`, `udp/udp`, `tcp/udp`, `udp/tcp`.

---

## Inbound (server)

The `server` package is a full inbound implementation: auth, request decode, symmetric relay handoff, UoT, asymmetric FLOW_OPEN/ATTACH pairing, and QUIC session handling.

Two integration styles:

### A. Standalone Portal-like process

`server.Server` owns TCP accept + `crypto/tls` handshake, then runs the protocol. Forwarding goes to an `Upstream` — use `NewDialUpstream` for dial-and-copy, or plug in your own router.

```go
import (
    "crypto/tls"

    "github.com/hi2shark/go-nowhere/server"
)

cfg, err := server.NewConfig(password, userSpec, "now/1", []string{"tcp"})
if err != nil {
    return err
}

srv := server.NewServer(cfg, tlsConfig, server.NewDialUpstream(nil))
// Optional: srv.Logger = ...
// For UDP: set srv.QuicListener to a host adapter, networks include "udp"
return srv.ListenAndServe(ctx, ":443")
```

`networks`: `"tcp"`, `"udp"`, both, or empty (defaults to both).  
UDP without `QuicListener` returns `server.ErrQUICNotConfigured`.

### B. Host-owned listener (e.g. sing-box)

Keep your own accept / TLS / QUIC stack. After the carrier is ready, call the protocol handler:

```go
h := &server.Handler{
    Config:   cfg,
    Upstream: routerUpstream, // adapts host RouteConnection / RoutePacket
    Pairing:  server.NewFlowPairManager(0),
    Sessions: server.NewSessionManager(),
}
h.HandleConnWithClose(ctx, tlsConn, remoteAddr, onClose)
```

QUIC: adapt your `quic-go` connection to `server.QuicConn` / `server.QuicListener`, then `Handler.ServeQuicConn` or `Server.ServeQUIC`.

### Upstream interface

```go
type Upstream interface {
    HandleStream(ctx context.Context, conn net.Conn, source net.Addr, target string) error
    HandlePacket(ctx context.Context, pc net.PacketConn, source net.Addr, target string) error
}
```

On success the Upstream owns the connection lifecycle.

---

## Design boundaries

| In go-nowhere | In the host |
|---|---|
| Wire codecs and session/flow state machines | Listen addresses, certs, ALPN product policy |
| TLS/TCP pool logic (dialers injected) | Actual `net.Dial` / TLS stacks |
| Inbound Handler + pairing + UoT | Router / firewall / detour |
| QUIC *interfaces* | QUIC *implementations* |

Local development against a monorepo checkout:

```go
replace github.com/hi2shark/go-nowhere => ../go-nowhere
```

---

## Develop & CI

```bash
go test ./...
go vet ./...
go run ./cmd/nowhere-check            # wire vectors + self-check
go run ./cmd/nowhere-check -version
```

GitHub Actions ([`.github/workflows/ci.yml`](.github/workflows/ci.yml)) runs the same on Go **1.20 / 1.22 / 1.24** for push, PR, and `workflow_dispatch`. No release binaries are published — consume the module with `go get`.

```bash
go get github.com/hi2shark/go-nowhere@latest
```
