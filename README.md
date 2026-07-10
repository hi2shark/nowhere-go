# Nowhere-Go

Go implementation of the [Nowhere](https://github.com/NodePassProject/Nowhere) v1 protocol — both **outbound** (client) and **inbound** (server). The v0.3 line targets upstream **v1.3.3** (`962408bd`) and remains an integration preview.

This is a library, not a standalone proxy. Hosts such as [sing-box](https://github.com/SagerNet/sing-box) or [mihomo](https://github.com/MetaCubeX/mihomo) import it and supply platform pieces: TLS material, dialers, QUIC stacks, and routing.

Protocol behavior follows the official Rust project:

- Spec: [protocol.md](https://github.com/NodePassProject/Nowhere/blob/main/docs/protocol.md)
- Integration notes: [integrations.md](https://github.com/NodePassProject/Nowhere/blob/main/docs/integrations.md)

```text
module github.com/hi2shark/nowhere-go
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
nowhere-go/
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
2. Build an immutable `tcptls.Config` with host dialers.
3. If either direction is UDP, inject a `carrier.QuicBackend`.
4. Open flows through `bundle.CarrierBundle`.

```go
import (
    "github.com/hi2shark/nowhere-go/bundle"
    "github.com/hi2shark/nowhere-go/carrier/tcptls"
    "github.com/hi2shark/nowhere-go/wire"
)

spec, err := wire.BuildEffectiveSpec(password, userSpec, wire.DefaultALPN)
if err != nil {
    return err
}

tcp, err := tcptls.NewConfig(tcptls.TCPOptions{
	Address:   serverAddr,
	Spec:      spec,
	Key:       password,
	Dialer:    hostTCPDialer,
	TLSDialer: hostTLSDialer,
	Observer:  hostObserver,
})
if err != nil {
	return err
}

up, down := wire.CarrierTCP, wire.CarrierUDP
b, err := bundle.NewCarrierBundle(bundle.BundleOptions{
	TCP:      tcp,
	QUIC:     hostQuicBackend, // required when Up or Down is CarrierUDP
	PoolSize: pool,            // meaningful for tcp/tcp; UDP matrices use 0
	Up:       up,
	Down:     down,
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

    "github.com/hi2shark/nowhere-go/server"
)

cfg, err := server.NewConfig(server.ConfigOptions{
	Password: password,
	Spec:     userSpec,
	ALPN:     "now/1",
	Networks: []server.Network{server.NetworkTCP},
})
if err != nil {
    return err
}

srv, err := server.NewServer(server.ServerOptions{
	Config:       cfg,
	TLS:          tlsConfig,
	Upstream:     server.NewDialUpstream(nil),
	Observer:     hostObserver,
	QUICListener: hostQuicListener, // required only when UDP is enabled
})
if err != nil {
	return err
}
return srv.ListenAndServe(ctx, ":443")
```

`Networks`: `NetworkTCP`, `NetworkUDP`, both, or empty (defaults to both). Unknown and duplicate entries are rejected.
UDP without `QuicListener` returns `server.ErrQUICNotConfigured`.

### B. Host-owned listener (e.g. sing-box)

Keep your own accept / TLS / QUIC stack. After the carrier is ready, call the protocol handler:

```go
h, err := server.NewHandler(server.HandlerOptions{
	Config:   cfg,
	Upstream: routerUpstream, // adapts host RouteConnection / RoutePacket
	Observer: hostObserver,
})
if err != nil {
	return err
}
err = h.ServeTCP(ctx, rawConn, remoteAddr, hostTLSHandshake, onClose)
```

QUIC: adapt your connection to `server.QuicConn` / `server.QuicListener`, then call `Handler.ServeQUIC` or `Server.ServeQUIC`.

### Upstream interface

```go
type Upstream interface {
    HandleStream(ctx context.Context, conn net.Conn, source net.Addr, target string) error
    HandlePacket(ctx context.Context, pc net.PacketConn, source net.Addr, target string) error
}
```

On success the Upstream owns the wrapped connection lifecycle. Closing the wrapper or invoking the context `CloseHandler` closes every physical carrier and invokes each host callback exactly once. Normal close passes `nil`; terminal failures pass their cause. Callbacks run synchronously after close, must not block, and panics are isolated and reported to the Observer.

### Default server guardrails

- Authentication: 5 seconds with `[0.8, 1.2]` jitter; request idle: 40 seconds
- Pending asymmetric pairs: 1024 per session, 4096 global; timeout: 5 seconds
- QUIC UDP: 256 flows/session, 64 packets/flow, 4 MiB queued/session, 120 second idle
- Active QUIC sessions: 1024; a matching session ID replaces the previous carrier

---

## Design boundaries

| In nowhere-go | In the host |
|---|---|
| Wire codecs and session/flow state machines | Listen addresses, certs, ALPN product policy |
| TLS/TCP pool logic (dialers injected) | Actual `net.Dial` / TLS stacks |
| Inbound Handler + pairing + UoT | Router / firewall / detour |
| QUIC *interfaces* | QUIC *implementations* |

Local development against a monorepo checkout:

```go
replace github.com/hi2shark/nowhere-go => ../nowhere-go
```

---

## Develop & CI

```bash
go test ./...
go test -race -shuffle=on -count=20 ./...
go vet ./...
staticcheck ./...
go run ./cmd/nowhere-check            # wire vectors + self-check
go run ./cmd/nowhere-check -version
```

GitHub Actions ([`.github/workflows/ci.yml`](.github/workflows/ci.yml)) validates Go **1.20.x / 1.24.x / stable** for push, PR, and `workflow_dispatch`. No release binaries are published — consume the module with `go get`.

```bash
go get github.com/hi2shark/nowhere-go@latest
```
