# Contributing

Protocol changes must update the upstream specification/reference implementation first, export fixed Rust vectors, synchronize the workspace vector corpus, and then update Go codecs. Do not introduce a second hand-maintained set of wire hex values.

Before submitting a change, run:

```sh
go test ./...
go test -race -shuffle=on -count=20 ./...
go vet ./...
staticcheck ./...
go run ./cmd/nowhere-check
```

Changes to pairing, session, pool, or close ownership require deterministic cancellation/timeout tests. Runtime packages must retain zero third-party dependencies.
