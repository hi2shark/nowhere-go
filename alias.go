package nowhere

import "github.com/hi2shark/nowhere-go/wire"

// Convenience re-exports; prefer importing wire directly in new code.

const (
	DefaultALPN  = wire.DefaultALPN
	DefaultSpec  = wire.DefaultSpec
	SessionIDLen = wire.SessionIDLen
)

type SessionID = wire.SessionID
type EffectiveSpec = wire.EffectiveSpec

func BuildEffectiveSpec(key, spec, alpn string) (*EffectiveSpec, error) {
	return wire.BuildEffectiveSpec(key, spec, alpn)
}
