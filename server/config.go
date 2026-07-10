package server

import (
	"fmt"
	"time"

	"github.com/hi2shark/go-nowhere/wire"
)

const DefaultFlowPairTimeout = 5 * time.Second

// Config is the normalized Nowhere Portal-like server configuration.
type Config struct {
	Key             string
	Spec            *wire.EffectiveSpec
	Networks        []string
	FlowPairTimeout time.Duration
	EnableTCP       bool
	EnableUDP       bool
}

// NewConfig builds Config from password / spec / alpn and network list.
// networks entries are "tcp" / "udp" (case-sensitive, lowercase). Empty means both.
func NewConfig(password, spec, alpn string, networks []string) (*Config, error) {
	if password == "" {
		return nil, fmt.Errorf("nowhere: missing password")
	}
	es, err := wire.BuildEffectiveSpec(password, spec, alpn)
	if err != nil {
		return nil, err
	}
	cfg := &Config{
		Key:             password,
		Spec:            es,
		Networks:        networks,
		FlowPairTimeout: DefaultFlowPairTimeout,
	}
	for _, n := range networks {
		switch n {
		case "tcp":
			cfg.EnableTCP = true
		case "udp":
			cfg.EnableUDP = true
		}
	}
	if !cfg.EnableTCP && !cfg.EnableUDP {
		cfg.EnableTCP = true
		cfg.EnableUDP = true
	}
	return cfg, nil
}
