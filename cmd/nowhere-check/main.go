// Command nowhere-check prints version info and optionally validates wire
// conformance vectors. It is a local/CI self-check helper, not a release artifact.
package main

import (
	"flag"
	"fmt"
	"os"
	"runtime"
	"runtime/debug"

	"github.com/hi2shark/nowhere-go/internal/veccheck"
	"github.com/hi2shark/nowhere-go/internal/vectors"
	"github.com/hi2shark/nowhere-go/wire"
)

// Version is overridden at link time: -ldflags "-X main.Version=v1.2.3"
var Version = "dev"

const (
	// UpstreamVersion is the supported Rust Nowhere protocol release.
	UpstreamVersion = "v1.5.1"
	// UpstreamCommit is the exact Rust oracle commit used to export vectors.
	UpstreamCommit = "1133040065029678c8b76b2b3fda9efa3260ada9"
)

func main() {
	fs := flag.NewFlagSet("nowhere-check", flag.ExitOnError)
	showVersion := fs.Bool("version", false, "print version and exit")
	vectorsOnly := fs.Bool("vectors", false, "validate conformance vectors and exit")
	vectorsDir := fs.String("vectors-dir", "", "vector directory (default: auto-detect / GO_NOWHERE_VECTORS)")
	selfCheck := fs.Bool("self-check", true, "run a small in-process wire self-check")
	_ = fs.Parse(os.Args[1:])

	if *showVersion {
		printVersion()
		return
	}

	if *vectorsOnly {
		if err := runVectors(*vectorsDir); err != nil {
			fmt.Fprintf(os.Stderr, "vectors: %v\n", err)
			os.Exit(1)
		}
		return
	}

	printVersion()
	if *selfCheck {
		if err := runSelfCheck(); err != nil {
			fmt.Fprintf(os.Stderr, "self-check: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("self-check: ok")
	}
	if err := runVectors(*vectorsDir); err != nil {
		fmt.Fprintf(os.Stderr, "vectors: %v\n", err)
		os.Exit(1)
	}
}

func printVersion() {
	fmt.Printf("nowhere-check %s\n", resolveVersion())
	fmt.Printf("go %s %s/%s\n", runtime.Version(), runtime.GOOS, runtime.GOARCH)
	fmt.Printf("module github.com/hi2shark/nowhere-go\n")
	fmt.Printf("upstream nowhere %s %s\n", UpstreamVersion, UpstreamCommit)
}

func resolveVersion() string {
	if Version != "" && Version != "dev" {
		return Version
	}
	if info, ok := debug.ReadBuildInfo(); ok {
		if info.Main.Version != "" && info.Main.Version != "(devel)" {
			return info.Main.Version
		}
	}
	return Version
}

func runSelfCheck() error {
	target, err := wire.NewDomainTarget("example.com", 443)
	if err != nil {
		return err
	}
	frame, err := wire.EncodeTarget(target)
	if err != nil {
		return err
	}
	if len(frame) == 0 {
		return fmt.Errorf("empty target frame")
	}
	if _, err := wire.WriteFlowHeader(wire.FlowHeader{
		Role:     wire.FlowRoleOpen,
		FlowID:   1,
		Kind:     wire.FlowKindTCP,
		Uplink:   wire.CarrierQUIC,
		Downlink: wire.CarrierTLSTCP,
	}); err != nil {
		return err
	}
	// Auth frame sanity: validates against its connection-bound exporter.
	creds, err := wire.NewCredentials("secret")
	if err != nil {
		return err
	}
	exporter := wire.TLSExporter{}
	for i := range exporter {
		exporter[i] = byte(i)
	}
	authFrame, err := wire.EncodeAuthFrame(creds, wire.AuthTransportTLSTCP, exporter, wire.SessionID{})
	if err != nil {
		return err
	}
	if _, err := wire.ValidateAuthFrame(authFrame[:], creds, wire.AuthTransportTLSTCP, exporter); err != nil {
		return err
	}
	return nil
}

func runVectors(dirFlag string) error {
	dir := dirFlag
	var err error
	if dir == "" {
		dir, err = vectors.Dir()
		if err != nil {
			return err
		}
	}
	n, err := veccheck.CheckDir(dir)
	if err != nil {
		return err
	}
	fmt.Printf("vectors: ok (%d cases) dir=%s\n", n, dir)
	return nil
}
