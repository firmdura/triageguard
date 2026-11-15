package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/firmdura/triageguard/internal/cli"
	"github.com/firmdura/triageguard/pkg/triageguard"
)

// Release builds set this with -ldflags '-X main.version=v1.0.0'.
var version = "dev"

func main() {
	// Go otherwise terminates on a broken stdout pipe before Run can return the
	// documented I/O-error exit code. Ignore SIGPIPE so writes return EPIPE.
	signal.Ignore(syscall.SIGPIPE)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := cli.Run(ctx, os.Args[1:], os.Stdout, os.Stderr, version, cli.Operations{
		LoadManifest:  triageguard.LoadManifest,
		Check:         triageguard.Check,
		WriteJSON:     triageguard.WriteJSON,
		WriteMarkdown: triageguard.WriteMarkdown,
	})
	stop()
	os.Exit(code)
}
