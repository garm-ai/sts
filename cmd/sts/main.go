// Command sts is a small RFC 8693 security token service. It mints the
// delegation token garmd verifies, through either of two doors — a BFF
// presenting a verified human token (exchange 1), or a registered runner
// naming a subject it was handed (exchange 2, which adds the `exec` claim)
// — and it mints the approval grants garmd spends, at POST /approve. See
// README.md.
//
// This file is flags, the environment and the signal context, and nothing
// else: the service itself is stsd.Serve, which garm-ai/stack's garmstack
// runs too. There is one implementation, not one per caller.
package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/garm-ai/sts"
	"github.com/garm-ai/sts/stsd"
)

func main() {
	cfgPath := flag.String("config", "config.yaml", "path to the STS config file")
	flag.Parse()

	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(log)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cfg, err := sts.LoadConfig(*cfgPath)
	if err != nil {
		log.Error("sts: config", "err", err)
		os.Exit(1)
	}

	// newAuthorizer picks this BUILD's Authorizer implementation, not a
	// runtime choice: an untagged binary always uses the static, file-backed
	// one (cmd/sts/authz_static.go), and a binary built with -tags openfga
	// always uses the OpenFGA-backed one (cmd/sts/authz_openfga.go). Which
	// implementation a given `sts` binary has is decided when it is built,
	// which is why stsd.Config takes the Authorizer as a value rather than
	// building one for its caller.
	authz, err := newAuthorizer(cfg)
	if err != nil {
		log.Error("sts: authorizer", "err", err)
		os.Exit(1)
	}

	// SIGTERM cancels ctx, and a cancelled ctx is how Serve drains — one
	// shutdown path, shared with every other caller.
	if err := stsd.Serve(ctx, stsd.Config{
		STS:   cfg,
		Authz: authz,
		// Plaintext unless both are set; Serve warns when they are not.
		TLSCertFile: os.Getenv("STS_TLS_CERT"),
		TLSKeyFile:  os.Getenv("STS_TLS_KEY"),
		Log:         log,
	}); err != nil {
		log.Error("sts: serve", "err", err)
		os.Exit(1)
	}
}
