// Command sts is a small RFC 8693 security token service. It verifies a
// customer or employee token against its issuer's JWKS, checks entitlement
// against the configured Authorizer, and mints a short-lived delegation
// token carrying the `garm` claim and the act chain — exchange 1 only (see
// README.md for what is and is not built).
package main

import (
	"context"
	"crypto/tls"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/garm-ai/sts"
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
	// implementation a given `sts` binary has is decided when it is built.
	authz, err := newAuthorizer(cfg)
	if err != nil {
		log.Error("sts: authorizer", "err", err)
		os.Exit(1)
	}

	srv, err := cfg.Build(ctx, authz)
	if err != nil {
		log.Error("sts: build", "err", err)
		os.Exit(1)
	}

	mux := http.NewServeMux()
	mux.Handle("/token", srv.Handler())
	mux.Handle("/.well-known/jwks.json", srv.Keyring().Handler())
	// Published so a verifier can check, at ITS startup, that it was
	// configured to expect what this service actually mints. See metadata.go.
	mux.Handle("/.well-known/oauth-authorization-server",
		srv.MetadataHandler(cfg.Issuer+"/.well-known/jwks.json", cfg.Issuer+"/token"))

	h := &http.Server{
		Addr:              cfg.Listen,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS12},
	}

	go func() {
		<-ctx.Done()
		log.Info("sts: shutting down")
		sc, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := h.Shutdown(sc); err != nil {
			log.Error("sts: shutdown", "err", err)
		}
	}()

	log.Info("sts listening", "addr", cfg.Listen, "issuer", cfg.Issuer, "audience", cfg.Audience)

	cert, key := os.Getenv("STS_TLS_CERT"), os.Getenv("STS_TLS_KEY")
	if cert != "" && key != "" {
		err = h.ListenAndServeTLS(cert, key)
	} else {
		log.Warn("sts: serving PLAINTEXT — set STS_TLS_CERT and STS_TLS_KEY, or terminate TLS at a proxy/mesh sidecar in front of this service")
		err = h.ListenAndServe()
	}
	if err != nil && err != http.ErrServerClosed {
		log.Error("sts: serve", "err", err)
		os.Exit(1)
	}
}
