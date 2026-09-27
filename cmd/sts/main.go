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

	// The static, file-backed Authorizer is the only implementation this
	// task builds; an OpenFGA-backed one is a later task. Choosing which
	// Authorizer to build is main's job, not Config's — see config.go's
	// Build doc comment.
	authz, err := sts.LoadStaticAuthorizer(cfg.StaticAuthzPath)
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
