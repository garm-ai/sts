// Package stsd runs the security token service: the routes, the HTTP
// server and the drain that cmd/sts used to hold inline.
//
// The binary is the way to run this service. Serve exists so that
// garm-ai/stack's garmstack can run garmd, the STS and agentd as goroutines
// in a single process for local development and demonstration; that
// single-process mode is never for production, because one process holding
// this service's signing key, agentd's client key and garmd's verifier
// configuration is one compromise away from all three.
//
// There is exactly one implementation: cmd/sts parses flags and the
// environment into a Config and calls Serve, and so does garmstack.
package stsd

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/garm-ai/sts"
)

// shutdownTimeout is how long in-flight requests get once the context ends.
// A request to this service is milliseconds — a signature and a lookup —
// so five seconds is generous rather than tight.
const shutdownTimeout = 5 * time.Second

// Config is everything this daemon needs, one field per flag or environment
// variable cmd/sts reads. It carries values, never flags: nothing here is
// parsed, looked up in the environment, or defaulted from a command line
// inside Serve.
type Config struct {
	// STS is the validated service configuration — what sts.LoadConfig
	// returns for the file cmd/sts's -config flag names. Required.
	STS *sts.Config

	// Authz is the Authorizer to answer instance checks with. It is a
	// value rather than something Serve builds, because WHICH
	// implementation a binary has is decided when that binary is BUILT,
	// not at runtime: an untagged build uses the static, file-backed one
	// and a -tags openfga build uses the OpenFGA-backed one (see
	// cmd/sts/authz_static.go and cmd/sts/authz_openfga.go). A library
	// cannot make that choice for the program importing it. Required.
	Authz sts.Authorizer

	// TLSCertFile and TLSKeyFile are the certificate and key to serve
	// with — STS_TLS_CERT and STS_TLS_KEY for the binary. Both empty means
	// PLAINTEXT, which is only ever right behind a proxy or mesh sidecar
	// that terminates TLS; Serve says so at WARN every time.
	TLSCertFile string
	TLSKeyFile  string

	// Log is where this daemon writes. nil means slog.Default().
	Log *slog.Logger
}

// Serve builds the service from cfg and serves it until ctx is cancelled,
// then drains and returns nil. It returns an error only when the service
// could not be built or the listener failed on its own.
//
// Cancelling ctx is the ONLY shutdown path: cmd/sts's signal context is
// this ctx, so SIGTERM and a cancelled context drain through the same code
// rather than through two that can drift apart.
func Serve(ctx context.Context, cfg Config) error {
	if cfg.STS == nil {
		return errors.New("sts: serve: a configuration is required")
	}
	if cfg.Authz == nil {
		return errors.New("sts: serve: an Authorizer is required")
	}
	log := cfg.Log
	if log == nil {
		log = slog.Default()
	}

	srv, err := cfg.STS.Build(ctx, cfg.Authz)
	if err != nil {
		return fmt.Errorf("sts: build: %w", err)
	}

	mux := http.NewServeMux()
	mux.Handle("/token", srv.Handler())
	// The approval endpoint. Same keyring, same client registry, same
	// opaque denial — a different credential entirely (see approve.go).
	mux.Handle("/approve", srv.ApproveHandler())
	mux.Handle("/.well-known/jwks.json", srv.Keyring().Handler())
	// Published so a verifier can check, at ITS startup, that it was
	// configured to expect what this service actually mints. See metadata.go.
	mux.Handle("/.well-known/oauth-authorization-server",
		srv.MetadataHandler(cfg.STS.Issuer+"/.well-known/jwks.json", cfg.STS.Issuer+"/token", cfg.STS.Issuer+"/approve"))

	h := &http.Server{
		Addr:              cfg.STS.Listen,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS12},
	}

	// Closed once Shutdown has returned, so Serve does not come back while
	// handlers are still writing. The goroutine outlives a failed
	// ListenAndServe below — it is waiting on ctx, which the caller ends.
	drained := make(chan struct{})
	go func() {
		defer close(drained)
		<-ctx.Done()
		log.Info("sts: shutting down")
		sc, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		if err := h.Shutdown(sc); err != nil {
			log.Error("sts: shutdown", "err", err)
		}
	}()

	log.Info("sts listening", "addr", cfg.STS.Listen, "issuer", cfg.STS.Issuer, "audience", cfg.STS.Audience)

	if cfg.TLSCertFile != "" && cfg.TLSKeyFile != "" {
		err = h.ListenAndServeTLS(cfg.TLSCertFile, cfg.TLSKeyFile)
	} else {
		log.Warn("sts: serving PLAINTEXT — set STS_TLS_CERT and STS_TLS_KEY, or terminate TLS at a proxy/mesh sidecar in front of this service")
		err = h.ListenAndServe()
	}
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("sts: serve: %w", err)
	}
	// ErrServerClosed says Shutdown was CALLED, not that it returned: the
	// listener closes at once while in-flight requests are still being
	// answered. Wait for them, so a caller that treats Serve's return as
	// "drained" is right.
	<-drained
	return nil
}
