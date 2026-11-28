// Command scep-intune is a webhook bridge: it lets a vanilla step-ca SCEP
// provisioner validate enrollments against Microsoft Intune and report issuance
// results, via step-ca's SCEPCHALLENGE and NOTIFYING webhooks.
package main

import (
	"context"
	"encoding/base64"
	"errors"
	"flag"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/KerckhoffsLabs/scep-intune/internal/config"
	"github.com/KerckhoffsLabs/scep-intune/internal/intune"
	"github.com/KerckhoffsLabs/scep-intune/internal/webhook"
)

func main() {
	// run returns instead of calling os.Exit, so deferred cleanup (closing the
	// log file) always happens.
	os.Exit(run(context.Background(), os.Args[1:], os.Stdout, os.Stderr))
}

// run starts the bridge and blocks until it fails or a shutdown signal (or the
// cancellation of parent) drains it. args are the command-line arguments
// without the program name; stdout receives the bootstrap log and stderr the
// usage text.
func run(parent context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("scep-intune", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", "config.yaml", "path to YAML config")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}

	// Bootstrap logger until config (which may redirect logs to a file) loads.
	log := slog.New(slog.NewJSONHandler(stdout, nil))

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		log.Error("config", "err", err)
		return 1
	}

	logger, logCloser, err := cfg.Logger()
	if err != nil {
		log.Error("logging setup", "err", err)
		return 1
	}
	if logCloser != nil {
		defer func() { _ = logCloser.Close() }()
	}
	log = logger

	validateSecret, err := base64.StdEncoding.DecodeString(cfg.Webhook.ValidateSecret)
	if err != nil {
		log.Error("webhook.validate_secret must be base64", "err", err)
		return 1
	}
	notifySecret, err := base64.StdEncoding.DecodeString(cfg.Webhook.NotifySecret)
	if err != nil {
		log.Error("webhook.notify_secret must be base64", "err", err)
		return 1
	}
	if len(validateSecret) == 0 || len(notifySecret) == 0 {
		log.Warn("a webhook secret is empty: requests are NOT fully authenticated (test/trusted-network only)")
	}

	if env := os.Getenv("AZURE_AUTHORITY_HOST"); intune.EnvAuthorityConflicts(cfg.Intune.AuthorityHost, env) {
		log.Warn("AZURE_AUTHORITY_HOST is ignored: intune.authority_host (INTUNE_AUTHORITY_HOST) decides the Entra authority",
			"AZURE_AUTHORITY_HOST", env, "authority_host", cfg.Intune.AuthorityHost)
	}
	tokens, err := intune.NewEntraTokens(cfg.Intune.TenantID, cfg.Intune.ClientID, cfg.Intune.ClientSecret, cfg.Intune.AuthorityHost)
	if err != nil {
		log.Error("entra credential", "err", err)
		return 1
	}
	if cfg.Intune.AuthorityHost != config.DefaultAuthorityHost || cfg.Intune.GraphURL != config.DefaultGraphURL ||
		cfg.Intune.ResourceURL != config.DefaultResourceURL || cfg.Intune.AppID != config.DefaultAppID {
		level := slog.LevelInfo
		msg := "using non-default Microsoft endpoints"
		if !intune.KnownMicrosoftAuthority(cfg.Intune.AuthorityHost) {
			// The client secret goes to this host: make a stray override visible.
			level = slog.LevelWarn
			msg = "using non-default Microsoft endpoints: the Entra client secret is sent to a host that is not a Microsoft authority"
		}
		log.Log(parent, level, msg,
			"authority_host", cfg.Intune.AuthorityHost, "graph_url", cfg.Intune.GraphURL,
			"resource_url", cfg.Intune.ResourceURL, "app_id", cfg.Intune.AppID)
	}
	client := intune.New(tokens, cfg.Intune.CallerInfo, intune.Endpoints{
		GraphURL:    cfg.Intune.GraphURL,
		ResourceURL: cfg.Intune.ResourceURL,
		AppID:       cfg.Intune.AppID,
	})

	h := webhook.New(client, validateSecret, notifySecret, log)

	// Explicit timeouts bound slow/abusive connections (Slowloris). WriteTimeout
	// is generous because each request fans out to Intune (and, on first call,
	// Graph discovery) before responding.
	srv := &http.Server{
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	ctx, stop := signal.NotifyContext(parent, os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Bind before serving, so a busy port fails here and the log names the
	// address actually bound (the port of a ":0" listen included).
	ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", cfg.Server.Listen)
	if err != nil {
		log.Error("server failed to start", "err", err)
		return 1
	}
	log.Info("starting", "listen", cfg.Server.Listen, "addr", ln.Addr().String(), "tls", cfg.Server.TLS.Enabled)
	serveErr := make(chan error, 1)
	go func() {
		if cfg.Server.TLS.Enabled {
			serveErr <- srv.ServeTLS(ln, cfg.Server.TLS.Cert, cfg.Server.TLS.Key)
		} else {
			serveErr <- srv.Serve(ln)
		}
	}()

	select {
	case err := <-serveErr:
		log.Error("server failed to start", "err", err)
		return 1
	case <-ctx.Done():
		stop() // restore default signal handling: a second signal force-quits
		log.Info("shutdown signal received, draining in-flight requests")
		// The drain deadline must outlive parent, which may be what just ended.
		shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(parent), 25*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			log.Error("graceful shutdown failed", "err", err)
			return 1
		}
		log.Info("shutdown complete")
	}
	return 0
}
