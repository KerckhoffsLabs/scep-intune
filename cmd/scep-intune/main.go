// Command scep-intune is a webhook bridge: it lets a vanilla step-ca SCEP
// provisioner validate enrollments against Microsoft Intune and report issuance
// results, via step-ca's SCEPCHALLENGE and NOTIFYING webhooks.
package main

import (
	"context"
	"encoding/base64"
	"flag"
	"log/slog"
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
	cfgPath := flag.String("config", "config.yaml", "path to YAML config")
	flag.Parse()

	// Bootstrap logger until config (which may redirect logs to a file) loads.
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		log.Error("config", "err", err)
		os.Exit(1)
	}

	logger, logCloser, err := cfg.Logger()
	if err != nil {
		log.Error("logging setup", "err", err)
		os.Exit(1)
	}
	if logCloser != nil {
		defer func() { _ = logCloser.Close() }()
	}
	log = logger

	validateSecret, err := base64.StdEncoding.DecodeString(cfg.Webhook.ValidateSecret)
	if err != nil {
		log.Error("webhook.validate_secret must be base64", "err", err)
		os.Exit(1)
	}
	notifySecret, err := base64.StdEncoding.DecodeString(cfg.Webhook.NotifySecret)
	if err != nil {
		log.Error("webhook.notify_secret must be base64", "err", err)
		os.Exit(1)
	}
	if len(validateSecret) == 0 || len(notifySecret) == 0 {
		log.Warn("a webhook secret is empty: requests are NOT fully authenticated (test/trusted-network only)")
	}

	tokens, err := intune.NewEntraTokens(cfg.Intune.TenantID, cfg.Intune.ClientID, cfg.Intune.ClientSecret)
	if err != nil {
		log.Error("entra credential", "err", err)
		os.Exit(1)
	}
	client := intune.New(tokens, cfg.Intune.CallerInfo)

	h := webhook.New(client, validateSecret, notifySecret, log)

	// Explicit timeouts bound slow/abusive connections (Slowloris). WriteTimeout
	// is generous because each request fans out to Intune (and, on first call,
	// Graph discovery) before responding.
	srv := &http.Server{
		Addr:              cfg.Server.Listen,
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	serveErr := make(chan error, 1)
	go func() {
		log.Info("starting", "listen", cfg.Server.Listen, "tls", cfg.Server.TLS.Enabled)
		if cfg.Server.TLS.Enabled {
			serveErr <- srv.ListenAndServeTLS(cfg.Server.TLS.Cert, cfg.Server.TLS.Key)
		} else {
			serveErr <- srv.ListenAndServe()
		}
	}()

	select {
	case err := <-serveErr:
		log.Error("server failed to start", "err", err)
		os.Exit(1)
	case <-ctx.Done():
		stop() // restore default signal handling: a second signal force-quits
		log.Info("shutdown signal received, draining in-flight requests")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			log.Error("graceful shutdown failed", "err", err)
			os.Exit(1)
		}
		log.Info("shutdown complete")
	}
}
