// Command intune-mock serves a test double of Entra ID, Graph discovery and the
// Intune ScepActions API, so scep-intune can be exercised end to end without a
// Microsoft tenant. For tests and local development only. See docs/testing.md.
//
// Every flag can also be set with the environment variable MOCK_<FLAG>, with
// dashes as underscores (e.g. MOCK_BASE_URL). Flags win over the environment.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/KerckhoffsLabs/scep-intune/internal/intunemock"
)

// applyEnv sets each flag from MOCK_<FLAG> (dashes as underscores) when that
// variable is set. An invalid value is an error rather than a silent fallback
// to the default.
func applyEnv(fs *flag.FlagSet, lookup func(string) (string, bool)) error {
	var errs []error
	fs.VisitAll(func(f *flag.Flag) {
		name := "MOCK_" + strings.ToUpper(strings.ReplaceAll(f.Name, "-", "_"))
		if v, ok := lookup(name); ok {
			if err := f.Value.Set(v); err != nil {
				errs = append(errs, fmt.Errorf("%s=%q: %w", name, v, err))
			}
		}
	})
	return errors.Join(errs...)
}

func main() {
	// run returns instead of calling os.Exit, so deferred cleanup runs first.
	os.Exit(run())
}

func run() int {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	fs := flag.NewFlagSet("intune-mock", flag.ExitOnError)
	listen := fs.String("listen", ":8443", "address to listen on")
	cert := fs.String("cert", "", "PEM certificate (required: the Azure SDK only accepts an https authority)")
	key := fs.String("key", "", "PEM private key (required)")
	baseURL := fs.String("base-url", "", "address clients use to reach the mock, e.g. https://intune-mock:8443 (required)")
	graphScope := fs.String("graph-scope", "", "Graph token scope to accept (default <base-url>/.default)")
	intuneScope := fs.String("intune-scope", "", "Intune token scope to accept (default https://api.manage.microsoft.com/.default)")
	appID := fs.String("app-id", "", "Intune app ID answered by discovery (default Intune's real app ID)")
	clientID := fs.String("client-id", "", "only client ID the token endpoint accepts (default: any non-empty)")
	clientSecret := fs.String("client-secret", "", "only client secret the token endpoint accepts (default: any non-empty)")
	maxRecords := fs.Int("max-records", 1000, "size of the /_mock/requests log; oldest entries are dropped")

	// Environment first, flags override.
	if err := applyEnv(fs, os.LookupEnv); err != nil {
		log.Error("invalid environment", "err", err)
		return 2
	}
	_ = fs.Parse(os.Args[1:])

	if *cert == "" || *key == "" || *baseURL == "" {
		log.Error("-cert, -key and -base-url are required")
		return 2
	}
	if err := intunemock.ValidateBaseURL(*baseURL); err != nil {
		log.Error("invalid -base-url", "base_url", *baseURL, "err", err)
		return 2
	}

	m := intunemock.New(intunemock.Options{
		BaseURL:      *baseURL,
		GraphScope:   *graphScope,
		IntuneScope:  *intuneScope,
		AppID:        *appID,
		ClientID:     *clientID,
		ClientSecret: *clientSecret,
		MaxRecords:   *maxRecords,
	})
	logged := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Info("request", "method", r.Method, "path", r.URL.Path)
		m.ServeHTTP(w, r)
	})
	srv := &http.Server{Addr: *listen, Handler: logged, ReadHeaderTimeout: 10 * time.Second}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()

	log.Info("intune-mock starting: for tests only, never point a production bridge here", "listen", *listen, "config", m.String())
	if err := srv.ListenAndServeTLS(*cert, *key); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Error("server failed", "err", err)
		return 1
	}
	return 0
}
