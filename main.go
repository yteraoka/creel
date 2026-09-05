// Command creel is an HTTP forward proxy that intercepts TLS with a locally
// generated CA and saves matching response bodies to disk, mirroring each
// request's domain and path.
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
	"path/filepath"
	"syscall"
	"time"

	"github.com/yteraoka/creel/internal/ca"
	"github.com/yteraoka/creel/internal/config"
	"github.com/yteraoka/creel/internal/proxy"
	"github.com/yteraoka/creel/internal/store"
)

// version is the build's version, set by GoReleaser at release time.
var version = "dev"

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "creel: "+err.Error())
		os.Exit(1)
	}
}

func run() error {
	var (
		configPath = flag.String("config", "",
			"path to the YAML configuration file (default ./config.yaml, else $HOME/.config/creel/config.yaml)")
		listen    = flag.String("listen", "", "address to listen on (overrides listen in the config)")
		outputDir = flag.String("output", "", "directory to save bodies under (overrides output_dir)")
		caDir     = flag.String("ca-dir", "", "directory holding the CA (default $HOME/.config/creel)")
		logLevel  = flag.String("log-level", "info", "debug, info, warn or error")
		printCA   = flag.Bool("print-ca", false, "print the CA certificate path and exit")
		showVer   = flag.Bool("version", false, "print the version and exit")
	)
	flag.Parse()

	if *showVer {
		fmt.Println("creel " + version)
		return nil
	}

	level, err := parseLevel(*logLevel)
	if err != nil {
		return err
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	dir := *caDir
	if dir == "" {
		if dir, err = config.Dir(); err != nil {
			return fmt.Errorf("locate CA directory: %w", err)
		}
	}
	root, created, err := ca.LoadOrCreate(dir)
	if err != nil {
		return fmt.Errorf("load CA: %w", err)
	}
	certPath := filepath.Join(dir, ca.CertFile)
	if *printCA {
		fmt.Println(certPath)
		return nil
	}
	if created {
		log.Info("created CA", "file", certPath, "expires", root.Certificate().NotAfter.Format(time.DateOnly))
		fmt.Fprintf(os.Stderr, "Trust %s in your client to let creel intercept TLS.\n", certPath)
	}

	path, err := configFile(*configPath)
	if err != nil {
		return err
	}
	cfg, err := config.Load(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("%s not found; pass -config or create one (see config.example.yaml)", path)
		}
		return err
	}
	if *listen != "" {
		cfg.Listen = *listen
	}
	if *outputDir != "" {
		cfg.OutputDir = *outputDir
	}
	if len(cfg.Rules) == 0 {
		log.Warn("no rules configured; nothing will be saved", "config", path)
	}

	st, err := store.New(cfg.OutputDir, store.ExistPolicy(cfg.OnExist), cfg.AddExtension)
	if err != nil {
		return err
	}

	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           proxy.New(cfg, root, st, log),
		ReadHeaderTimeout: 30 * time.Second,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelDebug),
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() {
		log.Info("listening", "addr", cfg.Listen, "config", path,
			"output_dir", st.Root(), "rules", len(cfg.Rules), "ca", certPath)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		log.Info("shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	}
}

// configFile returns the file named by the -config flag, or the default one:
// config.yaml in the working directory, else the one under $HOME/.config/creel.
func configFile(flagValue string) (string, error) {
	if flagValue != "" {
		return flagValue, nil
	}
	p, found, err := config.DefaultPath()
	if err != nil {
		return "", fmt.Errorf("locate config file: %w", err)
	}
	if !found {
		return "", fmt.Errorf("no config file: create %s or %s, or pass -config (see config.example.yaml)",
			config.FileName, p)
	}
	return p, nil
}

func parseLevel(s string) (slog.Level, error) {
	var l slog.Level
	if err := l.UnmarshalText([]byte(s)); err != nil {
		return 0, fmt.Errorf("bad -log-level %q", s)
	}
	return l, nil
}
