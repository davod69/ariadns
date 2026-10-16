// Command ariadns is a fast, privacy-friendly DNS server with DoT/DoH,
// caching, rules, blocklists and a small admin dashboard.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"ariadns/internal/config"
	"ariadns/internal/server"
	"ariadns/internal/version"
)

func main() { os.Exit(run()) }

func run() int {
	var (
		cfgPath = flag.String("config", "", "path to config.json (defaults are used when empty)")
		check   = flag.Bool("check", false, "validate the configuration and exit")
		showVer = flag.Bool("version", false, "print version and exit")
	)
	flag.Parse()

	if *showVer {
		fmt.Printf("ariadns %s (commit %s, built %s)\n", version.Version, version.Commit, version.Date)
		return 0
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "config error:", err)
		return 2
	}
	if *check {
		fmt.Println("configuration OK")
		return 0
	}

	var lvl slog.Level
	_ = lvl.UnmarshalText([]byte(strings.ToUpper(cfg.Log.Level)))
	opts := &slog.HandlerOptions{Level: lvl}
	var h slog.Handler = slog.NewTextHandler(os.Stderr, opts)
	if cfg.Log.Format == "json" {
		h = slog.NewJSONHandler(os.Stderr, opts)
	}
	log := slog.New(h)

	srv, err := server.New(cfg, *cfgPath, log)
	if err != nil {
		log.Error("startup failed", "err", err)
		return 1
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	go func() {
		for range hup {
			if err := srv.Reload(); err != nil {
				log.Error("reload failed, keeping previous configuration", "err", err)
			}
		}
	}()

	log.Info("ariadns starting", "version", version.Version)
	if err := srv.Run(ctx); err != nil {
		log.Error("server error", "err", err)
		return 1
	}
	log.Info("bye")
	return 0
}
