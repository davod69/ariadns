// Command ariadns is a fast, privacy-friendly DNS server with DoT/DoH,
// caching, rules, blocklists and a small admin dashboard.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"ariadns/internal/admin"
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
		initCr  = flag.Bool("init", false, "create admin credentials if missing, print the panel address and exit")
	)
	flag.Parse()
	if flag.Arg(0) == "menu" {
		return runMenu(*cfgPath)
	}

	if *showVer {
		fmt.Printf("ariadns %s (commit %s, built %s)\n", version.Version, version.Commit, version.Date)
		return 0
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "config error:", err)
		return 2
	}
	if *initCr {
		return runInit(cfg)
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

// runInit prepares the admin credentials and tells the operator how to log in.
func runInit(cfg *config.Config) int {
	if cfg.DataDir == "" || cfg.Panel.Listen == "" {
		fmt.Fprintln(os.Stderr, "-init needs data_dir and panel.listen in the config")
		return 2
	}
	cr, pw, err := admin.OpenCreds(cfg.DataDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "init failed:", err)
		return 1
	}
	host := cfg.Smart.PublicIP
	if host == "" {
		host = "SERVER_IP"
	}
	_, port, _ := net.SplitHostPort(cfg.Panel.Listen)
	scheme := "http"
	if cfg.Panel.TLS {
		scheme = "https"
	}
	fmt.Printf("Admin panel : %s://%s:%s/%s/\n", scheme, host, port, cr.Path())
	if pw != "" {
		fmt.Printf("Password    : %s\n(shown once - save it now; reset later with: ariadns menu)\n", pw)
	} else {
		fmt.Println("Password    : unchanged (reset with: ariadns menu, option 8)")
	}
	return 0
}
