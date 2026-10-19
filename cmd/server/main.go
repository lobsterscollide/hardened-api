package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/lobsterscollide/hardened-api/internal/api"
	"github.com/lobsterscollide/hardened-api/internal/checks"
	"github.com/lobsterscollide/hardened-api/internal/config"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	slog.SetDefault(logger)

	cfg, err := config.Load()
	if err != nil {
		slog.Error("config error", "err", err)
		os.Exit(1)
	}

	checkers := map[string]checks.Checker{
		"ssh":        &checks.SSHChecker{},
		"firewall":   &checks.FirewallChecker{},
		"fileperm":   &checks.FilePermChecker{},
		"ports":      &checks.PortsChecker{WhitelistPorts: cfg.WhitelistPorts},
		"sysctl":     &checks.SysctlChecker{},
		"users":      &checks.UserChecker{},
		"services":   &checks.ServicesChecker{},
		"chkrootkit": &checks.ChkrootkitChecker{},
		"rkhunter":   &checks.RkhunterChecker{},
		"clamscan":   &checks.ClamscanChecker{},
		"packages":   &checks.ArchAuditChecker{},
		"aide":       &checks.AIDEChecker{},
		"suid":       &checks.SUIDBinChecker{},
	}

	handler := api.NewRouter(cfg, checkers)

	srv := &http.Server{
		Addr:         cfg.Bind,
		Handler:      handler,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 15 * time.Minute,
		IdleTimeout:  120 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go func() {
		slog.Info("starting server", "addr", cfg.Bind)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("server error", "err", err)
			os.Exit(1)
		}
	}()

	<-ctx.Done()
	slog.Info("shutting down")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		slog.Error("shutdown error", "err", err)
	}
}
