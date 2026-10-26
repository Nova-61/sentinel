package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Nova-61/sentinel/services/auth-service/internal/config"
	"github.com/Nova-61/sentinel/services/auth-service/internal/httpapi"
	"github.com/Nova-61/sentinel/services/auth-service/internal/password"
	"github.com/Nova-61/sentinel/services/auth-service/internal/store"
	"github.com/Nova-61/sentinel/services/auth-service/internal/token"
)

func main() {
	os.Exit(run())
}

func run() int {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	cfg, err := config.Load()
	if err != nil {
		logger.Error("invalid config", "error", err)
		return 1
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	pool, err := store.NewPool(ctx, cfg.DatabaseURL.Reveal())
	if err != nil {
		logger.Error("database connection failed", "error", err)
		return 1
	}
	defer pool.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})

	tokens, err := token.NewManager([]byte(cfg.JWTKey.Reveal()), cfg.AccessTTL)
	if err != nil {
		logger.Error("token manager failed", "error", err)
		return 1
	}
	dummyHash, err := password.Hash([]byte("timing-equalizer-password"))
	if err != nil {
		logger.Error("dummy hash failed", "error", err)
		return 1
	}

	users := store.NewUsers(pool)
	api := &httpapi.Handler{
		Users:     users,
		Lookup:    users,
		Tokens:    tokens,
		DummyHash: dummyHash,
		Logger:    logger,
	}
	mux.HandleFunc("POST /register", api.Register)
	mux.HandleFunc("POST /login", api.Login)

	srv := &http.Server{
		Addr:              cfg.Addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		logger.Info("auth-service starting", "addr", srv.Addr)
		errCh <- srv.ListenAndServe()
	}()

	select {
	case err := <-errCh:
		logger.Error("server failed", "error", err)
		return 1
	case <-ctx.Done():
		logger.Info("shutdown signal received")
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.Error("graceful shutdown failed", "error", err)
		return 1
	}
	logger.Info("server stopped")
	return 0
}
