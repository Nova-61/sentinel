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
	"github.com/Nova-61/sentinel/services/auth-service/internal/secretbox"
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

	rdb, err := store.NewRedis(ctx, cfg.RedisAddr, cfg.RedisPassword.Reveal())
	if err != nil {
		logger.Error("redis connection failed", "error", err)
		return 1
	}
	defer rdb.Close()

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
	box, err := secretbox.New([]byte(cfg.MFAKey.Reveal()))
	if err != nil {
		logger.Error("secretbox failed", "error", err)
		return 1
	}

	users := store.NewUsers(pool)
	sessions := store.NewSessions(rdb)
	api := &httpapi.Handler{
		Users:     users,
		Lookup:    users,
		Tokens:    tokens,
		Sessions:  sessions,
		Parser:    tokens,
		Checker:   sessions,
		MFA:       users,
		Box:       box,
		DummyHash: dummyHash,
		Logger:    logger,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})
	mux.HandleFunc("POST /register", api.Register)
	mux.HandleFunc("POST /login", api.Login)
	mux.Handle("GET /validate", api.Authenticate(http.HandlerFunc(api.Validate)))
	mux.Handle("POST /logout", api.Authenticate(http.HandlerFunc(api.Logout)))
	mux.Handle("POST /mfa/enroll", api.Authenticate(http.HandlerFunc(api.MFAEnroll)))
	mux.Handle("POST /mfa/confirm", api.Authenticate(http.HandlerFunc(api.MFAConfirm)))

	srv := &http.Server{
		Addr:              cfg.Addr,
		Handler:           api.Recover(mux),
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
