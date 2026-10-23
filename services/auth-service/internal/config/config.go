package config

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
)

// Secret хранит значение, которое нельзя выводить в логи и сообщения.
type Secret string

func (Secret) String() string       { return "[REDACTED]" }
func (Secret) GoString() string     { return "[REDACTED]" }
func (Secret) LogValue() slog.Value { return slog.StringValue("[REDACTED]") }

// Reveal возвращает настоящее значение. Вызывать только там, где оно реально нужно.
func (s Secret) Reveal() string { return string(s) }

type Config struct {
	Addr        string
	DatabaseURL Secret
}

func Load() (Config, error) {
	addr := getEnv("AUTH_ADDR", ":8080")
	if _, _, err := net.SplitHostPort(addr); err != nil {
		return Config{}, fmt.Errorf("invalid AUTH_ADDR %q: %w", addr, err)
	}

	dbURL := os.Getenv("AUTH_DATABASE_URL")
	if dbURL == "" {
		return Config{}, errors.New("AUTH_DATABASE_URL is required")
	}

	return Config{Addr: addr, DatabaseURL: Secret(dbURL)}, nil
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
