package config

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"time"
)

const (
	minJWTKeyLen = 32 // байт, под HS256 нужен ключ не короче хеша
	maxAccessTTL = 24 * time.Hour
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
	JWTKey      Secret
	AccessTTL   time.Duration
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

	jwtKey := os.Getenv("AUTH_JWT_KEY")
	if len(jwtKey) < minJWTKeyLen {
		return Config{}, fmt.Errorf("AUTH_JWT_KEY is required and must be at least %d bytes", minJWTKeyLen)
	}

	ttl, err := time.ParseDuration(getEnv("AUTH_ACCESS_TTL", "15m"))
	if err != nil || ttl <= 0 || ttl > maxAccessTTL {
		return Config{}, fmt.Errorf("invalid AUTH_ACCESS_TTL: must be a duration between 1s and %s", maxAccessTTL)
	}

	return Config{
		Addr:        addr,
		DatabaseURL: Secret(dbURL),
		JWTKey:      Secret(jwtKey),
		AccessTTL:   ttl,
	}, nil
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
