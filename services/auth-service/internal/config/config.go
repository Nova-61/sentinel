package config

import (
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"time"
)

const (
	minJWTKeyLen        = 32 // байт, под HS256 нужен ключ не короче хеша
	minRedisPasswordLen = 16
	mfaKeyLen           = 32 // байт, AES-256
	maxAccessTTL        = 24 * time.Hour
)

// Secret хранит значение, которое нельзя выводить в логи и сообщения.
type Secret string

func (Secret) String() string       { return "[REDACTED]" }
func (Secret) GoString() string     { return "[REDACTED]" }
func (Secret) LogValue() slog.Value { return slog.StringValue("[REDACTED]") }

// Reveal возвращает настоящее значение. Вызывать только там, где оно реально нужно.
func (s Secret) Reveal() string { return string(s) }

type Config struct {
	Addr          string
	DatabaseURL   Secret
	JWTKey        Secret
	AccessTTL     time.Duration
	RedisAddr     string
	RedisPassword Secret
	MFAKey        Secret // 32 сырых байта после декодирования из hex
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

	redisAddr := getEnv("AUTH_REDIS_ADDR", "127.0.0.1:6379")
	if _, _, err := net.SplitHostPort(redisAddr); err != nil {
		return Config{}, fmt.Errorf("invalid AUTH_REDIS_ADDR %q: %w", redisAddr, err)
	}

	redisPW := os.Getenv("AUTH_REDIS_PASSWORD")
	if len(redisPW) < minRedisPasswordLen {
		return Config{}, fmt.Errorf("AUTH_REDIS_PASSWORD is required and must be at least %d bytes", minRedisPasswordLen)
	}

	mfaHex := os.Getenv("AUTH_MFA_KEY")
	mfaKey, err := hex.DecodeString(mfaHex)
	if err != nil || len(mfaKey) != mfaKeyLen {
		return Config{}, fmt.Errorf("AUTH_MFA_KEY is required and must be %d bytes in hex (%d characters)", mfaKeyLen, mfaKeyLen*2)
	}
	if mfaHex == jwtKey {
		return Config{}, errors.New("AUTH_MFA_KEY must differ from AUTH_JWT_KEY")
	}

	return Config{
		Addr:          addr,
		DatabaseURL:   Secret(dbURL),
		JWTKey:        Secret(jwtKey),
		AccessTTL:     ttl,
		RedisAddr:     redisAddr,
		RedisPassword: Secret(redisPW),
		MFAKey:        Secret(mfaKey),
	}, nil
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
