package config

import (
	"fmt"
	"net"
	"os"
)

type Config struct {
	Addr string
}

func Load() (Config, error) {
	addr := getEnv("AUTH_ADDR", ":8080")
	if _, _, err := net.SplitHostPort(addr); err != nil {
		return Config{}, fmt.Errorf("invalid AUTH_ADDR %q: %w", addr, err)
	}
	return Config{Addr: addr}, nil
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
