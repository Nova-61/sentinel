package config

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

const (
	validDB  = "postgres://user:pass@127.0.0.1:5432/db"
	validKey = "0123456789abcdef0123456789abcdef"
)

func TestLoad(t *testing.T) {
	tests := []struct {
		name     string
		addr     string
		db       string
		key      string
		ttl      string
		wantAddr string
		wantTTL  time.Duration
		wantErr  bool
	}{
		{"defaults", "", validDB, validKey, "", ":8080", 15 * time.Minute, false},
		{"custom addr", "127.0.0.1:9090", validDB, validKey, "", "127.0.0.1:9090", 15 * time.Minute, false},
		{"custom ttl", "", validDB, validKey, "1h", ":8080", time.Hour, false},
		{"missing port", "abc", validDB, validKey, "", "", 0, true},
		{"missing database url", "", "", validKey, "", "", 0, true},
		{"missing jwt key", "", validDB, "", "", "", 0, true},
		{"short jwt key", "", validDB, "too-short", "", "", 0, true},
		{"bad ttl", "", validDB, validKey, "soon", "", 0, true},
		{"zero ttl", "", validDB, validKey, "0s", "", 0, true},
		{"ttl too long", "", validDB, validKey, "48h", "", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("AUTH_ADDR", tt.addr)
			t.Setenv("AUTH_DATABASE_URL", tt.db)
			t.Setenv("AUTH_JWT_KEY", tt.key)
			t.Setenv("AUTH_ACCESS_TTL", tt.ttl)

			cfg, err := Load()
			if (err != nil) != tt.wantErr {
				t.Fatalf("Load() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if cfg.Addr != tt.wantAddr || cfg.AccessTTL != tt.wantTTL {
				t.Errorf("got Addr=%q TTL=%v, want %q %v", cfg.Addr, cfg.AccessTTL, tt.wantAddr, tt.wantTTL)
			}
		})
	}
}

func TestLoadErrorDoesNotLeakKey(t *testing.T) {
	const shortKey = "leak-me-please"
	t.Setenv("AUTH_DATABASE_URL", validDB)
	t.Setenv("AUTH_JWT_KEY", shortKey)

	_, err := Load()
	if err == nil {
		t.Fatal("Load() accepted a short key")
	}
	if strings.Contains(err.Error(), shortKey) {
		t.Errorf("error leaks the key value: %v", err)
	}
}

func TestSecretIsRedacted(t *testing.T) {
	s := Secret("super-secret-value")
	out := fmt.Sprintf("%v|%s|%+v|%#v", s, s, s, s)
	if strings.Contains(out, "super-secret-value") {
		t.Fatalf("secret leaked into formatted output: %s", out)
	}
}
