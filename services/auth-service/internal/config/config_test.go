package config

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

const (
	validDB  = "postgres://user:pass@127.0.0.1:5432/db"
	validKey = "test-only-signing-key-32-bytes-ok"
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
			t.Setenv("AUTH_MFA_KEY", validMFAKey)
			t.Setenv("AUTH_ACCESS_TTL", tt.ttl)
			t.Setenv("AUTH_REDIS_PASSWORD", strings.Repeat("x", 20))

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
	t.Setenv("AUTH_MFA_KEY", validMFAKey)

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

func TestLoadRedis(t *testing.T) {
	longPW := strings.Repeat("x", 20)

	tests := []struct {
		name     string
		addr     string
		pw       string
		wantAddr string
		wantErr  bool
	}{
		{"default addr", "", longPW, "127.0.0.1:6379", false},
		{"custom addr", "redis:6379", longPW, "redis:6379", false},
		{"addr without port", "redis", longPW, "", true},
		{"missing password", "", "", "", true},
		{"short password", "", "short", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("AUTH_DATABASE_URL", validDB)
			t.Setenv("AUTH_JWT_KEY", validKey)
			t.Setenv("AUTH_MFA_KEY", validMFAKey)
			t.Setenv("AUTH_REDIS_ADDR", tt.addr)
			t.Setenv("AUTH_REDIS_PASSWORD", tt.pw)

			cfg, err := Load()
			if (err != nil) != tt.wantErr {
				t.Fatalf("Load() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && cfg.RedisAddr != tt.wantAddr {
				t.Errorf("RedisAddr = %q, want %q", cfg.RedisAddr, tt.wantAddr)
			}
		})
	}
}

func TestLoadErrorDoesNotLeakRedisPassword(t *testing.T) {
	const shortPW = "tiny-pw-value"
	t.Setenv("AUTH_DATABASE_URL", validDB)
	t.Setenv("AUTH_JWT_KEY", validKey)
	t.Setenv("AUTH_MFA_KEY", validMFAKey)
	t.Setenv("AUTH_REDIS_PASSWORD", shortPW)

	_, err := Load()
	if err == nil {
		t.Fatal("Load() accepted a short redis password")
	}
	if strings.Contains(err.Error(), shortPW) {
		t.Errorf("error leaks the password value: %v", err)
	}
}

var validMFAKey = strings.Repeat("ab", 32)

func TestLoadMFAKey(t *testing.T) {
	tests := []struct {
		name    string
		mfa     string
		jwt     string
		wantErr bool
	}{
		{"valid", validMFAKey, validKey, false},
		{"missing", "", validKey, true},
		{"not hex", strings.Repeat("zz", 32), validKey, true},
		{"too short", strings.Repeat("ab", 16), validKey, true},
		{"too long", strings.Repeat("ab", 33), validKey, true},
		{"same as jwt key", validMFAKey, validMFAKey, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("AUTH_DATABASE_URL", validDB)
			t.Setenv("AUTH_JWT_KEY", tt.jwt)
			t.Setenv("AUTH_MFA_KEY", tt.mfa)
			t.Setenv("AUTH_REDIS_PASSWORD", strings.Repeat("x", 20))

			cfg, err := Load()
			if (err != nil) != tt.wantErr {
				t.Fatalf("Load() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err != nil && tt.mfa != "" && strings.Contains(err.Error(), tt.mfa) {
				t.Errorf("error leaks the key value: %v", err)
			}
			if err == nil && len(cfg.MFAKey.Reveal()) != 32 {
				t.Errorf("decoded key length = %d, want 32", len(cfg.MFAKey.Reveal()))
			}
		})
	}
}
