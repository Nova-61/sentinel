package config

import (
	"fmt"
	"strings"
	"testing"
)

func TestLoad(t *testing.T) {
	const validDB = "postgres://user:pass@127.0.0.1:5432/db"

	tests := []struct {
		name    string
		addr    string
		db      string
		want    string
		wantErr bool
	}{
		{"default addr", "", validDB, ":8080", false},
		{"custom port", ":9090", validDB, ":9090", false},
		{"host and port", "127.0.0.1:9090", validDB, "127.0.0.1:9090", false},
		{"missing port", "abc", validDB, "", true},
		{"missing database url", "", "", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("AUTH_ADDR", tt.addr)
			t.Setenv("AUTH_DATABASE_URL", tt.db)

			cfg, err := Load()
			if (err != nil) != tt.wantErr {
				t.Fatalf("Load() error = %v, wantErr %v", err, tt.wantErr)
			}
			if cfg.Addr != tt.want {
				t.Errorf("Addr = %q, want %q", cfg.Addr, tt.want)
			}
		})
	}
}

func TestSecretIsRedacted(t *testing.T) {
	s := Secret("super-secret-value")
	out := fmt.Sprintf("%v|%s|%+v|%#v", s, s, s, s)
	if strings.Contains(out, "super-secret-value") {
		t.Fatalf("secret leaked into formatted output: %s", out)
	}
}
