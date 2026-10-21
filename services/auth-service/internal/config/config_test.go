package config

import "testing"

func TestLoad(t *testing.T) {
	tests := []struct {
		name    string
		env     string
		want    string
		wantErr bool
	}{
		{"default", "", ":8080", false},
		{"custom port", ":9090", ":9090", false},
		{"host and port", "127.0.0.1:9090", "127.0.0.1:9090", false},
		{"missing port", "abc", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("AUTH_ADDR", tt.env)

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

