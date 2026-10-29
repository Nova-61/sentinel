package mfa

import (
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
)

var fixedNow = time.Unix(1_700_000_010, 0)

func codeAt(t *testing.T, secret string, at time.Time) string {
	t.Helper()
	c, err := totp.GenerateCodeCustom(secret, at, validateOpts())
	if err != nil {
		t.Fatalf("GenerateCodeCustom() error = %v", err)
	}
	return c
}

func newSecret(t *testing.T) string {
	t.Helper()
	enr, err := Generate("Sentinel", "user@example.com")
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}
	return enr.Secret
}

func TestGenerate(t *testing.T) {
	a, err := Generate("Sentinel", "user@example.com")
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}
	b, _ := Generate("Sentinel", "user@example.com")
	if a.Secret == "" || a.Secret == b.Secret {
		t.Error("secrets are empty or repeat between calls")
	}
	if !strings.HasPrefix(a.URL, "otpauth://totp/") {
		t.Errorf("URL = %q, want otpauth://totp/ prefix", a.URL)
	}
	if _, err := Generate("", "user@example.com"); err == nil {
		t.Error("Generate() accepted an empty issuer")
	}
	if _, err := Generate("Sentinel", ""); err == nil {
		t.Error("Generate() accepted an empty account")
	}
}

func TestVerifyAcceptsNeighbourSteps(t *testing.T) {
	secret := newSecret(t)
	code := codeAt(t, secret, fixedNow)
	wantStep := fixedNow.Unix() / Period

	for _, shift := range []time.Duration{0, Period * time.Second, -Period * time.Second} {
		step, ok := Verify(secret, code, fixedNow.Add(shift))
		if !ok {
			t.Errorf("code rejected with clock shift %v", shift)
		}
		if step != wantStep {
			t.Errorf("shift %v: step = %d, want %d", shift, step, wantStep)
		}
	}
}

func TestVerifyRejectsOutsideWindow(t *testing.T) {
	secret := newSecret(t)
	code := codeAt(t, secret, fixedNow)

	for _, shift := range []time.Duration{3 * Period * time.Second, -3 * Period * time.Second} {
		if _, ok := Verify(secret, code, fixedNow.Add(shift)); ok {
			t.Errorf("code accepted with clock shift %v: the window is too wide", shift)
		}
	}
}

func TestVerifyRejectsWrongAndMalformed(t *testing.T) {
	secret := newSecret(t)
	valid := map[string]bool{}
	for _, off := range offsets {
		valid[codeAt(t, secret, fixedNow.Add(time.Duration(off*Period)*time.Second))] = true
	}
	wrong := "000000"
	if valid[wrong] {
		wrong = "111111"
	}

	tests := []struct {
		name string
		code string
	}{
		{"wrong code", wrong},
		{"empty", ""},
		{"too short", "12345"},
		{"too long", "1234567"},
		{"letters", "abcdef"},
		{"inner space", "123 56"},
		{"leading space", " 12345"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, ok := Verify(secret, tt.code, fixedNow); ok {
				t.Errorf("Verify(%q) accepted a bad code", tt.code)
			}
		})
	}
}

func TestVerifyRejectsOtherSecret(t *testing.T) {
	code := codeAt(t, newSecret(t), fixedNow)
	if _, ok := Verify(newSecret(t), code, fixedNow); ok {
		t.Error("code of one secret was accepted for another")
	}
}
