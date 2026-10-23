package token

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var testKey = []byte("0123456789abcdef0123456789abcdef")

func newTestManager(t *testing.T, key []byte) *Manager {
	t.Helper()
	m, err := NewManager(key, time.Minute)
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	return m
}

func TestIssueAndParse(t *testing.T) {
	m := newTestManager(t, testKey)

	raw, exp, err := m.Issue("user-1")
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}
	if !exp.After(time.Now()) {
		t.Error("expiration is not in the future")
	}

	claims, err := m.Parse(raw)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if claims.Subject != "user-1" || claims.ID == "" {
		t.Errorf("claims = %+v, want subject user-1 and non-empty jti", claims)
	}
}

func TestNewManagerRejectsShortKey(t *testing.T) {
	if _, err := NewManager([]byte("too-short"), time.Minute); err == nil {
		t.Error("NewManager() accepted a short key")
	}
}

func TestParseRejectsWrongKey(t *testing.T) {
	raw, _, _ := newTestManager(t, testKey).Issue("user-1")
	other := newTestManager(t, []byte("ffffffffffffffffffffffffffffffff"))
	if _, err := other.Parse(raw); err == nil {
		t.Error("Parse() accepted a token signed with another key")
	}
}

func TestParseRejectsExpired(t *testing.T) {
	old := newTestManager(t, testKey)
	old.now = func() time.Time { return time.Now().Add(-time.Hour) }
	raw, _, _ := old.Issue("user-1")

	if _, err := newTestManager(t, testKey).Parse(raw); err == nil {
		t.Error("Parse() accepted an expired token")
	}
}

func TestParseRejectsAlgNone(t *testing.T) {
	claims := jwt.RegisteredClaims{
		Issuer:    issuer,
		Subject:   "attacker",
		Audience:  jwt.ClaimStrings{audience},
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
	}
	raw, err := jwt.NewWithClaims(jwt.SigningMethodNone, claims).SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatalf("building alg=none token: %v", err)
	}
	if _, err := newTestManager(t, testKey).Parse(raw); err == nil {
		t.Error("Parse() accepted an unsigned alg=none token")
	}
}

func TestParseRejectsGarbage(t *testing.T) {
	m := newTestManager(t, testKey)
	for _, raw := range []string{"", "abc", "a.b.c"} {
		if _, err := m.Parse(raw); err == nil {
			t.Errorf("Parse(%q) accepted garbage", raw)
		}
	}
}

func TestParseRejectsOtherHMACAlgorithm(t *testing.T) {
	claims := jwt.RegisteredClaims{
		Issuer:    issuer,
		Subject:   "attacker",
		Audience:  jwt.ClaimStrings{audience},
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
	}
	raw, err := jwt.NewWithClaims(jwt.SigningMethodHS512, claims).SignedString(testKey)
	if err != nil {
		t.Fatalf("building HS512 token: %v", err)
	}
	if _, err := newTestManager(t, testKey).Parse(raw); err == nil {
		t.Error("Parse() accepted a token signed with HS512, expected only HS256")
	}
}
