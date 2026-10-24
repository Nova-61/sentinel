package password

import (
	"bytes"
	"errors"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func TestHashAndVerify(t *testing.T) {
	pw := []byte("correct horse battery")

	h1, err := Hash(pw)
	if err != nil {
		t.Fatalf("Hash() error = %v", err)
	}
	if h1 == string(pw) {
		t.Fatal("hash equals the plaintext password")
	}
	if got, _ := bcrypt.Cost([]byte(h1)); got != cost {
		t.Errorf("cost = %d, want %d", got, cost)
	}
	if !Verify(h1, pw) {
		t.Error("Verify() rejected the correct password")
	}
	if Verify(h1, []byte("wrong password here")) {
		t.Error("Verify() accepted a wrong password")
	}

	h2, err := Hash(pw)
	if err != nil {
		t.Fatalf("Hash() error = %v", err)
	}
	if h1 == h2 {
		t.Error("two hashes of the same password are identical: salt is missing")
	}
}

func TestHashLimits(t *testing.T) {
	tests := []struct {
		name string
		pw   []byte
		want error
	}{
		{"too short", []byte("short"), ErrTooShort},
		{"exactly 12", []byte("123456789012"), nil},
		{"72 bytes", bytes.Repeat([]byte("a"), 72), nil},
		{"73 bytes", bytes.Repeat([]byte("a"), 73), ErrTooLong},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Hash(tt.pw)
			if !errors.Is(err, tt.want) {
				t.Errorf("Hash() error = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestVerifyBadHash(t *testing.T) {
	if Verify("not-a-bcrypt-hash", []byte("whatever password")) {
		t.Error("Verify() accepted a malformed hash")
	}
}

func TestWipe(t *testing.T) {
	b := []byte("secret-password")
	Wipe(b)
	if !bytes.Equal(b, make([]byte, len(b))) {
		t.Error("Wipe() did not zero the slice")
	}
}
