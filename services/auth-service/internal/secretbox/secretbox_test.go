package secretbox

import (
	"bytes"
	"errors"
	"testing"
)

func newBox(t *testing.T, fill byte) *Box {
	t.Helper()
	b, err := New(bytes.Repeat([]byte{fill}, KeyLen))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return b
}

func TestSealOpenRoundTrip(t *testing.T) {
	b := newBox(t, 1)
	plain := []byte("totp-secret-value")
	aad := []byte("user-1")

	sealed, err := b.Seal(plain, aad)
	if err != nil {
		t.Fatalf("Seal() error = %v", err)
	}
	if bytes.Contains(sealed, plain) {
		t.Error("ciphertext contains the plaintext")
	}
	got, err := b.Open(sealed, aad)
	if err != nil || !bytes.Equal(got, plain) {
		t.Errorf("Open() = %q, %v, want %q, nil", got, err, plain)
	}
}

func TestSealUsesFreshNonce(t *testing.T) {
	b := newBox(t, 1)
	first, _ := b.Seal([]byte("same"), []byte("user-1"))
	second, _ := b.Seal([]byte("same"), []byte("user-1"))
	if bytes.Equal(first, second) {
		t.Error("two encryptions of the same data are identical: the nonce is reused")
	}
}

func TestOpenRejects(t *testing.T) {
	b := newBox(t, 1)
	sealed, _ := b.Seal([]byte("secret"), []byte("user-1"))

	tampered := bytes.Clone(sealed)
	tampered[len(tampered)-1] ^= 0xff

	tests := []struct {
		name string
		box  *Box
		data []byte
		aad  []byte
	}{
		{"wrong aad (another user)", b, sealed, []byte("user-2")},
		{"wrong key", newBox(t, 2), sealed, []byte("user-1")},
		{"tampered ciphertext", b, tampered, []byte("user-1")},
		{"too short", b, []byte{1, 2, 3}, []byte("user-1")},
		{"empty", b, nil, []byte("user-1")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := tt.box.Open(tt.data, tt.aad); !errors.Is(err, ErrDecrypt) {
				t.Errorf("Open() error = %v, want ErrDecrypt", err)
			}
		})
	}
}

func TestNewRejectsBadKeyLength(t *testing.T) {
	for _, n := range []int{0, 16, 31, 33, 64} {
		if _, err := New(make([]byte, n)); err == nil {
			t.Errorf("New() accepted a key of %d bytes", n)
		}
	}
}
