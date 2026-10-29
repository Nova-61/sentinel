package store

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"
)

func TestMFAState(t *testing.T) {
	dbURL := os.Getenv("AUTH_DATABASE_URL")
	if dbURL == "" {
		t.Skip("AUTH_DATABASE_URL is not set, skipping integration test")
	}

	ctx := context.Background()
	pool, err := NewPool(ctx, dbURL)
	if err != nil {
		t.Fatalf("NewPool() error = %v", err)
	}
	defer pool.Close()
	users := NewUsers(pool)

	user, err := users.Create(ctx, fmt.Sprintf("mfa-%d@example.com", time.Now().UnixNano()), "hash")
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM users WHERE id = $1::uuid`, user.ID)
	})

	st, err := users.GetTOTP(ctx, user.ID)
	if err != nil || st.Enabled || st.SecretEnc != nil {
		t.Fatalf("fresh user: GetTOTP() = %+v, %v, want disabled and no secret", st, err)
	}

	first, second := []byte("sealed-secret-1"), []byte("sealed-secret-2")

	if err := users.SetPendingTOTP(ctx, user.ID, first); err != nil {
		t.Fatalf("SetPendingTOTP() error = %v", err)
	}
	if err := users.SetPendingTOTP(ctx, user.ID, second); err != nil {
		t.Fatalf("re-enrolling before confirmation must be allowed, error = %v", err)
	}
	if st, _ = users.GetTOTP(ctx, user.ID); !bytes.Equal(st.SecretEnc, second) || st.Enabled {
		t.Fatalf("after re-enroll: %+v, want the second secret and MFA disabled", st)
	}

	if err := users.EnableTOTP(ctx, user.ID, first); !errors.Is(err, ErrNoPendingMFA) {
		t.Errorf("EnableTOTP accepted a stale secret: error = %v, want ErrNoPendingMFA", err)
	}
	if err := users.EnableTOTP(ctx, user.ID, second); err != nil {
		t.Fatalf("EnableTOTP() error = %v", err)
	}
	if st, _ = users.GetTOTP(ctx, user.ID); !st.Enabled {
		t.Fatal("MFA is not enabled after EnableTOTP")
	}

	if err := users.SetPendingTOTP(ctx, user.ID, first); !errors.Is(err, ErrMFAAlreadyEnabled) {
		t.Errorf("SetPendingTOTP overwrote the secret of a user with MFA enabled: error = %v", err)
	}
	if st, _ = users.GetTOTP(ctx, user.ID); !bytes.Equal(st.SecretEnc, second) {
		t.Error("the secret changed after a rejected SetPendingTOTP")
	}
	if err := users.EnableTOTP(ctx, user.ID, second); !errors.Is(err, ErrNoPendingMFA) {
		t.Errorf("second EnableTOTP: error = %v, want ErrNoPendingMFA", err)
	}

	if _, err := users.GetTOTP(ctx, "00000000-0000-4000-8000-000000000000"); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown user: error = %v, want ErrNotFound", err)
	}
	if _, err := users.GetTOTP(ctx, "not-a-uuid"); err == nil || errors.Is(err, ErrNotFound) {
		t.Errorf("malformed id: error = %v, want a plain error", err)
	}
}

func TestEmailByID(t *testing.T) {
	dbURL := os.Getenv("AUTH_DATABASE_URL")
	if dbURL == "" {
		t.Skip("AUTH_DATABASE_URL is not set, skipping integration test")
	}

	ctx := context.Background()
	pool, err := NewPool(ctx, dbURL)
	if err != nil {
		t.Fatalf("NewPool() error = %v", err)
	}
	defer pool.Close()
	users := NewUsers(pool)

	email := fmt.Sprintf("byid-%d@example.com", time.Now().UnixNano())
	user, err := users.Create(ctx, email, "hash")
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM users WHERE id = $1::uuid`, user.ID)
	})

	if got, err := users.EmailByID(ctx, user.ID); err != nil || got != email {
		t.Errorf("EmailByID() = %q, %v, want %q", got, err, email)
	}
	if _, err := users.EmailByID(ctx, "00000000-0000-4000-8000-000000000000"); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown user: error = %v, want ErrNotFound", err)
	}
}
