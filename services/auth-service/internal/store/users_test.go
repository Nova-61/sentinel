package store

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"
)

func TestUsers(t *testing.T) {
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

	suffix := time.Now().UnixNano()
	email := fmt.Sprintf("Test-%d@Example.com", suffix)
	evil := fmt.Sprintf("x%d'; DROP TABLE users; --@example.com", suffix)

	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM users WHERE lower(email) = lower($1) OR email = $2`, email, evil)
	})

	created, err := users.Create(ctx, email, "hash-1")
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if created.ID == "" {
		t.Error("Create() returned an empty ID")
	}

	if _, err := users.Create(ctx, fmt.Sprintf("test-%d@example.com", suffix), "hash-2"); !errors.Is(err, ErrEmailTaken) {
		t.Errorf("duplicate with other case: error = %v, want ErrEmailTaken", err)
	}

	got, err := users.GetByEmail(ctx, fmt.Sprintf("TEST-%d@EXAMPLE.COM", suffix))
	if err != nil {
		t.Fatalf("GetByEmail() error = %v", err)
	}
	if got.ID != created.ID || got.PasswordHash != "hash-1" {
		t.Errorf("GetByEmail() = %+v, want id %s and hash-1", got, created.ID)
	}

	if _, err := users.GetByEmail(ctx, "nobody@example.com"); !errors.Is(err, ErrNotFound) {
		t.Errorf("missing user: error = %v, want ErrNotFound", err)
	}

	if _, err := users.Create(ctx, evil, "hash-3"); err != nil {
		t.Fatalf("Create() with SQL in email error = %v", err)
	}
	if _, err := users.GetByEmail(ctx, "nobody@example.com"); !errors.Is(err, ErrNotFound) {
		t.Errorf("table broken after injection attempt: error = %v", err)
	}
}
