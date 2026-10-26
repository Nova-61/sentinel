package store

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"
)

func TestSessions(t *testing.T) {
	addr := os.Getenv("AUTH_REDIS_ADDR")
	if addr == "" {
		t.Skip("AUTH_REDIS_ADDR is not set, skipping integration test")
	}

	ctx := context.Background()
	rdb, err := NewRedis(ctx, addr, os.Getenv("AUTH_REDIS_PASSWORD"))
	if err != nil {
		t.Fatalf("NewRedis() error = %v", err)
	}
	defer rdb.Close()
	sessions := NewSessions(rdb)

	jti := fmt.Sprintf("test-%d", time.Now().UnixNano())
	t.Cleanup(func() { _ = sessions.Revoke(ctx, jti) })

	if err := sessions.Create(ctx, jti, "user-1", 0); err == nil {
		t.Fatal("Create() accepted a zero TTL: the session would never expire")
	}

	if err := sessions.Create(ctx, jti, "user-1", time.Minute); err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if ok, err := sessions.Active(ctx, jti, "user-1"); err != nil || !ok {
		t.Errorf("Active() = %v, %v, want true, nil", ok, err)
	}
	if ok, _ := sessions.Active(ctx, jti, "user-2"); ok {
		t.Error("Active() accepted another user's id")
	}

	if err := sessions.Revoke(ctx, jti); err != nil {
		t.Fatalf("Revoke() error = %v", err)
	}
	if ok, _ := sessions.Active(ctx, jti, "user-1"); ok {
		t.Error("Active() returned true after Revoke()")
	}

	if err := sessions.Create(ctx, jti, "user-1", 200*time.Millisecond); err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	time.Sleep(400 * time.Millisecond)
	if ok, _ := sessions.Active(ctx, jti, "user-1"); ok {
		t.Error("Active() returned true after the TTL expired")
	}
}
