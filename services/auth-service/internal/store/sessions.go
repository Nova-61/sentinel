package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

type Sessions struct {
	rdb *redis.Client
}

func NewRedis(ctx context.Context, addr, password string) (*redis.Client, error) {
	rdb := redis.NewClient(&redis.Options{
		Addr:         addr,
		Password:     password,
		DialTimeout:  5 * time.Second,
		ReadTimeout:  3 * time.Second,
		WriteTimeout: 3 * time.Second,
	})

	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := rdb.Ping(pingCtx).Err(); err != nil {
		_ = rdb.Close()
		return nil, fmt.Errorf("ping redis: %w", err)
	}
	return rdb, nil
}

func NewSessions(rdb *redis.Client) *Sessions {
	return &Sessions{rdb: rdb}
}

func sessionKey(jti string) string { return "session:" + jti }

// Create сохраняет сессию. Срок обязателен: без него запись жила бы вечно.
func (s *Sessions) Create(ctx context.Context, jti, userID string, ttl time.Duration) error {
	if ttl <= 0 {
		return errors.New("session ttl must be positive")
	}
	if err := s.rdb.Set(ctx, sessionKey(jti), userID, ttl).Err(); err != nil {
		return fmt.Errorf("create session: %w", err)
	}
	return nil
}

// Active возвращает true, только если сессия есть и принадлежит этому пользователю.
// При ошибке Redis возвращается false и ошибка: вызывающий обязан отказать в доступе.
func (s *Sessions) Active(ctx context.Context, jti, userID string) (bool, error) {
	v, err := s.rdb.Get(ctx, sessionKey(jti)).Result()
	if errors.Is(err, redis.Nil) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("read session: %w", err)
	}
	return v == userID, nil
}

// Revoke удаляет сессию. Повторный вызов безопасен.
func (s *Sessions) Revoke(ctx context.Context, jti string) error {
	if err := s.rdb.Del(ctx, sessionKey(jti)).Err(); err != nil {
		return fmt.Errorf("revoke session: %w", err)
	}
	return nil
}
