package store

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	ErrEmailTaken = errors.New("email already registered")
	ErrNotFound   = errors.New("user not found")
)

type User struct {
	ID           string
	Email        string
	PasswordHash string
}

type Users struct {
	pool *pgxpool.Pool
}

func NewUsers(pool *pgxpool.Pool) *Users {
	return &Users{pool: pool}
}

func (u *Users) Create(ctx context.Context, email, passwordHash string) (User, error) {
	email = strings.TrimSpace(email)

	var user User
	err := u.pool.QueryRow(ctx,
		`INSERT INTO users (email, password_hash)
		 VALUES ($1, $2)
		 RETURNING id::text, email`,
		email, passwordHash,
	).Scan(&user.ID, &user.Email)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return User{}, ErrEmailTaken
		}
		return User{}, fmt.Errorf("insert user: %w", err)
	}
	return user, nil
}

func (u *Users) GetByEmail(ctx context.Context, email string) (User, error) {
	var user User
	err := u.pool.QueryRow(ctx,
		`SELECT id::text, email, password_hash
		 FROM users
		 WHERE lower(email) = lower($1)`,
		strings.TrimSpace(email),
	).Scan(&user.ID, &user.Email, &user.PasswordHash)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return User{}, ErrNotFound
		}
		return User{}, fmt.Errorf("select user: %w", err)
	}
	return user, nil
}
