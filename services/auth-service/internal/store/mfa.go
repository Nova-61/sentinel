package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
)

var (
	ErrMFAAlreadyEnabled = errors.New("mfa already enabled")
	ErrNoPendingMFA      = errors.New("no pending mfa enrollment")
)

type MFAState struct {
	SecretEnc []byte
	Enabled   bool
}

// EmailByID возвращает только адрес, без хеша пароля.
func (u *Users) EmailByID(ctx context.Context, userID string) (string, error) {
	var email string
	err := u.pool.QueryRow(ctx,
		`SELECT email FROM users WHERE id = $1::uuid`, userID,
	).Scan(&email)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", ErrNotFound
		}
		return "", fmt.Errorf("select email: %w", err)
	}
	return email, nil
}

// SetPendingTOTP сохраняет зашифрованный секрет для будущего включения MFA.
func (u *Users) SetPendingTOTP(ctx context.Context, userID string, secretEnc []byte) error {
	tag, err := u.pool.Exec(ctx,
		`UPDATE users
		 SET totp_secret_enc = $1
		 WHERE id = $2::uuid AND totp_enabled = FALSE`,
		secretEnc, userID,
	)
	if err != nil {
		return fmt.Errorf("set pending totp: %w", err)
	}
	if tag.RowsAffected() == 0 {
		// Либо пользователя нет, либо MFA уже включен.
		return ErrMFAAlreadyEnabled
	}
	return nil
}

// GetTOTP возвращает состояние MFA пользователя.
func (u *Users) GetTOTP(ctx context.Context, userID string) (MFAState, error) {
	var st MFAState
	err := u.pool.QueryRow(ctx,
		`SELECT totp_secret_enc, totp_enabled
		 FROM users
		 WHERE id = $1::uuid`,
		userID,
	).Scan(&st.SecretEnc, &st.Enabled)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return MFAState{}, ErrNotFound
		}
		return MFAState{}, fmt.Errorf("get totp state: %w", err)
	}
	return st, nil
}

// EnableTOTP включает MFA, но только если переданный секрет совпадает с ожидающим.
func (u *Users) EnableTOTP(ctx context.Context, userID string, secretEnc []byte) error {
	tag, err := u.pool.Exec(ctx,
		`UPDATE users
		 SET totp_enabled = TRUE
		 WHERE id = $1::uuid AND totp_enabled = FALSE AND totp_secret_enc = $2`,
		userID, secretEnc,
	)
	if err != nil {
		return fmt.Errorf("enable totp: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNoPendingMFA
	}
	return nil
}
