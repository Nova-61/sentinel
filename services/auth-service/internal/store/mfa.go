package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
)

var (
	ErrMFAAlreadyEnabled = errors.New("mfa already enabled")
	ErrNoPendingMFA      = errors.New("no matching pending mfa enrollment")
)

// MFAState описывает состояние второго фактора. Секрет всегда зашифрован.
type MFAState struct {
	SecretEnc []byte
	Enabled   bool
}

// SetPendingTOTP сохраняет секрет, но не включает MFA. Пока MFA включён, секрет менять нельзя.
func (u *Users) SetPendingTOTP(ctx context.Context, userID string, secretEnc []byte) error {
	tag, err := u.pool.Exec(ctx,
		`UPDATE users SET totp_secret_enc = $2
		 WHERE id = $1::uuid AND totp_enabled = FALSE`,
		userID, secretEnc)
	if err != nil {
		return fmt.Errorf("set pending totp: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrMFAAlreadyEnabled
	}
	return nil
}

func (u *Users) GetTOTP(ctx context.Context, userID string) (MFAState, error) {
	var st MFAState
	err := u.pool.QueryRow(ctx,
		`SELECT totp_secret_enc, totp_enabled FROM users WHERE id = $1::uuid`,
		userID,
	).Scan(&st.SecretEnc, &st.Enabled)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return MFAState{}, ErrNotFound
		}
		return MFAState{}, fmt.Errorf("select totp: %w", err)
	}
	return st, nil
}

// EnableTOTP включает MFA, только если в базе лежит ровно тот секрет, который проверили.
func (u *Users) EnableTOTP(ctx context.Context, userID string, secretEnc []byte) error {
	tag, err := u.pool.Exec(ctx,
		`UPDATE users SET totp_enabled = TRUE
		 WHERE id = $1::uuid AND totp_enabled = FALSE AND totp_secret_enc = $2`,
		userID, secretEnc)
	if err != nil {
		return fmt.Errorf("enable totp: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNoPendingMFA
	}
	return nil
}

