package password

import (
	"errors"
	"unicode/utf8"

	"golang.org/x/crypto/bcrypt"
)

const (
	MinLength = 12 // символов
	MaxBytes  = 72 // предел самого bcrypt
	cost      = 12
)

var (
	ErrTooShort = errors.New("password too short")
	ErrTooLong  = errors.New("password too long")
)

func Hash(pw []byte) (string, error) {
	if utf8.RuneCount(pw) < MinLength {
		return "", ErrTooShort
	}
	if len(pw) > MaxBytes {
		return "", ErrTooLong
	}
	h, err := bcrypt.GenerateFromPassword(pw, cost)
	if err != nil {
		return "", err
	}
	return string(h), nil
}

func Verify(hash string, pw []byte) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), pw) == nil
}

// Wipe затирает пароль в памяти после использования.
func Wipe(b []byte) {
	clear(b)
}
