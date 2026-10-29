package mfa

import (
	"errors"
	"fmt"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

const (
	Period = 30 // секунд в одном шаге
	Digits = otp.DigitsSix
)

// offsets задаёт, какие шаги принимаются: прошлый, текущий и следующий.
var offsets = []int{-1, 0, 1}

type Enrollment struct {
	Secret string // base32, шифруется перед записью в базу
	URL    string // otpauth://, из него строится QR-код
}

func validateOpts() totp.ValidateOpts {
	return totp.ValidateOpts{Period: Period, Skew: 0, Digits: Digits, Algorithm: otp.AlgorithmSHA1}
}

func Generate(issuer, account string) (Enrollment, error) {
	if issuer == "" || account == "" {
		return Enrollment{}, errors.New("issuer and account are required")
	}
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      issuer,
		AccountName: account,
		Period:      Period,
		Digits:      Digits,
		Algorithm:   otp.AlgorithmSHA1,
	})
	if err != nil {
		return Enrollment{}, fmt.Errorf("generate totp key: %w", err)
	}
	return Enrollment{Secret: key.Secret(), URL: key.URL()}, nil
}

// Verify проверяет код и возвращает номер шага, на котором он совпал.
func Verify(secret, code string, now time.Time) (int64, bool) {
	if len(code) != Digits.Length() || !allDigits(code) {
		return 0, false
	}
	for _, off := range offsets {
		t := now.Add(time.Duration(off*Period) * time.Second)
		ok, err := totp.ValidateCustom(code, secret, t, validateOpts())
		if err == nil && ok {
			return t.Unix() / Period, true
		}
	}
	return 0, false
}

func allDigits(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
