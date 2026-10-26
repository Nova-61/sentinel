package token

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	issuer    = "sentinel-auth"
	audience  = "sentinel"
	MinKeyLen = 32
)

var ErrInvalidToken = errors.New("invalid token")

type Manager struct {
	key []byte
	ttl time.Duration
	now func() time.Time
}

// Issued описывает выданный токен вместе с идентификатором для сессии.
type Issued struct {
	Token     string
	ID        string // jti: по нему сессия ищется в Redis
	ExpiresAt time.Time
}

func NewManager(key []byte, ttl time.Duration) (*Manager, error) {
	if len(key) < MinKeyLen {
		return nil, fmt.Errorf("signing key must be at least %d bytes", MinKeyLen)
	}
	if ttl <= 0 {
		return nil, errors.New("ttl must be positive")
	}
	return &Manager{key: key, ttl: ttl, now: time.Now}, nil
}

// Issue выдаёт подписанный токен для пользователя.
func (m *Manager) Issue(userID string) (Issued, error) {
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		return Issued{}, fmt.Errorf("generate token id: %w", err)
	}
	jti := hex.EncodeToString(id)

	now := m.now()
	exp := now.Add(m.ttl)
	claims := jwt.RegisteredClaims{
		Issuer:    issuer,
		Subject:   userID,
		Audience:  jwt.ClaimStrings{audience},
		IssuedAt:  jwt.NewNumericDate(now),
		NotBefore: jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(exp),
		ID:        jti,
	}

	signed, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(m.key)
	if err != nil {
		return Issued{}, fmt.Errorf("sign token: %w", err)
	}
	return Issued{Token: signed, ID: jti, ExpiresAt: exp}, nil
}

// Parse проверяет подпись, алгоритм, издателя, адресата и срок.
func (m *Manager) Parse(raw string) (*jwt.RegisteredClaims, error) {
	claims := &jwt.RegisteredClaims{}
	tok, err := jwt.ParseWithClaims(raw, claims,
		func(*jwt.Token) (any, error) { return m.key, nil },
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
		jwt.WithIssuer(issuer),
		jwt.WithAudience(audience),
		jwt.WithExpirationRequired(),
		jwt.WithTimeFunc(m.now),
	)
	if err != nil || !tok.Valid {
		return nil, ErrInvalidToken
	}
	return claims, nil
}
