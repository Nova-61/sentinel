package secretbox

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
)

const KeyLen = 32 // AES-256

var ErrDecrypt = errors.New("decrypt failed")

type Box struct {
	aead cipher.AEAD
}

func New(key []byte) (*Box, error) {
	if len(key) != KeyLen {
		return nil, fmt.Errorf("key must be exactly %d bytes", KeyLen)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create gcm: %w", err)
	}
	return &Box{aead: aead}, nil
}

// Seal шифрует plaintext. Результат: nonce || шифртекст. aad привязывает данные к контексту.
func (b *Box) Seal(plaintext, aad []byte) ([]byte, error) {
	nonce := make([]byte, b.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}
	return b.aead.Seal(nonce, nonce, plaintext, aad), nil
}

// Open расшифровывает данные из Seal. При любой проблеме возвращает ErrDecrypt.
func (b *Box) Open(data, aad []byte) ([]byte, error) {
	ns := b.aead.NonceSize()
	if len(data) < ns+b.aead.Overhead() {
		return nil, ErrDecrypt
	}
	plaintext, err := b.aead.Open(nil, data[:ns], data[ns:], aad)
	if err != nil {
		return nil, ErrDecrypt
	}
	return plaintext, nil
}
