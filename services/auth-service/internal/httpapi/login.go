package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/Nova-61/sentinel/services/auth-service/internal/password"
	"github.com/Nova-61/sentinel/services/auth-service/internal/store"
	"github.com/Nova-61/sentinel/services/auth-service/internal/token"
)

type UserLookup interface {
	GetByEmail(ctx context.Context, email string) (store.User, error)
}

type TokenIssuer interface {
	Issue(userID string) (token.Issued, error)
}

type SessionStore interface {
	Create(ctx context.Context, jti, userID string, ttl time.Duration) error
}

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()

	var req loginRequest
	if err := dec.Decode(&req); err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			writeError(w, http.StatusRequestEntityTooLarge, "request body too large")
			return
		}
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	pw := []byte(req.Password)
	defer password.Wipe(pw)

	user, err := h.Lookup.GetByEmail(r.Context(), strings.TrimSpace(req.Email))
	switch {
	case err == nil:
		if !password.Verify(user.PasswordHash, pw) {
			writeError(w, http.StatusUnauthorized, "invalid credentials")
			return
		}
	case errors.Is(err, store.ErrNotFound):
		password.Verify(h.DummyHash, pw)
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	default:
		h.Logger.Error("lookup user failed", "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	issued, err := h.Tokens.Issue(user.ID)
	if err != nil {
		h.Logger.Error("issue token failed", "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	// Токен без сессии бесполезен, поэтому при сбое не выдаём его вовсе (fail closed).
	ttl := time.Until(issued.ExpiresAt)
	if err := h.Sessions.Create(r.Context(), issued.ID, user.ID, ttl); err != nil {
		h.Logger.Error("create session failed", "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]string{
		"access_token": issued.Token,
		"token_type":   "Bearer",
		"expires_at":   issued.ExpiresAt.UTC().Format(time.RFC3339),
	})
}
