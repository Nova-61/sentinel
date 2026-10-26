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
)

type UserLookup interface {
	GetByEmail(ctx context.Context, email string) (store.User, error)
}

type TokenIssuer interface {
	Issue(userID string) (string, time.Time, error)
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
		password.Verify(h.DummyHash, pw) // выравниваем время ответа
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	default:
		h.Logger.Error("lookup user failed", "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	raw, exp, err := h.Tokens.Issue(user.ID)
	if err != nil {
		h.Logger.Error("issue token failed", "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]string{
		"access_token": raw,
		"token_type":   "Bearer",
		"expires_at":   exp.UTC().Format(time.RFC3339),
	})
}
