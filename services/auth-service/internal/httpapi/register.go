package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/mail"
	"strings"

	"github.com/Nova-61/sentinel/services/auth-service/internal/password"
	"github.com/Nova-61/sentinel/services/auth-service/internal/store"
)

// UserStore описывает только то, что нужно обработчику: так его можно тестировать без базы.
type UserStore interface {
	Create(ctx context.Context, email, passwordHash string) (store.User, error)
}

type Handler struct {
	Users     UserStore
	Lookup    UserLookup
	Tokens    TokenIssuer
	DummyHash string
	Logger    *slog.Logger
}

type registerRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func (h *Handler) Register(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()

	var req registerRequest
	if err := dec.Decode(&req); err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			writeError(w, http.StatusRequestEntityTooLarge, "request body too large")
			return
		}
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	email := strings.TrimSpace(req.Email)
	if !validEmail(email) {
		writeError(w, http.StatusBadRequest, "invalid email")
		return
	}

	pw := []byte(req.Password)
	defer password.Wipe(pw)

	hash, err := password.Hash(pw)
	switch {
	case errors.Is(err, password.ErrTooShort):
		writeError(w, http.StatusBadRequest, "password must be at least 12 characters")
		return
	case errors.Is(err, password.ErrTooLong):
		writeError(w, http.StatusBadRequest, "password must be at most 72 bytes")
		return
	case err != nil:
		h.Logger.Error("hash password failed", "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	user, err := h.Users.Create(r.Context(), email, hash)
	if err != nil {
		if errors.Is(err, store.ErrEmailTaken) {
			writeError(w, http.StatusConflict, "email already registered")
			return
		}
		h.Logger.Error("create user failed", "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	writeJSON(w, http.StatusCreated, map[string]string{"id": user.ID, "email": user.Email})
}

func validEmail(s string) bool {
	if s == "" || len(s) > 254 {
		return false
	}
	addr, err := mail.ParseAddress(s)
	return err == nil && addr.Address == s
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
