package httpapi

import (
	"context"
	"fmt"
	"net/http"
	"runtime/debug"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

// TokenParser проверяет токен и возвращает его claims.
type TokenParser interface {
	Parse(raw string) (*jwt.RegisteredClaims, error)
}

// SessionChecker работает с состоянием сессий в хранилище.
type SessionChecker interface {
	Active(ctx context.Context, jti, userID string) (bool, error)
	Revoke(ctx context.Context, jti string) error
}

type ctxKey struct{}

// Principal описывает, кто сделал запрос, после проверки токена и сессии.
type Principal struct {
	UserID string
	JTI    string
}

func principalFrom(ctx context.Context) (Principal, bool) {
	p, ok := ctx.Value(ctxKey{}).(Principal)
	return p, ok
}

func bearerToken(r *http.Request) (string, bool) {
	scheme, tok, found := strings.Cut(r.Header.Get("Authorization"), " ")
	tok = strings.TrimSpace(tok)
	if !found || !strings.EqualFold(scheme, "Bearer") || tok == "" {
		return "", false
	}
	return tok, true
}

func unauthorized(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", "Bearer")
	writeError(w, http.StatusUnauthorized, "unauthorized")
}

// Authenticate пропускает запрос дальше, только если токен верен и сессия жива.
func (h *Handler) Authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, ok := bearerToken(r)
		if !ok {
			unauthorized(w)
			return
		}

		claims, err := h.Parser.Parse(raw)
		if err != nil || claims.Subject == "" || claims.ID == "" {
			unauthorized(w)
			return
		}

		active, err := h.Checker.Active(r.Context(), claims.ID, claims.Subject)
		if err != nil {
			// Не знаем, жива ли сессия: не пускаем (fail closed).
			h.Logger.Error("check session failed", "error", err)
			writeError(w, http.StatusServiceUnavailable, "service unavailable")
			return
		}
		if !active {
			unauthorized(w)
			return
		}

		ctx := context.WithValue(r.Context(), ctxKey{}, Principal{UserID: claims.Subject, JTI: claims.ID})
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// Validate отвечает 200 и id пользователя. Его вызывает gateway.
func (h *Handler) Validate(w http.ResponseWriter, r *http.Request) {
	p, ok := principalFrom(r.Context())
	if !ok {
		unauthorized(w)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]string{"user_id": p.UserID})
}

// Logout отзывает сессию текущего токена.
func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	p, ok := principalFrom(r.Context())
	if !ok {
		unauthorized(w)
		return
	}
	if err := h.Checker.Revoke(r.Context(), p.JTI); err != nil {
		h.Logger.Error("revoke session failed", "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// Recover превращает панику в обработчике в лог и ответ 500 без деталей.
func (h *Handler) Recover(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				if rec == http.ErrAbortHandler {
					panic(rec)
				}
				h.Logger.Error("panic in handler",
					"panic", fmt.Sprint(rec),
					"path", r.URL.Path,
					"stack", string(debug.Stack()))
				writeError(w, http.StatusInternalServerError, "internal error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}
