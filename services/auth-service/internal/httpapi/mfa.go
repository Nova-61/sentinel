package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/Nova-61/sentinel/services/auth-service/internal/mfa"
	"github.com/Nova-61/sentinel/services/auth-service/internal/store"
)

const mfaIssuer = "Sentinel"

type MFAStore interface {
	SetPendingTOTP(ctx context.Context, userID string, secretEnc []byte) error
	GetTOTP(ctx context.Context, userID string) (store.MFAState, error)
	EnableTOTP(ctx context.Context, userID string, secretEnc []byte) error
	EmailByID(ctx context.Context, userID string) (string, error)
}

type SecretBox interface {
	Seal(plaintext, aad []byte) ([]byte, error)
	Open(data, aad []byte) ([]byte, error)
}

func (h *Handler) now() time.Time {
	if h.Now != nil {
		return h.Now()
	}
	return time.Now()
}

func (h *Handler) internalError(w http.ResponseWriter, msg string, err error) {
	h.Logger.Error(msg, "error", err)
	writeError(w, http.StatusInternalServerError, "internal error")
}

// MFAEnroll создаёт секрет TOTP и сохраняет его зашифрованным. MFA пока не включён.
func (h *Handler) MFAEnroll(w http.ResponseWriter, r *http.Request) {
	p, ok := principalFrom(r.Context())
	if !ok {
		unauthorized(w)
		return
	}

	st, err := h.MFA.GetTOTP(r.Context(), p.UserID)
	if err != nil {
		h.internalError(w, "load mfa state failed", err)
		return
	}
	if st.Enabled {
		writeError(w, http.StatusConflict, "mfa already enabled")
		return
	}

	email, err := h.MFA.EmailByID(r.Context(), p.UserID)
	if err != nil {
		h.internalError(w, "load email failed", err)
		return
	}
	enr, err := mfa.Generate(mfaIssuer, email)
	if err != nil {
		h.internalError(w, "generate totp failed", err)
		return
	}

	secret := []byte(enr.Secret)
	defer clear(secret)

	sealed, err := h.Box.Seal(secret, []byte(p.UserID))
	if err != nil {
		h.internalError(w, "seal totp secret failed", err)
		return
	}
	if err := h.MFA.SetPendingTOTP(r.Context(), p.UserID, sealed); err != nil {
		if errors.Is(err, store.ErrMFAAlreadyEnabled) {
			writeError(w, http.StatusConflict, "mfa already enabled")
			return
		}
		h.internalError(w, "save pending totp failed", err)
		return
	}

	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]string{"secret": enr.Secret, "otpauth_url": enr.URL})
}

// MFAConfirm включает MFA после первого верного кода.
func (h *Handler) MFAConfirm(w http.ResponseWriter, r *http.Request) {
	p, ok := principalFrom(r.Context())
	if !ok {
		unauthorized(w)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1<<10)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	var req struct {
		Code string `json:"code"`
	}
	if err := dec.Decode(&req); err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			writeError(w, http.StatusRequestEntityTooLarge, "request body too large")
			return
		}
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	st, err := h.MFA.GetTOTP(r.Context(), p.UserID)
	if err != nil {
		h.internalError(w, "load mfa state failed", err)
		return
	}
	if st.Enabled {
		writeError(w, http.StatusConflict, "mfa already enabled")
		return
	}
	if len(st.SecretEnc) == 0 {
		writeError(w, http.StatusConflict, "no pending enrollment")
		return
	}

	secret, err := h.Box.Open(st.SecretEnc, []byte(p.UserID))
	if err != nil {
		h.internalError(w, "open totp secret failed", err)
		return
	}
	defer clear(secret)

	if _, ok := mfa.Verify(string(secret), req.Code, h.now()); !ok {
		writeError(w, http.StatusBadRequest, "invalid code")
		return
	}

	if err := h.MFA.EnableTOTP(r.Context(), p.UserID, st.SecretEnc); err != nil {
		if errors.Is(err, store.ErrNoPendingMFA) {
			writeError(w, http.StatusConflict, "enrollment changed, start again")
			return
		}
		h.internalError(w, "enable totp failed", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
