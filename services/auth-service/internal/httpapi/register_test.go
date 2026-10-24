package httpapi

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Nova-61/sentinel/services/auth-service/internal/store"
)

type fakeStore struct {
	err   error
	email string
	hash  string
}

func (f *fakeStore) Create(_ context.Context, email, hash string) (store.User, error) {
	f.email, f.hash = email, hash
	if f.err != nil {
		return store.User{}, f.err
	}
	return store.User{ID: "id-1", Email: email}, nil
}

const okBody = `{"email":"a@example.com","password":"correct horse battery"}`

func call(h *Handler, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/register", strings.NewReader(body))
	rec := httptest.NewRecorder()
	h.Register(rec, req)
	return rec
}

func newHandler(fs *fakeStore) *Handler {
	return &Handler{Users: fs, Logger: slog.New(slog.NewJSONHandler(io.Discard, nil))}
}

func TestRegisterStatuses(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		storeErr error
		want     int
	}{
		{"ok", okBody, nil, http.StatusCreated},
		{"bad json", `{`, nil, http.StatusBadRequest},
		{"unknown field", `{"email":"a@example.com","password":"correct horse battery","admin":true}`, nil, http.StatusBadRequest},
		{"bad email", `{"email":"not-an-email","password":"correct horse battery"}`, nil, http.StatusBadRequest},
		{"short password", `{"email":"a@example.com","password":"short"}`, nil, http.StatusBadRequest},
		{"email taken", okBody, store.ErrEmailTaken, http.StatusConflict},
		{"store failure", okBody, errors.New("db down"), http.StatusInternalServerError},
		{"body too large", `{"email":"a@example.com","password":"` + strings.Repeat("a", 5000) + `"}`, nil, http.StatusRequestEntityTooLarge},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := call(newHandler(&fakeStore{err: tt.storeErr}), tt.body)
			if rec.Code != tt.want {
				t.Errorf("status = %d, want %d, body: %s", rec.Code, tt.want, rec.Body.String())
			}
		})
	}
}

func TestRegisterStoresHashOnly(t *testing.T) {
	fs := &fakeStore{}
	rec := call(newHandler(fs), okBody)

	if fs.hash == "correct horse battery" || !strings.HasPrefix(fs.hash, "$2") {
		t.Errorf("store received %q, want a bcrypt hash", fs.hash)
	}
	out := rec.Body.String()
	if strings.Contains(out, "correct horse battery") || strings.Contains(out, fs.hash) {
		t.Errorf("response leaks password or hash: %s", out)
	}
}
