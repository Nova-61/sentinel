package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Nova-61/sentinel/services/auth-service/internal/password"
	"github.com/Nova-61/sentinel/services/auth-service/internal/store"
	"github.com/Nova-61/sentinel/services/auth-service/internal/token"
)

const loginPW = "correct horse battery"

var testJWTKey = []byte("0123456789abcdef0123456789abcdef")

type fakeLookup struct {
	user store.User
	err  error
}

func (f fakeLookup) GetByEmail(context.Context, string) (store.User, error) {
	return f.user, f.err
}

func newLoginHandler(t *testing.T, lookup fakeLookup) (*Handler, *token.Manager) {
	t.Helper()
	tm, err := token.NewManager(testJWTKey, time.Minute)
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	dummy, err := password.Hash([]byte("timing-equalizer-password"))
	if err != nil {
		t.Fatalf("Hash() error = %v", err)
	}
	return &Handler{
		Lookup:    lookup,
		Tokens:    tm,
		Sessions:  &fakeSessions{},
		DummyHash: dummy,
		Logger:    slog.New(slog.NewJSONHandler(io.Discard, nil)),
	}, tm
}

func doLogin(h *Handler, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(body))
	rec := httptest.NewRecorder()
	h.Login(rec, req)
	return rec
}

func existingUser(t *testing.T) fakeLookup {
	t.Helper()
	hash, err := password.Hash([]byte(loginPW))
	if err != nil {
		t.Fatalf("Hash() error = %v", err)
	}
	return fakeLookup{user: store.User{ID: "id-1", Email: "a@example.com", PasswordHash: hash}}
}

func TestLoginSuccess(t *testing.T) {
	h, tm := newLoginHandler(t, existingUser(t))
	rec := doLogin(h, `{"email":"a@example.com","password":"`+loginPW+`"}`)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body: %s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Error("Cache-Control: no-store is missing on the token response")
	}
	var resp struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("response is not JSON: %v", err)
	}
	claims, err := tm.Parse(resp.AccessToken)
	if err != nil {
		t.Fatalf("issued token does not parse: %v", err)
	}
	if claims.Subject != "id-1" || resp.TokenType != "Bearer" {
		t.Errorf("subject = %q, type = %q", claims.Subject, resp.TokenType)
	}
}

func TestLoginBadCredentialsLookTheSame(t *testing.T) {
	hWrong, _ := newLoginHandler(t, existingUser(t))
	hMissing, _ := newLoginHandler(t, fakeLookup{err: store.ErrNotFound})

	wrong := doLogin(hWrong, `{"email":"a@example.com","password":"wrong password here"}`)

	start := time.Now()
	unknown := doLogin(hMissing, `{"email":"nobody@example.com","password":"wrong password here"}`)
	elapsed := time.Since(start)

	if wrong.Code != http.StatusUnauthorized || unknown.Code != http.StatusUnauthorized {
		t.Fatalf("statuses = %d and %d, want 401 and 401", wrong.Code, unknown.Code)
	}
	if wrong.Body.String() != unknown.Body.String() {
		t.Errorf("bodies differ: %q vs %q", wrong.Body.String(), unknown.Body.String())
	}
	if elapsed < 50*time.Millisecond {
		t.Errorf("unknown email answered in %v: no dummy hash comparison, timing reveals which emails exist", elapsed)
	}
}

func TestLoginStatuses(t *testing.T) {
	tests := []struct {
		name string
		body string
		err  error
		want int
	}{
		{"bad json", `{`, nil, http.StatusBadRequest},
		{"unknown field", `{"email":"a@example.com","password":"x","admin":true}`, nil, http.StatusBadRequest},
		{"store failure", `{"email":"a@example.com","password":"x"}`, errors.New("db down"), http.StatusInternalServerError},
		{"body too large", `{"email":"a@example.com","password":"` + strings.Repeat("a", 5000) + `"}`, nil, http.StatusRequestEntityTooLarge},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h, _ := newLoginHandler(t, fakeLookup{err: tt.err})
			rec := doLogin(h, tt.body)
			if rec.Code != tt.want {
				t.Errorf("status = %d, want %d, body: %s", rec.Code, tt.want, rec.Body.String())
			}
		})
	}
}

type fakeSessions struct {
	err    error
	jti    string
	userID string
	ttl    time.Duration
}

func (f *fakeSessions) Create(_ context.Context, jti, userID string, ttl time.Duration) error {
	f.jti, f.userID, f.ttl = jti, userID, ttl
	return f.err
}

func TestLoginCreatesSessionForIssuedToken(t *testing.T) {
	h, tm := newLoginHandler(t, existingUser(t))
	fs := &fakeSessions{}
	h.Sessions = fs

	rec := doLogin(h, `{"email":"a@example.com","password":"`+loginPW+`"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body: %s", rec.Code, rec.Body.String())
	}

	var resp struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("response is not JSON: %v", err)
	}
	claims, err := tm.Parse(resp.AccessToken)
	if err != nil {
		t.Fatalf("issued token does not parse: %v", err)
	}
	if fs.jti == "" || fs.jti != claims.ID {
		t.Errorf("session jti = %q, token jti = %q", fs.jti, claims.ID)
	}
	if fs.userID != "id-1" {
		t.Errorf("session userID = %q, want id-1", fs.userID)
	}
	if fs.ttl <= 0 || fs.ttl > time.Minute {
		t.Errorf("session ttl = %v, want within (0, 1m]", fs.ttl)
	}
}

func TestLoginFailsClosedWhenSessionStoreDown(t *testing.T) {
	h, _ := newLoginHandler(t, existingUser(t))
	h.Sessions = &fakeSessions{err: errors.New("redis down")}

	rec := doLogin(h, `{"email":"a@example.com","password":"`+loginPW+`"}`)
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "access_token") {
		t.Error("a token was issued even though the session could not be stored")
	}
}
