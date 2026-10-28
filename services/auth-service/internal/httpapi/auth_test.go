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
	"time"

	"github.com/Nova-61/sentinel/services/auth-service/internal/token"
)

type fakeChecker struct {
	sessions map[string]string // jti -> userID
	err      error
}

func (f *fakeChecker) Active(_ context.Context, jti, userID string) (bool, error) {
	if f.err != nil {
		return false, f.err
	}
	owner, ok := f.sessions[jti]
	return ok && owner == userID, nil
}

func (f *fakeChecker) Revoke(_ context.Context, jti string) error {
	if f.err != nil {
		return f.err
	}
	delete(f.sessions, jti)
	return nil
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewJSONHandler(io.Discard, nil))
}

func newAuthMux(t *testing.T, fc *fakeChecker) (*http.ServeMux, *token.Manager) {
	t.Helper()
	tm, err := token.NewManager(testJWTKey, time.Minute)
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	h := &Handler{Parser: tm, Checker: fc, Logger: discardLogger()}
	mux := http.NewServeMux()
	mux.Handle("GET /validate", h.Authenticate(http.HandlerFunc(h.Validate)))
	mux.Handle("POST /logout", h.Authenticate(http.HandlerFunc(h.Logout)))
	return mux, tm
}

func issueFor(t *testing.T, tm *token.Manager, fc *fakeChecker, userID string) string {
	t.Helper()
	issued, err := tm.Issue(userID)
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}
	fc.sessions[issued.ID] = userID
	return issued.Token
}

func doAuth(mux *http.ServeMux, method, path, authz string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, nil)
	if authz != "" {
		req.Header.Set("Authorization", authz)
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

func TestValidateAcceptsLiveSession(t *testing.T) {
	fc := &fakeChecker{sessions: map[string]string{}}
	mux, tm := newAuthMux(t, fc)
	tok := issueFor(t, tm, fc, "user-1")

	rec := doAuth(mux, http.MethodGet, "/validate", "Bearer "+tok)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"user-1"`) {
		t.Errorf("body %q does not contain the user id", rec.Body.String())
	}
}

func TestAuthenticateRejects(t *testing.T) {
	fc := &fakeChecker{sessions: map[string]string{}}
	mux, tm := newAuthMux(t, fc)

	foreignTM, err := token.NewManager([]byte("ffffffffffffffffffffffffffffffff"), time.Minute)
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	foreign := issueFor(t, foreignTM, fc, "user-1")

	noSession, err := tm.Issue("user-1")
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}

	wrongOwner, err := tm.Issue("user-1")
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}
	fc.sessions[wrongOwner.ID] = "user-2"

	tests := []struct {
		name  string
		authz string
	}{
		{"no header", ""},
		{"wrong scheme", "Basic dXNlcjpwYXNz"},
		{"empty bearer", "Bearer "},
		{"garbage token", "Bearer not.a.token"},
		{"signed with another key", "Bearer " + foreign},
		{"no session in store", "Bearer " + noSession.Token},
		{"session of another user", "Bearer " + wrongOwner.Token},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := doAuth(mux, http.MethodGet, "/validate", tt.authz)
			if rec.Code != http.StatusUnauthorized {
				t.Errorf("status = %d, want 401, body: %s", rec.Code, rec.Body.String())
			}
			if rec.Header().Get("WWW-Authenticate") == "" {
				t.Error("WWW-Authenticate header is missing")
			}
		})
	}
}

func TestAuthenticateFailsClosedWhenSessionStoreDown(t *testing.T) {
	fc := &fakeChecker{sessions: map[string]string{}}
	mux, tm := newAuthMux(t, fc)
	tok := issueFor(t, tm, fc, "user-1")
	fc.err = errors.New("redis down")

	rec := doAuth(mux, http.MethodGet, "/validate", "Bearer "+tok)
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "user-1") {
		t.Errorf("response leaks user id while the session store is down: %s", rec.Body.String())
	}
}

func TestLogoutRevokesSession(t *testing.T) {
	fc := &fakeChecker{sessions: map[string]string{}}
	mux, tm := newAuthMux(t, fc)
	authz := "Bearer " + issueFor(t, tm, fc, "user-1")

	if rec := doAuth(mux, http.MethodGet, "/validate", authz); rec.Code != http.StatusOK {
		t.Fatalf("before logout: status = %d, want 200", rec.Code)
	}
	if rec := doAuth(mux, http.MethodPost, "/logout", authz); rec.Code != http.StatusNoContent {
		t.Fatalf("logout: status = %d, want 204", rec.Code)
	}
	if rec := doAuth(mux, http.MethodGet, "/validate", authz); rec.Code != http.StatusUnauthorized {
		t.Errorf("after logout: status = %d, want 401: the token still works", rec.Code)
	}
}

func TestRecoverTurnsPanicInto500(t *testing.T) {
	h := &Handler{Logger: discardLogger()}
	panicking := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("boom internal detail")
	})

	rec := httptest.NewRecorder()
	h.Recover(panicking).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "boom") {
		t.Errorf("response leaks panic details: %s", rec.Body.String())
	}
}
