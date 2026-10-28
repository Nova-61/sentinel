package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"

	"github.com/Nova-61/sentinel/services/auth-service/internal/secretbox"
	"github.com/Nova-61/sentinel/services/auth-service/internal/store"
	"github.com/Nova-61/sentinel/services/auth-service/internal/token"
)

var mfaNow = time.Unix(1_700_000_010, 0)

type fakeMFAStore struct {
	email string
	st    store.MFAState
}

func (f *fakeMFAStore) SetPendingTOTP(_ context.Context, _ string, enc []byte) error {
	f.st.SecretEnc = enc
	return nil
}

func (f *fakeMFAStore) GetTOTP(context.Context, string) (store.MFAState, error) {
	return f.st, nil
}

func (f *fakeMFAStore) EnableTOTP(_ context.Context, _ string, enc []byte) error {
	if !bytes.Equal(enc, f.st.SecretEnc) {
		return store.ErrNoPendingMFA
	}
	f.st.Enabled = true
	return nil
}

func (f *fakeMFAStore) EmailByID(context.Context, string) (string, error) {
	return f.email, nil
}

type mfaEnv struct {
	mux   *http.ServeMux
	fs    *fakeMFAStore
	box   *secretbox.Box
	authz string
}

func newMFAEnv(t *testing.T) *mfaEnv {
	t.Helper()
	tm, err := token.NewManager(testJWTKey, time.Minute)
	if err != nil {
		t.Fatalf("token.NewManager() error = %v", err)
	}
	box, err := secretbox.New(bytes.Repeat([]byte{7}, secretbox.KeyLen))
	if err != nil {
		t.Fatalf("secretbox.New() error = %v", err)
	}
	fs := &fakeMFAStore{email: "user@example.com"}
	fc := &fakeChecker{sessions: map[string]string{}}
	h := &Handler{
		Parser:  tm,
		Checker: fc,
		MFA:     fs,
		Box:     box,
		Now:     func() time.Time { return mfaNow },
		Logger:  discardLogger(),
	}
	mux := http.NewServeMux()
	mux.Handle("POST /mfa/enroll", h.Authenticate(http.HandlerFunc(h.MFAEnroll)))
	mux.Handle("POST /mfa/confirm", h.Authenticate(http.HandlerFunc(h.MFAConfirm)))
	return &mfaEnv{mux: mux, fs: fs, box: box, authz: "Bearer " + issueFor(t, tm, fc, "user-1")}
}

func (e *mfaEnv) post(path, authz, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	if authz != "" {
		req.Header.Set("Authorization", authz)
	}
	rec := httptest.NewRecorder()
	e.mux.ServeHTTP(rec, req)
	return rec
}

type enrollResp struct {
	Secret string `json:"secret"`
	URL    string `json:"otpauth_url"`
}

func decodeEnroll(t *testing.T, rec *httptest.ResponseRecorder) enrollResp {
	t.Helper()
	if rec.Code != http.StatusOK {
		t.Fatalf("enroll status = %d, want 200, body: %s", rec.Code, rec.Body.String())
	}
	var resp enrollResp
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("enroll response is not JSON: %v", err)
	}
	return resp
}

func TestMFAEnrollStoresEncryptedSecretBoundToUser(t *testing.T) {
	e := newMFAEnv(t)
	rec := e.post("/mfa/enroll", e.authz, "")
	resp := decodeEnroll(t, rec)

	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Error("Cache-Control: no-store is missing on the secret response")
	}
	if resp.Secret == "" || !strings.HasPrefix(resp.URL, "otpauth://totp/") {
		t.Errorf("response = %+v, want a secret and an otpauth URL", resp)
	}

	enc := e.fs.st.SecretEnc
	if len(enc) == 0 || bytes.Contains(enc, []byte(resp.Secret)) {
		t.Fatal("secret is missing or stored in plaintext")
	}
	if got, err := e.box.Open(enc, []byte("user-1")); err != nil || string(got) != resp.Secret {
		t.Errorf("Open() with the owner's AAD = %q, %v, want the secret", got, err)
	}
	if _, err := e.box.Open(enc, []byte("user-2")); err == nil {
		t.Error("the stored secret opens with another user's AAD")
	}
	if e.fs.st.Enabled {
		t.Error("MFA became enabled right after enrollment, before any code was confirmed")
	}
}

func TestMFAEnrollRejectsWhenAlreadyEnabled(t *testing.T) {
	e := newMFAEnv(t)
	e.fs.st = store.MFAState{SecretEnc: []byte("old"), Enabled: true}

	rec := e.post("/mfa/enroll", e.authz, "")
	if rec.Code != http.StatusConflict {
		t.Errorf("status = %d, want 409", rec.Code)
	}
	if string(e.fs.st.SecretEnc) != "old" {
		t.Error("the secret of a user with MFA enabled was replaced")
	}
}

func TestMFAConfirmEnablesOnlyWithValidCode(t *testing.T) {
	e := newMFAEnv(t)
	secret := decodeEnroll(t, e.post("/mfa/enroll", e.authz, "")).Secret

	valid := map[string]bool{}
	for _, d := range []time.Duration{-30 * time.Second, 0, 30 * time.Second} {
		c, err := totp.GenerateCode(secret, mfaNow.Add(d))
		if err != nil {
			t.Fatalf("GenerateCode() error = %v", err)
		}
		valid[c] = true
	}
	wrong := "000000"
	if valid[wrong] {
		wrong = "111111"
	}

	if rec := e.post("/mfa/confirm", e.authz, `{"code":"`+wrong+`"}`); rec.Code != http.StatusBadRequest {
		t.Errorf("wrong code: status = %d, want 400", rec.Code)
	}
	if e.fs.st.Enabled {
		t.Fatal("MFA was enabled with a wrong code")
	}

	good, err := totp.GenerateCode(secret, mfaNow)
	if err != nil {
		t.Fatalf("GenerateCode() error = %v", err)
	}
	if rec := e.post("/mfa/confirm", e.authz, `{"code":"`+good+`"}`); rec.Code != http.StatusNoContent {
		t.Fatalf("valid code: status = %d, want 204, body: %s", rec.Code, rec.Body.String())
	}
	if !e.fs.st.Enabled {
		t.Error("MFA is not enabled after a valid code")
	}
	if rec := e.post("/mfa/confirm", e.authz, `{"code":"`+good+`"}`); rec.Code != http.StatusConflict {
		t.Errorf("second confirm: status = %d, want 409", rec.Code)
	}
}

func TestMFAConfirmWithoutEnrollment(t *testing.T) {
	e := newMFAEnv(t)
	if rec := e.post("/mfa/confirm", e.authz, `{"code":"123456"}`); rec.Code != http.StatusConflict {
		t.Errorf("status = %d, want 409", rec.Code)
	}
}

func TestMFAConfirmRejectsMalformedBody(t *testing.T) {
	e := newMFAEnv(t)
	for _, body := range []string{`{`, `{"code":"123456","admin":true}`, ``} {
		if rec := e.post("/mfa/confirm", e.authz, body); rec.Code != http.StatusBadRequest {
			t.Errorf("body %q: status = %d, want 400", body, rec.Code)
		}
	}
}

func TestMFARequiresAuth(t *testing.T) {
	e := newMFAEnv(t)
	for _, path := range []string{"/mfa/enroll", "/mfa/confirm"} {
		if rec := e.post(path, "", `{"code":"123456"}`); rec.Code != http.StatusUnauthorized {
			t.Errorf("%s without a token: status = %d, want 401", path, rec.Code)
		}
	}
}
