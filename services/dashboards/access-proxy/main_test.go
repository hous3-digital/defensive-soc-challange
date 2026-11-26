package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

const testAUD = "test-aud-tag"

type fixture struct {
	key      *rsa.PrivateKey
	issuer   string
	handler  http.Handler
	upstream *httptest.Server
	lastReq  *http.Request
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f.key = key

	jwks := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/cdn-cgi/access/certs" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
			{Key: &key.PublicKey, KeyID: "k1", Algorithm: "RS256", Use: "sig"},
		}})
	}))
	t.Cleanup(jwks.Close)
	f.issuer = jwks.URL

	f.upstream = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.lastReq = r.Clone(context.Background())
		_, _ = io.WriteString(w, "upstream")
	}))
	t.Cleanup(f.upstream.Close)
	upstreamURL, _ := url.Parse(f.upstream.URL)

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := &config{upstream: upstreamURL, issuer: f.issuer, audience: testAUD}
	f.handler = newHandler(newAuthenticator(context.Background(), cfg, log), upstreamURL, log)
	return f
}

func (f *fixture) token(t *testing.T, mutate func(map[string]any)) string {
	t.Helper()
	now := time.Now()
	claims := map[string]any{
		"iss":   f.issuer,
		"aud":   []string{testAUD},
		"sub":   "user-id",
		"email": "analyst@example.com",
		"iat":   now.Unix(),
		"exp":   now.Add(5 * time.Minute).Unix(),
	}
	if mutate != nil {
		mutate(claims)
	}
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: jose.JSONWebKey{Key: f.key, KeyID: "k1"}},
		(&jose.SignerOptions{}).WithType("JWT"),
	)
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(claims)
	jws, err := signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	out, err := jws.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func (f *fixture) do(token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/app/home", nil)
	if token != "" {
		req.Header.Set(assertionHeader, token)
	}
	req.Header.Set("X-Forwarded-User", "spoofed@example.com")
	rec := httptest.NewRecorder()
	f.handler.ServeHTTP(rec, req)
	return rec
}

func TestValidAssertionIsForwardedWithIdentity(t *testing.T) {
	f := newFixture(t)
	rec := f.do(f.token(t, nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if got := f.lastReq.Header.Get("X-Forwarded-User"); got != "analyst@example.com" {
		t.Errorf("X-Forwarded-User = %q, want analyst@example.com", got)
	}
	if f.lastReq.Header.Get(assertionHeader) != "" {
		t.Error("assertion header must not reach upstream")
	}
}

func TestRejectedAssertions(t *testing.T) {
	f := newFixture(t)
	otherKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	cases := map[string]string{
		"missing":      "",
		"garbage":      "not-a-jwt",
		"wrong aud":    f.token(t, func(c map[string]any) { c["aud"] = []string{"other-app"} }),
		"wrong issuer": f.token(t, func(c map[string]any) { c["iss"] = "https://evil.cloudflareaccess.com" }),
		"expired":      f.token(t, func(c map[string]any) { c["exp"] = time.Now().Add(-time.Minute).Unix() }),
	}
	bad := *f
	bad.key = otherKey
	cases["wrong signature"] = bad.token(t, nil)

	for name, tok := range cases {
		t.Run(name, func(t *testing.T) {
			f.lastReq = nil
			rec := f.do(tok)
			if rec.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403", rec.Code)
			}
			if f.lastReq != nil {
				t.Fatal("request must not reach upstream")
			}
		})
	}
}

func TestHealthzIsUnauthenticated(t *testing.T) {
	f := newFixture(t)
	rec := httptest.NewRecorder()
	f.handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}

func TestAuthDisabledRefusedOnRender(t *testing.T) {
	t.Setenv("AUTH_DISABLED_LOCAL_ONLY", "true")
	t.Setenv("RENDER", "true")
	if _, err := loadConfig(); err == nil {
		t.Fatal("expected error when auth is disabled on Render")
	}
}
