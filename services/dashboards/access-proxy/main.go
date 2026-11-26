// access-proxy fronts OpenSearch Dashboards and only forwards requests that
// carry a valid Cloudflare Access JWT (Cf-Access-Jwt-Assertion header):
// signature against the team JWKS, issuer, audience (AUD tag) and expiry.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
)

const assertionHeader = "Cf-Access-Jwt-Assertion"

type config struct {
	listenAddr   string
	upstream     *url.URL
	issuer       string
	audience     string
	authDisabled bool
}

func loadConfig() (*config, error) {
	upstream, err := url.Parse(envOr("UPSTREAM_URL", "http://127.0.0.1:5601"))
	if err != nil {
		return nil, fmt.Errorf("UPSTREAM_URL: %w", err)
	}
	cfg := &config{
		listenAddr: ":" + envOr("PORT", "10000"),
		upstream:   upstream,
	}

	if os.Getenv("AUTH_DISABLED_LOCAL_ONLY") == "true" {
		if os.Getenv("RENDER") != "" {
			return nil, errors.New("AUTH_DISABLED_LOCAL_ONLY must never be set on Render")
		}
		cfg.authDisabled = true
		return cfg, nil
	}

	team := strings.TrimSuffix(strings.TrimSpace(os.Getenv("CF_ACCESS_TEAM_DOMAIN")), "/")
	if team == "" {
		return nil, errors.New("CF_ACCESS_TEAM_DOMAIN is required (e.g. myteam.cloudflareaccess.com)")
	}
	if !strings.HasPrefix(team, "https://") {
		team = "https://" + team
	}
	cfg.issuer = team

	cfg.audience = strings.TrimSpace(os.Getenv("CF_ACCESS_AUD"))
	if cfg.audience == "" {
		return nil, errors.New("CF_ACCESS_AUD is required (Access application AUD tag)")
	}
	return cfg, nil
}

// requestInfo is created by accessLog and filled by the auth middleware, so
// the access log can report the authenticated identity.
type requestInfo struct {
	identity string
}

type requestInfoKey struct{}

func withRequestInfo(r *http.Request) (*http.Request, *requestInfo) {
	if info, ok := r.Context().Value(requestInfoKey{}).(*requestInfo); ok {
		return r, info
	}
	info := &requestInfo{}
	return r.WithContext(context.WithValue(r.Context(), requestInfoKey{}, info)), info
}

func identityFrom(ctx context.Context) string {
	if info, ok := ctx.Value(requestInfoKey{}).(*requestInfo); ok {
		return info.identity
	}
	return ""
}

type authenticator struct {
	verifier *oidc.IDTokenVerifier
	disabled bool
	log      *slog.Logger
}

func newAuthenticator(ctx context.Context, cfg *config, log *slog.Logger) *authenticator {
	if cfg.authDisabled {
		return &authenticator{disabled: true, log: log}
	}
	keySet := oidc.NewRemoteKeySet(ctx, cfg.issuer+"/cdn-cgi/access/certs")
	return &authenticator{
		verifier: oidc.NewVerifier(cfg.issuer, keySet, &oidc.Config{ClientID: cfg.audience}),
		log:      log,
	}
}

func (a *authenticator) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r, info := withRequestInfo(r)
		if a.disabled {
			info.identity = "local-dev"
			next.ServeHTTP(w, r)
			return
		}

		token := r.Header.Get(assertionHeader)
		if token == "" {
			a.deny(w, r, "missing_assertion", nil)
			return
		}
		idToken, err := a.verifier.Verify(r.Context(), token)
		if err != nil {
			a.deny(w, r, "invalid_assertion", err)
			return
		}

		var claims struct {
			Email      string `json:"email"`
			CommonName string `json:"common_name"`
		}
		if err := idToken.Claims(&claims); err != nil {
			a.deny(w, r, "invalid_claims", err)
			return
		}
		identity := claims.Email
		if identity == "" {
			identity = claims.CommonName // service tokens
		}
		if identity == "" {
			identity = idToken.Subject
		}
		info.identity = identity

		next.ServeHTTP(w, r)
	})
}

func (a *authenticator) deny(w http.ResponseWriter, r *http.Request, reason string, err error) {
	attrs := []any{
		"reason", reason,
		"client_ip", clientIP(r),
		"method", r.Method,
		"path", r.URL.Path,
		"user_agent", r.UserAgent(),
	}
	if err != nil {
		attrs = append(attrs, "error", err.Error())
	}
	a.log.Warn("access denied", attrs...)
	http.Error(w, "Forbidden", http.StatusForbidden)
}

func newProxy(upstream *url.URL, log *slog.Logger) *httputil.ReverseProxy {
	return &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(upstream)
			pr.SetXForwarded()
			pr.Out.Header.Del(assertionHeader)
			pr.Out.Header.Del("X-Forwarded-User")
			if id := identityFrom(pr.In.Context()); id != "" {
				pr.Out.Header.Set("X-Forwarded-User", id)
			}
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			log.Error("upstream error", "path", r.URL.Path, "error", err.Error())
			http.Error(w, "Bad Gateway", http.StatusBadGateway)
		},
	}
}

func healthHandler(upstream *url.URL) http.Handler {
	client := &http.Client{Timeout: 3 * time.Second}
	statusURL := upstream.JoinPath("/api/status").String()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp, err := client.Get(statusURL)
		if err != nil {
			http.Error(w, "upstream unavailable", http.StatusServiceUnavailable)
			return
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			http.Error(w, "upstream unhealthy", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("OK\n"))
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Unwrap() http.ResponseWriter { return s.ResponseWriter }

func accessLog(log *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		r, info := withRequestInfo(r)
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		if r.URL.Path == "/healthz" {
			return
		}
		log.Info("request",
			"user", info.identity,
			"client_ip", clientIP(r),
			"method", r.Method,
			"path", r.URL.Path,
			"status", rec.status,
			"duration_ms", time.Since(start).Milliseconds(),
		)
	})
}

// clientIP is only used for logging; Cloudflare sets Cf-Connecting-Ip.
func clientIP(r *http.Request) string {
	if ip := r.Header.Get("Cf-Connecting-Ip"); ip != "" {
		return ip
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func newHandler(auth *authenticator, upstream *url.URL, log *slog.Logger) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /healthz", healthHandler(upstream))
	mux.Handle("/", auth.middleware(newProxy(upstream, log)))
	return accessLog(log, mux)
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil)).With("service", "access-proxy")

	cfg, err := loadConfig()
	if err != nil {
		log.Error("invalid configuration", "error", err.Error())
		os.Exit(1)
	}
	if cfg.authDisabled {
		log.Warn("Cloudflare Access validation DISABLED (local development only)")
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	srv := &http.Server{
		Addr:              cfg.listenAddr,
		Handler:           newHandler(newAuthenticator(ctx, cfg, log), cfg.upstream, log),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()

	log.Info("listening", "addr", cfg.listenAddr, "upstream", cfg.upstream.String(), "issuer", cfg.issuer)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Error("server error", "error", err.Error())
		os.Exit(1)
	}
}
