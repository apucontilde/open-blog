package api

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"golang.org/x/time/rate"

	"openblog/internal/auth"
	"openblog/internal/authz"
	"openblog/internal/import"
	"openblog/internal/media"
	"openblog/internal/oauth"
	"openblog/internal/posts"
	"openblog/internal/publicapi"
	"openblog/internal/store"
)

type server struct {
	db            *store.DB
	posts         *posts.Service
	media         *media.Media
	imports       *docimport.Service
	session       *auth.Auth
	oauth         *oauth.OAuth
	pub           *publicapi.API
	sessionName   string
	sessionSecure bool
	origins       []string
	limiter       *rateLimit
}

// Deps is the module graph the router serves.
type Deps struct {
	DB            *store.DB
	Posts         *posts.Service
	Media         *media.Media
	Imports       *docimport.Service
	Session       *auth.Auth
	OAuth         *oauth.OAuth
	Pub           *publicapi.API
	SessionName   string
	SessionSecure bool
	Origins       []string
}

func New(d Deps) *server {
	return &server{
		db:            d.DB,
		posts:         d.Posts,
		media:         d.Media,
		imports:       d.Imports,
		session:       d.Session,
		oauth:         d.OAuth,
		pub:           d.Pub,
		sessionName:   d.SessionName,
		sessionSecure: d.SessionSecure,
		origins:       d.Origins,
	}
}

type ctxKey int

const (
	ctxActor ctxKey = iota
	ctxScope
	ctxToken
	ctxBody
)

// adminHandler runs after auth has attached ctxActor, ctxScope, and ctxToken.
type adminHandler func(http.ResponseWriter, *http.Request)

func actorFrom(r *http.Request) authz.Actor {
	a, _ := r.Context().Value(ctxActor).(authz.Actor)
	return a
}

func scopeFrom(r *http.Request) store.Scope {
	s, _ := r.Context().Value(ctxScope).(store.Scope)
	return s
}

func tokenFrom(r *http.Request) string {
	t, _ := r.Context().Value(ctxToken).(string)
	return t
}

func (s *server) Routes() http.Handler {
	if s.limiter == nil {
		s.limiter = newRateLimit(10, 40, 10*time.Minute)
	}
	mux := http.NewServeMux()

	// public: no auth, no rate limit
	mux.Handle("GET /livez", s.base(livez()))
	mux.Handle("GET /readyz", s.base(readyz(s.db)))
	mux.Handle("GET /public/{tenant}/site", s.base(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp, err := s.pub.Site(r, r.PathValue("tenant"))
		s.pubResp(w, resp, err)
	})))
	mux.Handle("GET /public/{tenant}/posts", s.base(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp, err := s.pub.List(r, r.PathValue("tenant"))
		s.pubResp(w, resp, err)
	})))
	mux.Handle("GET /public/{tenant}/posts/{slug}", s.base(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp, err := s.pub.Get(r, r.PathValue("tenant"), r.PathValue("slug"))
		s.pubResp(w, resp, err)
	})))

	// auth entry: rate-limited by IP (+ email for signup/login)
	mux.Handle("POST /auth/signup", s.authRate(s.captureBody(http.HandlerFunc(s.handleSignup))))
	mux.Handle("POST /auth/login", s.authRate(s.captureBody(http.HandlerFunc(s.handleLogin))))
	mux.Handle("POST /auth/oauth/start", s.base(s.ipRate(http.HandlerFunc(s.handleOAuthStart))))
	mux.Handle("GET /auth/oauth/callback", s.base(s.ipRate(http.HandlerFunc(s.handleOAuthCallback))))

	// admin: session required
	mux.Handle("POST /auth/logout", s.base(s.auth(s.handleLogout)))
	mux.Handle("GET /auth/me", s.base(s.auth(s.handleMe)))
	mux.Handle("PUT /auth/me/active-tenant", s.base(s.auth(s.handleSetTenant)))
	mux.Handle("GET /admin/posts", s.base(s.auth(s.handlePostsList)))
	mux.Handle("POST /admin/posts", s.base(s.ipRate(s.auth(s.handlePostsCreate))))
	mux.Handle("GET /admin/posts/{id}", s.base(s.auth(s.handlePostsGet)))
	mux.Handle("PATCH /admin/posts/{id}", s.base(s.ipRate(s.auth(s.handlePostsUpdate))))
	mux.Handle("DELETE /admin/posts/{id}", s.base(s.ipRate(s.auth(s.handlePostsDelete))))
	mux.Handle("POST /admin/posts/{id}/publish", s.base(s.ipRate(s.auth(s.handlePostsPublish))))
	mux.Handle("POST /admin/posts/{id}/unpublish", s.base(s.ipRate(s.auth(s.handlePostsUnpublish))))
	mux.Handle("POST /admin/media/presign", s.base(s.ipRate(s.auth(s.handleMediaPresign))))
	mux.Handle("POST /admin/media/confirm", s.base(s.ipRate(s.auth(s.handleMediaConfirm))))
	mux.Handle("DELETE /admin/media/{id}", s.base(s.ipRate(s.auth(s.handleMediaDelete))))
	mux.Handle("POST /admin/imports", s.base(s.ipRate(s.auth(s.handleImportsStart))))
	mux.Handle("GET /admin/imports/{id}", s.base(s.auth(s.handleImportsStatus)))
	mux.Handle("POST /admin/imports/{id}/apply", s.base(s.ipRate(s.auth(s.handleImportsApply))))
	mux.Handle("GET /admin/members", s.base(s.auth(s.handleMembersList)))
	mux.Handle("POST /admin/members", s.base(s.ipRate(s.auth(s.handleMembersInvite))))
	mux.Handle("PATCH /admin/members/{userId}", s.base(s.ipRate(s.auth(s.handleMembersSetRole))))
	mux.Handle("DELETE /admin/members/{userId}", s.base(s.ipRate(s.auth(s.handleMembersRemove))))
	mux.Handle("GET /admin/tenants", s.base(s.auth(s.handleTenantsList)))
	mux.Handle("POST /admin/tenants", s.base(s.ipRate(s.auth(s.handleTenantsCreate))))
	mux.Handle("GET /admin/tenants/{id}", s.base(s.auth(s.handleTenantsGet)))
	mux.Handle("PATCH /admin/tenants/{id}", s.base(s.ipRate(s.auth(s.handleTenantsUpdate))))
	mux.Handle("DELETE /admin/tenants/{id}", s.base(s.ipRate(s.auth(s.handleTenantsDelete))))

	return mux
}

// base wraps next in the always-on chain: recover → requestID → accessLog → cors.
func (s *server) base(next http.Handler) http.Handler {
	return s.recover(s.requestID(s.accessLog(s.cors(next))))
}

// ipRate adds the IP-keyed limiter (auth + mutation routes only).
func (s *server) ipRate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.limiter.Allow("mutation|" + clientIP(r)) {
			writeError(w, http.StatusTooManyRequests, codeRateLimited, "too many requests")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// authRate is the IP + email limiter for signup/login.
func (s *server) authRate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := clientIP(r)
		if !s.limiter.Allow("auth|" + ip) {
			writeError(w, http.StatusTooManyRequests, codeRateLimited, "too many requests")
			return
		}
		var email string
		if b, ok := r.Context().Value(ctxBody).([]byte); ok {
			var v struct {
				Email string `json:"email"`
			}
			if json.Unmarshal(b, &v) == nil {
				email = strings.ToLower(strings.TrimSpace(v.Email))
			}
		}
		if email != "" && !s.limiter.Allow("auth|"+ip+"|"+email) {
			writeError(w, http.StatusTooManyRequests, codeRateLimited, "too many requests")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// captureBody buffers the body once so authRate can read email without consuming it.
func (s *server) captureBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			writeError(w, http.StatusBadRequest, codeValidation, "cannot read request body")
			return
		}
		r.Body.Close()
		r.Body = io.NopCloser(bytes.NewReader(b))
		r = r.WithContext(context.WithValue(r.Context(), ctxBody, b))
		next.ServeHTTP(w, r)
	})
}

// auth attaches Actor, the ScopeFromActor scope, and token; Platform is never set from input.
func (s *server) auth(h adminHandler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := s.sessionToken(r)
		userID, tenantID, err := s.session.Verify(r.Context(), token)
		if err != nil {
			writeError(w, http.StatusUnauthorized, codeUnauthorized, "unauthorized")
			return
		}
		actor, err := authz.ResolveActor(r.Context(), s.db, userID, tenantID)
		if err != nil {
			// A tenant-less session gets a session-only actor; anything else is a 401.
			if errors.Is(err, store.ErrNotMember) && tenantID == uuid.Nil {
				actor = authz.Actor{UserID: userID}
			} else {
				writeError(w, http.StatusUnauthorized, codeUnauthorized, "unauthorized")
				return
			}
		}
		scope := authz.ScopeFromActor(actor)
		ctx := context.WithValue(r.Context(), ctxActor, actor)
		ctx = context.WithValue(ctx, ctxScope, scope)
		ctx = context.WithValue(ctx, ctxToken, token)
		h(w, r.WithContext(ctx))
	})
}

// sessionToken prefers Authorization: Bearer, then the SameSite=Lax cookie.
func (s *server) sessionToken(r *http.Request) string {
	if h := r.Header.Get("Authorization"); len(h) > 7 && strings.EqualFold(h[:7], "Bearer ") {
		return strings.TrimSpace(h[7:])
	}
	if c, err := r.Cookie(s.sessionName); err == nil {
		return c.Value
	}
	return ""
}

func (s *server) sessionCookie(token string) *http.Cookie {
	return &http.Cookie{
		Name:     s.sessionName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   s.sessionSecure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   30 * 24 * 60 * 60,
	}
}

func (s *server) pubResp(w http.ResponseWriter, resp *publicapi.Response, err error) {
	if err != nil {
		slog.Error("public handler failed", "err", err)
		writeError(w, http.StatusInternalServerError, codeInternal, "internal server error")
		return
	}
	for k, v := range resp.Header {
		w.Header()[k] = v
	}
	w.WriteHeader(resp.Status)
	_, _ = w.Write(resp.Body)
}

func (s *server) recover(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if v := recover(); v != nil {
				slog.Error("panic", "err", v, "path", r.URL.Path)
				writeError(w, http.StatusInternalServerError, codeInternal, "internal server error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func (s *server) requestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("X-Request-ID")
		if id == "" {
			id = newRequestID()
		}
		w.Header().Set("X-Request-ID", id)
		next.ServeHTTP(w, r)
	})
}

func newRequestID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return time.Now().Format("20060102150405.000000000")
	}
	return hex.EncodeToString(b)
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

func (s *server) accessLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		slog.Info("http",
			"method", r.Method,
			"path", r.URL.Path,
			"status", rec.status,
			"us", time.Since(start).Microseconds(),
		)
	})
}

func (s *server) cors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin == "" {
			next.ServeHTTP(w, r)
			return
		}
		if !s.allowedOrigin(origin) {
			next.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Vary", "Origin")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		if r.Method == http.MethodOptions {
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PATCH, PUT, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
			w.Header().Set("Access-Control-Max-Age", "600")
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *server) allowedOrigin(origin string) bool {
	for _, o := range s.origins {
		if o == origin {
			return true
		}
	}
	return false
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func livez() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})
}

func readyz(db *store.DB) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := db.Pool().Ping(r.Context()); err != nil {
			writeError(w, http.StatusServiceUnavailable, codeInternal, "database unavailable")
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})
}

// rateLimit is an in-memory IP/email bucket store with idle-TTL eviction; per-process only.
type rateLimit struct {
	mu      sync.Mutex
	buckets map[string]*rateBkt
	rps     float64
	burst   int
	idleTTL time.Duration
}

type rateBkt struct {
	lim  *rate.Limiter
	last time.Time
}

func newRateLimit(rps float64, burst int, idleTTL time.Duration) *rateLimit {
	r := &rateLimit{
		buckets: make(map[string]*rateBkt),
		rps:     rps,
		burst:   burst,
		idleTTL: idleTTL,
	}
	go r.janitor()
	return r
}

func (r *rateLimit) Allow(key string) bool {
	r.mu.Lock()
	b, ok := r.buckets[key]
	if !ok {
		b = &rateBkt{lim: rate.NewLimiter(rate.Limit(r.rps), r.burst)}
		r.buckets[key] = b
	}
	b.last = time.Now()
	ok = b.lim.Allow()
	r.mu.Unlock()
	return ok
}

func (r *rateLimit) janitor() {
	t := time.NewTicker(5 * time.Minute)
	defer t.Stop()
	for now := range t.C {
		r.mu.Lock()
		for k, b := range r.buckets {
			if now.Sub(b.last) > r.idleTTL {
				delete(r.buckets, k)
			}
		}
		r.mu.Unlock()
	}
}
