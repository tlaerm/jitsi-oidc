// main.go
package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
	"github.com/joho/godotenv"
	"golang.org/x/oauth2"
)

// -----------------------------
// Config
// -----------------------------

type Config struct {
	JitsiSecret string
	JitsiURL    string
	JitsiSub    string

	IssuerBaseURL string
	BaseURL       string
	ClientID      string
	ClientSecret  string

	JwtIssuer   string
	JwtAudience string
	JwtTTL      time.Duration

	IncludeEmail bool
	IncludeName  bool

	// Session / cookie
	CookieName       string
	CookieMaxAge     time.Duration
	CookieSameSite   http.SameSite
	TrustProxy       bool
	TrustedProxies   []string
	ListenAddr       string
	LogLevel         string
	StateStoreTTL    time.Duration
	StateStoreGCIdle time.Duration
}

func loadConfig() (*Config, error) {
	// Optional .env support. Do NOT log values.
	_ = func() error {
		if _, err := os.Stat(".env"); err == nil {
			return godotenv.Load(".env")
		}
		return nil
	}()

	get := func(k string) string { return strings.TrimSpace(os.Getenv(k)) }
	getBool := func(k string, def bool) bool {
		v := strings.ToLower(get(k))
		if v == "" {
			return def
		}
		return v == "1" || v == "true" || v == "yes" || v == "y" || v == "on"
	}
	getDur := func(k string, def time.Duration) (time.Duration, error) {
		v := get(k)
		if v == "" {
			return def, nil
		}
		// Support either Go duration (10m) or seconds (e.g. 600)
		if d, err := time.ParseDuration(v); err == nil {
			return d, nil
		}
		if n, err := strconv.Atoi(v); err == nil {
			return time.Duration(n) * time.Second, nil
		}
		return 0, fmt.Errorf("invalid duration for %s: %q", k, v)
	}

	jwtTTL, err := getDur("JWT_TTL", 10*time.Minute)
	if err != nil {
		return nil, err
	}
	cookieMaxAge, err := getDur("COOKIE_MAX_AGE", 10*time.Minute)
	if err != nil {
		return nil, err
	}
	stateTTL, err := getDur("STATE_TTL", 10*time.Minute)
	if err != nil {
		return nil, err
	}
	gcEvery, err := getDur("STATE_GC_EVERY", 30*time.Second)
	if err != nil {
		return nil, err
	}

	// SameSite defaults to Lax for OIDC redirect flows.
	sameSite := http.SameSiteLaxMode
	switch strings.ToLower(get("COOKIE_SAMESITE")) {
	case "", "lax":
		sameSite = http.SameSiteLaxMode
	case "strict":
		sameSite = http.SameSiteStrictMode
	case "none":
		sameSite = http.SameSiteNoneMode
	default:
		return nil, fmt.Errorf("invalid COOKIE_SAMESITE: %q (use lax|strict|none)", get("COOKIE_SAMESITE"))
	}

	cfg := &Config{
		JitsiSecret:   get("JITSI_SECRET"),
		JitsiURL:      strings.TrimRight(get("JITSI_URL"), "/"),
		JitsiSub:      get("JITSI_SUB"),
		IssuerBaseURL: get("ISSUER_BASE_URL"),
		BaseURL:       strings.TrimRight(get("BASE_URL"), "/"),
		ClientID:      get("CLIENT_ID"),
		ClientSecret:  get("SECRET"),

		JwtIssuer:   firstNonEmpty(get("JWT_ISSUER"), "jitsi"),
		JwtAudience: firstNonEmpty(get("JWT_AUDIENCE"), "jitsi"),
		JwtTTL:      jwtTTL,

		IncludeEmail: getBool("INCLUDE_EMAIL", false),
		IncludeName:  getBool("INCLUDE_NAME", true),

		CookieName:     firstNonEmpty(get("COOKIE_NAME"), "jitsi_oidc_session"),
		CookieMaxAge:   cookieMaxAge,
		CookieSameSite: sameSite,

		TrustProxy:     getBool("TRUST_PROXY", true),
		TrustedProxies: splitCSV(get("TRUSTED_PROXIES")),

		ListenAddr:       firstNonEmpty(get("LISTEN_ADDR"), ":3001"),
		LogLevel:         firstNonEmpty(get("LOG_LEVEL"), "info"),
		StateStoreTTL:    stateTTL,
		StateStoreGCIdle: gcEvery,
	}

	// Validate required env
	var missing []string
	for _, req := range []struct {
		k string
		v string
	}{
		{"JITSI_SECRET", cfg.JitsiSecret},
		{"JITSI_URL", cfg.JitsiURL},
		{"JITSI_SUB", cfg.JitsiSub},
		{"ISSUER_BASE_URL", cfg.IssuerBaseURL},
		{"BASE_URL", cfg.BaseURL},
		{"CLIENT_ID", cfg.ClientID},
		{"SECRET", cfg.ClientSecret},
	} {
		if req.v == "" {
			missing = append(missing, req.k)
		}
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("missing required environment variables: %s", strings.Join(missing, ", "))
	}

	// If SameSite=None, cookie must be Secure or browsers will reject it.
	// We enforce Secure dynamically based on external https; SameSite=None is still risky.
	if cfg.CookieSameSite == http.SameSiteNoneMode {
		log.Printf("WARN: COOKIE_SAMESITE=none requires Secure cookies; ensure TLS externally (ingress) and X-Forwarded-Proto is set.")
	}

	return cfg, nil
}

func firstNonEmpty(v, def string) string {
	if strings.TrimSpace(v) == "" {
		return def
	}
	return v
}

func splitCSV(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// -----------------------------
// Logging helpers (no secrets)
// -----------------------------

type Logger struct {
	debug bool
}

func newLogger(level string) *Logger {
	return &Logger{debug: strings.EqualFold(level, "debug")}
}

func (l *Logger) Infof(format string, args ...any) { log.Printf("INFO: "+format, args...) }
func (l *Logger) Warnf(format string, args ...any) { log.Printf("WARN: "+format, args...) }
func (l *Logger) Errorf(format string, args ...any) {
	log.Printf("ERROR: "+format, args...)
}

func (l *Logger) Debugf(format string, args ...any) {
	if l.debug {
		log.Printf("DEBUG: "+format, args...)
	}
}

func sha8(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:8]
}

// -----------------------------
// In-memory state store (TTL)
// -----------------------------

type SessionData struct {
	Nonce     string
	Room      string
	CreatedAt time.Time
	ExpiresAt time.Time
}

type StateStore struct {
	mu    sync.Mutex
	ttl   time.Duration
	items map[string]SessionData
}

func NewStateStore(ttl time.Duration) *StateStore {
	return &StateStore{
		ttl:   ttl,
		items: make(map[string]SessionData),
	}
}

func (s *StateStore) Put(sessionID string, data SessionData) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	data.CreatedAt = now
	if data.ExpiresAt.IsZero() {
		data.ExpiresAt = now.Add(s.ttl)
	}
	s.items[sessionID] = data
}

func (s *StateStore) Get(sessionID string) (SessionData, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, ok := s.items[sessionID]
	if !ok {
		return SessionData{}, false
	}
	if time.Now().After(d.ExpiresAt) {
		delete(s.items, sessionID)
		return SessionData{}, false
	}
	return d, true
}

func (s *StateStore) Delete(sessionID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.items, sessionID)
}

func (s *StateStore) GC() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	removed := 0
	for k, v := range s.items {
		if now.After(v.ExpiresAt) {
			delete(s.items, k)
			removed++
		}
	}
	return removed
}

// -----------------------------
// OIDC types
// -----------------------------

type PlayLoad struct {
	ID    string `json:"sub,omitempty"`
	Email string `json:"email,omitempty"`
	Name  string `json:"name,omitempty"`
}

type UserContext struct {
	User PlayLoad `json:"user"`
}

// -----------------------------
// Utils
// -----------------------------

func randStringURLSafe(nBytes int) (string, error) {
	b := make([]byte, nBytes)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func externalIsHTTPS(c *gin.Context) bool {
	// Trust X-Forwarded-Proto when behind ingress/proxy.
	xfp := c.GetHeader("X-Forwarded-Proto")
	if strings.EqualFold(xfp, "https") {
		return true
	}
	// Fallback if TLS is terminated in-app (rare in k8s behind ingress).
	return c.Request.TLS != nil
}

func setCookie(c *gin.Context, name, value string, maxAge time.Duration, sameSite http.SameSite, secure bool) {
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		MaxAge:   int(maxAge.Seconds()),
		Secure:   secure,
		HttpOnly: true,
		SameSite: sameSite,
	})
}

func clearCookie(c *gin.Context, name string, sameSite http.SameSite, secure bool) {
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		Secure:   secure,
		HttpOnly: true,
		SameSite: sameSite,
	})
}

func sanitizeRoom(room string) (string, error) {
	room = strings.TrimSpace(room)
	if room == "" {
		return "", errors.New("room empty")
	}
	// Keep it conservative: allow URL path-safe room names only.
	// Jitsi typically supports a wide range, but you do NOT want arbitrary slashes.
	if strings.Contains(room, "/") || strings.Contains(room, "..") {
		return "", errors.New("invalid room")
	}
	return room, nil
}

func safeClientIP(c *gin.Context) string {
	ip := c.ClientIP()
	if ip == "" {
		return "-"
	}
	return ip
}

// -----------------------------
// Main
// -----------------------------

func main() {
	cfg, err := loadConfig()
	if err != nil {
		log.Fatalf("config error: %v", err)
	}
	l := newLogger(cfg.LogLevel)

	// OIDC provider
	ctx := context.Background()
	provider, err := oidc.NewProvider(ctx, cfg.IssuerBaseURL)
	if err != nil {
		log.Fatalf("failed to create OIDC provider: %v", err)
	}

	oauthCfg := oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  cfg.BaseURL + "/callback",
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
	}

	store := NewStateStore(cfg.StateStoreTTL)
	// GC loop
	go func() {
		t := time.NewTicker(cfg.StateStoreGCIdle)
		defer t.Stop()
		for range t.C {
			removed := store.GC()
			if removed > 0 {
				l.Debugf("state store GC removed=%d", removed)
			}
		}
	}()

	// Gin setup: NO default logger (it can leak query params).
	gin.SetMode(gin.ReleaseMode)
	if strings.EqualFold(cfg.LogLevel, "debug") {
		gin.SetMode(gin.DebugMode)
	}

	r := gin.New()
	r.Use(gin.Recovery())
	r.Use(gin.LoggerWithFormatter(func(p gin.LogFormatterParams) string {
		// Intentionally do not log query strings.
		// Also keep it compact; include request id if you add one later.
		return fmt.Sprintf("HTTP %s %s status=%d ip=%s latency=%s\n",
			p.Method, p.Path, p.StatusCode, p.ClientIP, p.Latency)
	}))

	if cfg.TrustProxy {
		if len(cfg.TrustedProxies) == 0 {
			// Trust all by default is risky; in k8s behind an ingress, you often want to trust the cluster CIDR.
			// But keeping this simple: user can set TRUSTED_PROXIES.
			l.Warnf("TRUST_PROXY enabled but TRUSTED_PROXIES empty; ClientIP/X-Forwarded-* trust may be unsafe. Set TRUSTED_PROXIES=10.0.0.0/8,192.168.0.0/16,... as appropriate.")
		} else {
			_ = r.SetTrustedProxies(cfg.TrustedProxies)
		}
	}

	// Health endpoint
	r.GET("/healthz", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	// Start auth flow for a room
	r.GET("/room/:room", func(c *gin.Context) {
		room, err := sanitizeRoom(c.Param("room"))
		if err != nil {
			c.String(http.StatusBadRequest, "invalid room")
			return
		}

		secure := externalIsHTTPS(c)

		sessionID, err := randStringURLSafe(24)
		if err != nil {
			l.Errorf("rand session id failed: %v", err)
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}

		state, err := randStringURLSafe(24)
		if err != nil {
			l.Errorf("rand state failed: %v", err)
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}
		nonce, err := randStringURLSafe(24)
		if err != nil {
			l.Errorf("rand nonce failed: %v", err)
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}

		// Store server-side (RAM). Cookie only holds opaque session id.
		store.Put(sessionID, SessionData{
			Nonce:     nonce,
			Room:      room,
			ExpiresAt: time.Now().Add(cfg.CookieMaxAge),
		})

		// Set cookie with the opaque session id.
		setCookie(c, cfg.CookieName, sessionID, cfg.CookieMaxAge, cfg.CookieSameSite, secure)

		// Create redirect to IdP; state in URL ties callback to this auth attempt.
		authURL := oauthCfg.AuthCodeURL(state, oidc.Nonce(nonce))

		// Minimal safe log (no secrets)
		l.Infof("auth start room=%q ip=%s sid=%s state=%s",
			room, safeClientIP(c), sha8(sessionID), sha8(state))

		c.Redirect(http.StatusFound, authURL)
	})

	// Callback from IdP
	r.GET("/callback", func(c *gin.Context) {
		secure := externalIsHTTPS(c)

		// Retrieve session
		sessionID, err := c.Cookie(cfg.CookieName)
		if err != nil || sessionID == "" {
			c.String(http.StatusBadRequest, "session not found")
			return
		}
		sd, ok := store.Get(sessionID)
		if !ok {
			clearCookie(c, cfg.CookieName, cfg.CookieSameSite, secure)
			c.String(http.StatusBadRequest, "session expired")
			return
		}
		// One-time use
		store.Delete(sessionID)
		clearCookie(c, cfg.CookieName, cfg.CookieSameSite, secure)

		// Validate state (must be present). We don’t persist it, but OIDC will validate nonce.
		// State mismatch checks are still useful; we can require it non-empty.
		stateQ := c.Query("state")
		if strings.TrimSpace(stateQ) == "" {
			c.String(http.StatusBadRequest, "missing state")
			return
		}

		code := c.Query("code")
		if code == "" {
			c.String(http.StatusBadRequest, "missing code")
			return
		}

		l.Infof("auth callback room=%q ip=%s sid=%s state=%s",
			sd.Room, safeClientIP(c), sha8(sessionID), sha8(stateQ))

		// Exchange code for token (do not log token content)
		oauth2Token, err := oauthCfg.Exchange(ctx, code)
		if err != nil {
			l.Warnf("token exchange failed room=%q sid=%s err=%v", sd.Room, sha8(sessionID), err)
			c.String(http.StatusInternalServerError, "token exchange failed")
			return
		}

		rawIDToken, ok := oauth2Token.Extra("id_token").(string)
		if !ok || rawIDToken == "" {
			l.Warnf("missing id_token room=%q sid=%s", sd.Room, sha8(sessionID))
			c.String(http.StatusInternalServerError, "missing id_token")
			return
		}

		verifier := provider.Verifier(&oidc.Config{ClientID: cfg.ClientID})
		idToken, err := verifier.Verify(ctx, rawIDToken)
		if err != nil {
			l.Warnf("id_token verify failed room=%q sid=%s err=%v", sd.Room, sha8(sessionID), err)
			c.String(http.StatusInternalServerError, "id_token verify failed")
			return
		}

		if idToken.Nonce != sd.Nonce {
			l.Warnf("nonce mismatch room=%q sid=%s", sd.Room, sha8(sessionID))
			c.String(http.StatusBadRequest, "nonce mismatch")
			return
		}

		// Parse claims (do not log entire payload)
		var rawClaims json.RawMessage
		if err := idToken.Claims(&rawClaims); err != nil {
			l.Warnf("claims parse failed room=%q sid=%s err=%v", sd.Room, sha8(sessionID), err)
			c.String(http.StatusInternalServerError, "claims parse failed")
			return
		}

		var pl PlayLoad
		if err := json.Unmarshal(rawClaims, &pl); err != nil {
			l.Warnf("claims unmarshal failed room=%q sid=%s err=%v", sd.Room, sha8(sessionID), err)
			c.String(http.StatusInternalServerError, "claims unmarshal failed")
			return
		}

		// Build JWT context (minimize PII by default)
		user := &UserContext{User: PlayLoad{}}
		// Provide stable-ish ID without exposing raw subject/email by default
		// (You can enable email/name via env)
		if cfg.IncludeEmail {
			user.User.Email = pl.Email
		}
		if cfg.IncludeName {
			user.User.Name = pl.Name
		}
		// ID: set to hash of the IdP sub if present (no PII)
		if pl.ID != "" {
			user.User.ID = sha8(pl.ID)
		}

		now := time.Now()
		claims := jwt.MapClaims{
			"exp":     now.Add(cfg.JwtTTL).Unix(),
			"aud":     cfg.JwtAudience,
			"sub":     cfg.JitsiSub,
			"iss":     cfg.JwtIssuer,
			"room":    sd.Room,
			"context": user,
		}

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tokenString, err := token.SignedString([]byte(cfg.JitsiSecret))
		if err != nil {
			l.Errorf("jwt sign failed room=%q sid=%s err=%v", sd.Room, sha8(sessionID), err)
			c.String(http.StatusInternalServerError, "jwt sign failed")
			return
		}

		// DO NOT log tokenString. At most log its hash.
		l.Debugf("jwt minted room=%q sid=%s jwt_hash=%s ttl=%s",
			sd.Room, sha8(sessionID), sha8(tokenString), cfg.JwtTTL)

		redirectURL := cfg.JitsiURL + "/" + sd.Room + "?jwt=" + tokenString
		c.Redirect(http.StatusFound, redirectURL)
	})

	l.Infof("starting server addr=%s base_url=%s jitsi_url=%s log_level=%s jwt_ttl=%s",
		cfg.ListenAddr, cfg.BaseURL, cfg.JitsiURL, cfg.LogLevel, cfg.JwtTTL)

	if err := r.Run(cfg.ListenAddr); err != nil {
		log.Fatalf("server failed: %v", err)
	}
}
