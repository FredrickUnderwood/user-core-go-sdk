// Package usercore is the Go client SDK for user-core.
//
// Typical use in a downstream Gin service:
//
//	uc := usercore.New("http://user-core:8082", "agenda", cfg.UserCore.JWTSecret)
//	v1 := r.Group("/api/v1")
//	v1.Use(uc.Middleware())                            // requires logged-in user with `access`
//	v1.POST("/tasks", uc.RequirePerm("task.create"), createTask)
//	// inside handler:
//	uid := usercore.UID(c)
package usercore

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

const (
	// PermAccess is the implicit permission point each app's middleware enforces.
	PermAccess = "access"

	// DefaultPermissionsPath is the direct user-core permissions endpoint.
	DefaultPermissionsPath = "/api/v1/me/permissions"

	ctxKeyUID   = "usercore_uid"
	ctxKeyEmail = "usercore_email"
	ctxKeyPerms = "usercore_perms"
)

// Client is the user-core SDK client. Safe for concurrent use.
type Client struct {
	BaseURL   string
	AppID     string
	JWTSecret []byte
	HTTP      *http.Client

	HostHeader      string
	PermissionsPath string

	cacheTTL time.Duration
	mu       sync.RWMutex
	cache    map[string]cacheEntry
}

type cacheEntry struct {
	perms     map[string]bool
	expiresAt time.Time
}

// Option customizes a Client during construction.
type Option func(*Client)

// New constructs a Client with sensible defaults: 5s HTTP timeout, 30s perm cache.
//
// By default the client talks directly to user-core at /api/v1/me/permissions.
// Gateway deployments can set USER_CORE_HOST_HEADER and
// USER_CORE_PERMISSIONS_PATH, or pass WithHostHeader / WithPermissionsPath
// explicitly. Explicit options win over environment variables.
func New(baseURL, appID, jwtSecret string, opts ...Option) *Client {
	c := &Client{
		BaseURL:         strings.TrimRight(baseURL, "/"),
		AppID:           appID,
		JWTSecret:       []byte(jwtSecret),
		HTTP:            &http.Client{Timeout: 5 * time.Second},
		PermissionsPath: DefaultPermissionsPath,
		cacheTTL:        30 * time.Second,
		cache:           make(map[string]cacheEntry),
	}
	WithEnvOptions()(c)
	for _, opt := range opts {
		if opt != nil {
			opt(c)
		}
	}
	return c
}

// SetCacheTTL overrides the default 30s permission cache TTL.
func (c *Client) SetCacheTTL(d time.Duration) { c.cacheTTL = d }

// SetHostHeader sets the HTTP Host header used when calling user-core.
// It is useful when user-core is reached through agenda-gateway routes bound
// to a public/admin host.
func (c *Client) SetHostHeader(host string) {
	c.HostHeader = strings.TrimSpace(host)
}

// SetPermissionsPath sets the path appended to BaseURL when loading perms.
// Examples:
//   - direct user-core: /api/v1/me/permissions
//   - gateway prefix /user-api with backend path /api/v1: /me/permissions
func (c *Client) SetPermissionsPath(path string) {
	path = strings.TrimSpace(path)
	if path == "" {
		return
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	c.PermissionsPath = path
}

// WithHTTPClient replaces the default HTTP client.
func WithHTTPClient(client *http.Client) Option {
	return func(c *Client) {
		if client != nil {
			c.HTTP = client
		}
	}
}

// WithCacheTTL overrides the default 30s permission cache TTL.
func WithCacheTTL(d time.Duration) Option {
	return func(c *Client) {
		c.SetCacheTTL(d)
	}
}

// WithHostHeader sets the HTTP Host header used when calling user-core.
func WithHostHeader(host string) Option {
	return func(c *Client) {
		c.SetHostHeader(host)
	}
}

// WithPermissionsPath sets the path appended to BaseURL when loading perms.
func WithPermissionsPath(path string) Option {
	return func(c *Client) {
		c.SetPermissionsPath(path)
	}
}

// WithEnvOptions reads gateway-related SDK options from environment variables.
//
// Supported variables:
//   - USER_CORE_HOST_HEADER
//   - USER_CORE_PERMISSIONS_PATH
func WithEnvOptions() Option {
	return func(c *Client) {
		if v := os.Getenv("USER_CORE_HOST_HEADER"); v != "" {
			c.SetHostHeader(v)
		}
		if v := os.Getenv("USER_CORE_PERMISSIONS_PATH"); v != "" {
			c.SetPermissionsPath(v)
		}
	}
}

type sdkClaims struct {
	UID   string `json:"uid"`
	Email string `json:"email"`
	Type  string `json:"typ"`
	jwt.RegisteredClaims
}

// Middleware returns a Gin middleware that:
//  1. Parses Authorization: Bearer <jwt>
//  2. Verifies HS256 with JWTSecret (fails 401 on invalid/expired)
//  3. Fetches the user's permissions for AppID (with caching)
//  4. Rejects 403 unless the user has PermAccess in AppID
//  5. Stores uid, email, and perms in the gin.Context for downstream handlers.
func (c *Client) Middleware() gin.HandlerFunc {
	return func(g *gin.Context) {
		auth := g.GetHeader("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			abortJSON(g, http.StatusUnauthorized, "invalid_token", "missing bearer token")
			return
		}
		raw := strings.TrimPrefix(auth, "Bearer ")
		claims, err := c.parseJWT(raw)
		if err != nil {
			abortJSON(g, http.StatusUnauthorized, "invalid_token", "invalid or expired token")
			return
		}
		perms, err := c.fetchPerms(g.Request.Context(), claims.UID, raw)
		if err != nil {
			abortJSON(g, http.StatusBadGateway, "user_core_unavailable", "could not fetch permissions")
			return
		}
		if !perms[PermAccess] {
			abortJSON(g, http.StatusForbidden, "access_denied", "user lacks access to "+c.AppID)
			return
		}
		g.Set(ctxKeyUID, claims.UID)
		g.Set(ctxKeyEmail, claims.Email)
		g.Set(ctxKeyPerms, perms)
		g.Next()
	}
}

// RequirePerm gates a route on a specific permission point in the app.
// Must run after Middleware().
func (c *Client) RequirePerm(perm string) gin.HandlerFunc {
	return func(g *gin.Context) {
		perms, _ := g.Get(ctxKeyPerms)
		m, _ := perms.(map[string]bool)
		if !m[perm] {
			abortJSON(g, http.StatusForbidden, "permission_denied", "missing permission "+perm)
			return
		}
		g.Next()
	}
}

// UID returns the authenticated user's uid (empty if no Middleware ran).
func UID(c *gin.Context) string { return c.GetString(ctxKeyUID) }

// Email returns the authenticated user's email (empty if no Middleware ran).
func Email(c *gin.Context) string { return c.GetString(ctxKeyEmail) }

// HasPerm reports whether the authenticated user has the given permission.
func HasPerm(c *gin.Context, perm string) bool {
	v, ok := c.Get(ctxKeyPerms)
	if !ok {
		return false
	}
	m, _ := v.(map[string]bool)
	return m[perm]
}

func (c *Client) parseJWT(raw string) (*sdkClaims, error) {
	t, err := jwt.ParseWithClaims(raw, &sdkClaims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return c.JWTSecret, nil
	})
	if err != nil {
		return nil, err
	}
	cl, ok := t.Claims.(*sdkClaims)
	if !ok || !t.Valid {
		return nil, errors.New("invalid claims")
	}
	if cl.Type != "" && cl.Type != "access" {
		return nil, errors.New("not an access token")
	}
	return cl, nil
}

func (c *Client) fetchPerms(ctx context.Context, uid, bearer string) (map[string]bool, error) {
	c.mu.RLock()
	if e, ok := c.cache[uid]; ok && time.Now().Before(e.expiresAt) {
		c.mu.RUnlock()
		return e.perms, nil
	}
	c.mu.RUnlock()

	u, err := c.permissionsURL()
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	if c.HostHeader != "" {
		req.Host = c.HostHeader
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, errors.New("user-core: " + resp.Status + ": " + string(body))
	}
	var env struct {
		Data struct {
			App   string   `json:"app"`
			Perms []string `json:"perms"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
		return nil, err
	}
	m := make(map[string]bool, len(env.Data.Perms))
	for _, p := range env.Data.Perms {
		m[p] = true
	}
	c.mu.Lock()
	c.cache[uid] = cacheEntry{perms: m, expiresAt: time.Now().Add(c.cacheTTL)}
	c.mu.Unlock()
	return m, nil
}

func (c *Client) permissionsURL() (string, error) {
	u, err := url.Parse(c.BaseURL)
	if err != nil {
		return "", err
	}
	u.Path = joinURLPath(u.Path, c.PermissionsPath)
	q := u.Query()
	q.Set("app", c.AppID)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func joinURLPath(basePath, childPath string) string {
	basePath = strings.TrimRight(strings.TrimSpace(basePath), "/")
	childPath = strings.TrimLeft(strings.TrimSpace(childPath), "/")
	if childPath == "" {
		if basePath == "" {
			return "/"
		}
		return basePath
	}
	if basePath == "" {
		return "/" + childPath
	}
	return basePath + "/" + childPath
}

func abortJSON(g *gin.Context, status int, code, msg string) {
	g.AbortWithStatusJSON(status, gin.H{
		"error": gin.H{"code": code, "message": msg},
	})
}
