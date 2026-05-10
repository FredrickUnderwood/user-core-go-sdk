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
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

const (
	// PermAccess is the implicit permission point each app's middleware enforces.
	PermAccess = "access"

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

	cacheTTL time.Duration
	mu       sync.RWMutex
	cache    map[string]cacheEntry
}

type cacheEntry struct {
	perms     map[string]bool
	expiresAt time.Time
}

// New constructs a Client with sensible defaults: 5s HTTP timeout, 30s perm cache.
func New(baseURL, appID, jwtSecret string) *Client {
	return &Client{
		BaseURL:   strings.TrimRight(baseURL, "/"),
		AppID:     appID,
		JWTSecret: []byte(jwtSecret),
		HTTP:      &http.Client{Timeout: 5 * time.Second},
		cacheTTL:  30 * time.Second,
		cache:     make(map[string]cacheEntry),
	}
}

// SetCacheTTL overrides the default 30s permission cache TTL.
func (c *Client) SetCacheTTL(d time.Duration) { c.cacheTTL = d }

type sdkClaims struct {
	UID   string `json:"uid"`
	Email string `json:"email"`
	Type  string `json:"typ"`
	jwt.RegisteredClaims
}

// Middleware returns a Gin middleware that:
//   1. Parses Authorization: Bearer <jwt>
//   2. Verifies HS256 with JWTSecret (fails 401 on invalid/expired)
//   3. Fetches the user's permissions for AppID (with caching)
//   4. Rejects 403 unless the user has PermAccess in AppID
//   5. Stores uid, email, and perms in the gin.Context for downstream handlers.
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

	u := c.BaseURL + "/api/v1/me/permissions?app=" + url.QueryEscape(c.AppID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
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

func abortJSON(g *gin.Context, status int, code, msg string) {
	g.AbortWithStatusJSON(status, gin.H{
		"error": gin.H{"code": code, "message": msg},
	})
}
