package usercore

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestFetchPermsUsesDefaultGatewayPath(t *testing.T) {
	t.Setenv("USER_CORE_HOST_HEADER", "")
	t.Setenv("USER_CORE_PERMISSIONS_PATH", "")

	var seenPath string
	var seenApp string
	var seenAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenPath = r.URL.Path
		seenApp = r.URL.Query().Get("app")
		seenAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"app":"data-platform","perms":["access","asset.read"]}}`))
	}))
	defer srv.Close()

	c := New(srv.URL+"/user-api", "data-platform", "secret")
	perms, err := c.fetchPerms(context.Background(), "u000001", "token-1")
	if err != nil {
		t.Fatalf("fetchPerms returned error: %v", err)
	}
	if seenPath != "/user-api/me/permissions" {
		t.Fatalf("path = %q, want /user-api/me/permissions", seenPath)
	}
	if seenApp != "data-platform" {
		t.Fatalf("app = %q, want data-platform", seenApp)
	}
	if seenAuth != "Bearer token-1" {
		t.Fatalf("authorization = %q, want bearer", seenAuth)
	}
	if !perms["access"] || !perms["asset.read"] {
		t.Fatalf("permissions not decoded correctly: %#v", perms)
	}
}

func TestFetchPermsSupportsDirectUserCorePath(t *testing.T) {
	t.Setenv("USER_CORE_HOST_HEADER", "")
	t.Setenv("USER_CORE_PERMISSIONS_PATH", "")

	var seenPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"app":"data-platform","perms":["access"]}}`))
	}))
	defer srv.Close()

	c := New(srv.URL, "data-platform", "secret", WithDirectUserCore())
	if _, err := c.fetchPerms(context.Background(), "u000001", "token-1"); err != nil {
		t.Fatalf("fetchPerms returned error: %v", err)
	}
	if seenPath != DirectPermissionsPath {
		t.Fatalf("path = %q, want %q", seenPath, DirectPermissionsPath)
	}
}

func TestFetchPermsSupportsHostHeaderOverride(t *testing.T) {
	t.Setenv("USER_CORE_HOST_HEADER", "")
	t.Setenv("USER_CORE_PERMISSIONS_PATH", "")

	var seenHost string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenHost = r.Host
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"app":"data-platform","perms":["access"]}}`))
	}))
	defer srv.Close()

	c := New(srv.URL+"/user-api", "data-platform", "secret", WithHostHeader("admin.snapcoach.cn"))
	if _, err := c.fetchPerms(context.Background(), "u000001", "token-1"); err != nil {
		t.Fatalf("fetchPerms returned error: %v", err)
	}
	if seenHost != "admin.snapcoach.cn" {
		t.Fatalf("host = %q, want admin.snapcoach.cn", seenHost)
	}
}

func TestNewUsesGatewayBaseURLByDefault(t *testing.T) {
	t.Setenv("USER_CORE_HOST_HEADER", "")
	t.Setenv("USER_CORE_PERMISSIONS_PATH", "")

	c := New("http://agenda-gateway:8080/user-api", "data-platform", "secret")
	if c.HostHeader != "" {
		t.Fatalf("host header = %q, want empty", c.HostHeader)
	}
	if c.PermissionsPath != "/me/permissions" {
		t.Fatalf("permissions path = %q, want /me/permissions", c.PermissionsPath)
	}

	u, err := c.permissionsURL()
	if err != nil {
		t.Fatalf("permissionsURL returned error: %v", err)
	}
	want := "http://agenda-gateway:8080/user-api/me/permissions?app=data-platform"
	if u != want {
		t.Fatalf("permissions url = %q, want %q", u, want)
	}
}

func TestNewAppliesEnvironmentOptions(t *testing.T) {
	t.Setenv("USER_CORE_HOST_HEADER", "admin.snapcoach.cn")
	t.Setenv("USER_CORE_PERMISSIONS_PATH", "custom/permissions")

	c := New("http://agenda-gateway:8080/user-api", "data-platform", "secret")
	if c.HostHeader != "admin.snapcoach.cn" {
		t.Fatalf("host header = %q, want admin.snapcoach.cn", c.HostHeader)
	}
	if c.PermissionsPath != "/custom/permissions" {
		t.Fatalf("permissions path = %q, want /custom/permissions", c.PermissionsPath)
	}
}

func TestExplicitOptionsOverrideEnvironmentOptions(t *testing.T) {
	t.Setenv("USER_CORE_HOST_HEADER", "wrong.example.com")
	t.Setenv("USER_CORE_PERMISSIONS_PATH", "/wrong")

	c := New(
		"http://agenda-gateway:8080/user-api",
		"data-platform",
		"secret",
		WithHostHeader("admin.snapcoach.cn"),
		WithPermissionsPath("/me/permissions"),
	)
	if c.HostHeader != "admin.snapcoach.cn" {
		t.Fatalf("host header = %q, want admin.snapcoach.cn", c.HostHeader)
	}
	if c.PermissionsPath != "/me/permissions" {
		t.Fatalf("permissions path = %q, want /me/permissions", c.PermissionsPath)
	}
}
