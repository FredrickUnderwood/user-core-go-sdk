# user-core-go-sdk

Gin middleware + thin HTTP client for [user-core](../user-core).

## Install

In a downstream service (开发期用 `replace` 指本地路径):

```go
// go.mod
require github.com/FredrickUnderwood/user-core-go-sdk v0.0.0

replace github.com/FredrickUnderwood/user-core-go-sdk => ../user-core-go-sdk
```

## Usage

```go
import usercore "github.com/FredrickUnderwood/user-core-go-sdk"

uc := usercore.New(cfg.UserCore.BaseURL, cfg.UserCore.AppID, cfg.UserCore.JWTSecret)

v1 := r.Group("/api/v1")
v1.Use(uc.Middleware()) // requires user logged in + has `access` perm in this app

v1.POST("/tasks", uc.RequirePerm("task.create"), createTaskHandler)

func createTaskHandler(c *gin.Context) {
    uid := usercore.UID(c)         // 7-char user id
    email := usercore.Email(c)
    if usercore.HasPerm(c, "task.admin") { ... }
}
```

### Through agenda-gateway

For gateway routes like:

```text
Host=api.snapcoach.cn
Path=/user-api
Strip=true
Backend Path=/api/v1
```

configure only the user-core gateway base URL:

```go
uc := usercore.New(
    "https://api.snapcoach.cn/user-api",
    "data-platform",
    cfg.UserCore.JWTSecret,
)
```

Or via environment in downstream services:

```bash
export USER_CORE_BASE_URL='https://api.snapcoach.cn/user-api'
```

The SDK appends `/me/permissions`, so the request becomes
`https://api.snapcoach.cn/user-api/me/permissions?app={AppID}`. The gateway
route then rewrites it to user-core's internal `/api/v1/me/permissions`.

`WithHostHeader` and `USER_CORE_HOST_HEADER` remain available for special
internal routes, but a real gateway domain is preferred because the HTTP Host
comes from the base URL naturally.

For direct user-core access, opt in explicitly:

```go
uc := usercore.New(
    "http://user-core:8082",
    "data-platform",
    cfg.UserCore.JWTSecret,
    usercore.WithDirectUserCore(),
)
```

## What it does

1. Parses `Authorization: Bearer <jwt>`.
2. Verifies HS256 locally with the shared `JWTSecret` (no remote call).
3. `GET {BaseURL}/me/permissions?app={AppID}` (forwarding the bearer) to load permissions.
4. Caches permissions in-memory for 30s per uid (configurable via `SetCacheTTL`).
5. Aborts 403 if the user lacks `access` in this app; otherwise puts uid/email/perms into the gin context.

The cache means a freshly revoked permission keeps working for up to 30s downstream.

Gateway-first defaults:

```text
PermissionsPath=/me/permissions
HostHeader=
```
