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
Host=admin.snapcoach.cn
Path=/user-api
Strip=true
Backend Path=/api/v1
```

configure the SDK as:

```go
uc := usercore.New(
    "http://agenda-gateway:8080/user-api",
    "data-platform",
    cfg.UserCore.JWTSecret,
    usercore.WithHostHeader("admin.snapcoach.cn"),
    usercore.WithPermissionsPath("/me/permissions"),
)
```

Old services that already call `usercore.New(...)` can use environment
variables instead:

```bash
export USER_CORE_BASE_URL='http://agenda-gateway:8080/user-api'
export USER_CORE_HOST_HEADER='admin.snapcoach.cn'
export USER_CORE_PERMISSIONS_PATH='/me/permissions'
```

## What it does

1. Parses `Authorization: Bearer <jwt>`.
2. Verifies HS256 locally with the shared `JWTSecret` (no remote call).
3. `GET {BaseURL}{PermissionsPath}?app={AppID}` (forwarding the bearer) to load permissions.
4. Caches permissions in-memory for 30s per uid (configurable via `SetCacheTTL`).
5. Aborts 403 if the user lacks `access` in this app; otherwise puts uid/email/perms into the gin context.

The cache means a freshly revoked permission keeps working for up to 30s downstream.

Defaults remain backward compatible:

```text
PermissionsPath=/api/v1/me/permissions
HostHeader=
```
