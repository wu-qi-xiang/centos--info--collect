# 凭据读取接口

## `POST /password/password_reveal/<id>/`

读取当前登录用户自己拥有的凭据。密码在数据库中继续使用 `PyLinux.crypto` 加密保存，服务端解密后只在本次显式 POST 响应中返回。

认证与边界：

- 使用项目现有 session 登录认证和 CSRF 保护。
- `id` 必须属于当前 session 用户，否则返回 `404`。
- 只允许 `POST`，`GET` 返回 `405`。
- 按“用户 + 凭据 ID”限制读取频率，默认每 60 秒最多 5 次；可通过 `PASSWORD_REVEAL_MAX_ATTEMPTS` 和 `PASSWORD_REVEAL_WINDOW_SECONDS` 配置。
- 每次成功读取和被限流的读取都会写入不含密码的审计记录。
- 响应设置 `Cache-Control: no-store`、`Pragma: no-cache` 和 `X-Content-Type-Options: nosniff`。

成功响应：

```json
{"ok": true, "password": "[明文仅在受控响应中返回]"}
```

限流响应：

```json
{"ok": false, "code": "rate_limited", "message": "凭据读取过于频繁，请稍后重试"}
```

该接口不读取 Vault，也不接受 Vault Token、路径或外部 Secret 值。后续如接入 Vault，应使用服务端注入的最小只读 Policy，并保持同样的所有权、审计、限流和不缓存约束。
