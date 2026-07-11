# DevOps API Dictionary

Use this when adding or changing `/devops/api/*` endpoints.

## Global Contract

- Auth: custom session auth through `request.session["is_login"]`.
- Unauthenticated response: `401` with `{ok: false, code: "unauthorized", message}`.
- Error shape: `{ok: false, code, message}`.
- Success shape: `{ok: true, ...}`.
- Host-specific results must honor `visible_hosts_for_request`, `can_access_host`, or `can_access_hosts`.
- Sensitive fields must be omitted: host passwords, private keys, passphrases, webhook URLs, notification secrets, encrypted secret values.

## Error Codes

| Code | HTTP | Use |
|---|---:|---|
| `unauthorized` | 401 | Missing custom session login |
| `forbidden` | 403 | Role/module/host-scope denial |
| `not_found` | 404 | Missing object or inaccessible object intentionally hidden |
| `invalid_json` | 400 | Body cannot be parsed as JSON |
| `validation_error` | 400 | Required field missing or invalid |
| `method_not_allowed` | 405 | Prefer Django `require_http_methods` where possible |
| `bad_request` | 400 | Generic request error |

## Current Endpoints

| Endpoint | Method | Purpose | Permission | Host Scope | Sensitive Omissions |
|---|---|---|---|---|---|
| `/devops/api/bootstrap/` | GET | Current user, module permissions, counts | login | counts visible hosts for host count | no secrets |
| `/devops/api/hosts/` | GET | Visible host list | login | yes | password, private key, passphrase |
| `/devops/api/dashboard/` | GET | Counts, recent commands/alerts, latest metrics | login | hosts/commands/metrics scoped | host secrets |
| `/devops/api/commands/` | GET | Command execution list | login + command viewer/operator pattern | yes | host secrets |
| `/devops/api/commands/` | POST | Execute or request approval for a command | command operator | yes | host secrets |
| `/devops/api/commands/<id>/` | GET | Command detail | login | command host scoped | host secrets |
| `/devops/api/tasks/` | GET | Batch task list | login | should reflect accessible hosts where applicable | no secrets |
| `/devops/api/tasks/` | POST | Create batch task | task operator | selected hosts scoped | host secrets |
| `/devops/api/metrics/` | GET | Metric series | metric viewer | yes | no secrets |
| `/devops/api/alerts/` | GET | Alert events | login/alert view pattern | should scope host-visible alerts | no secrets |
| `/devops/api/approvals/` | GET | Approval list | login/approval pattern | approvals with host/release scope | no secrets |
| `/devops/api/deployments/` | GET | Deployment releases | login/deployment pattern | release hosts should be scoped | no secrets |
| `/devops/api/files/` | GET | File distributions | login/file pattern | distribution hosts should be scoped | no uploaded file internals beyond safe metadata |
| `/devops/api/notifications/` | GET | Channels and recent logs | login/notification admin pattern | n/a | webhook URL, secret |

## Naming Rules

- Keep endpoint paths plural for collections.
- Use trailing slash to match existing Django route style.
- Use `GET` for list/detail and `POST` for creation/action.
- Use `limit` query parameter for list endpoints; clamp it with `limit_queryset`.
- Use existing range values for metrics: `6h`, `24h`, `7d`, `30d`.

## Serializer Rules

- Keep serializer helpers in `devops/api.py` unless reused elsewhere.
- Include both raw status and `status_label` for user-facing status fields.
- Use `iso()` for datetimes.
- Use `serialize_host()` for nested host data, which intentionally omits credentials.
- For new nested models, serialize only fields consumed by Vue or documented API callers.

## New Endpoint Checklist

1. Add route in `devops/urls.py`.
2. Add view in `devops/api.py`.
3. Decorate with `api_login_required` and `require_http_methods`.
4. Parse JSON with `request_json` for JSON POST bodies.
5. Enforce role/module permission.
6. Enforce host scope before data exposure or action.
7. Return existing error shape.
8. Add tests for unauthenticated, forbidden, invalid input, success, and host-scope behavior.
9. Update `docs/devops_json_api.md` using `../templates/api-doc-entry.md`.
