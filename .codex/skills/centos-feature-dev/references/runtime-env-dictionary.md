# Runtime Env Dictionary

Use this when changing `PyLinux/settings.py`, `PyLinux/checks.py`, `.env.example`, deployment manifests, or runtime docs.

## Core Django

| Env var | Default | Production safe | Used by | Notes |
|---|---|---|---|---|
| `DJANGO_SETTINGS_MODULE` | `PyLinux.settings` in `.env.example` | yes | runtime entrypoints | Usually unchanged. |
| `DJANGO_ENV` | `development` | set to `production` | `settings.py`, `checks.py` | Production mode is `prod`/`production` or `DEBUG=False`. |
| `DJANGO_SECRET_KEY` | `django-insecure-change-me` | no | `settings.SECRET_KEY` | Required in production; checked by `pylinux.E001`. |
| `DATA_ENCRYPTION_KEY` | empty | no | `PyLinux.crypto`, checks | Required in production; checked by `pylinux.E002`. Development without it warns `pylinux.W001`. |
| `DJANGO_DEBUG` | `True` | no | `settings.DEBUG` | Use false-like value in production. |
| `DJANGO_ALLOWED_HOSTS` | `*` | no | `settings.ALLOWED_HOSTS` | Comma-separated; `*` is blocked in production by `pylinux.E003`. |
| `DJANGO_STATIC_ROOT` | `<BASE_DIR>/staticfiles` | yes | `settings.STATIC_ROOT` | Update deployment/static collection docs if changed. |

## Database

| Env var | Default | Required | Notes |
|---|---|---|---|
| `DB_ENGINE` | `sqlite` | no | Aliases: `sqlite`, `sqlite3`, `mysql`, `postgres`, `postgresql`, or full Django backend. |
| `DB_NAME` | `<BASE_DIR>/db.sqlite3` for SQLite | yes for non-SQLite | Non-SQLite raises `ImproperlyConfigured` if missing. |
| `DB_USER` | empty | no | Passed to Django DB `USER` when set. |
| `DB_PASSWORD` | empty | no | Passed to Django DB `PASSWORD` when set; never document real value. |
| `DB_HOST` | empty | no | Passed to Django DB `HOST` when set. |
| `DB_PORT` | empty | no | Passed to Django DB `PORT` when set. |
| `DB_CONN_MAX_AGE` | `60` | no | Must be integer. |
| `DB_CHARSET` | empty | no | Adds `OPTIONS={"charset": value}`. Common MySQL value: `utf8mb4`. |

## Email

| Env var | Default | Notes |
|---|---|---|
| `EMAIL_HOST` | `smtp.qq.com` | SMTP host for monitor notifications. |
| `EMAIL_PORT` | `587` | Parsed as integer. |
| `EMAIL_HOST_USER` | empty | Also used as `DEFAULT_FROM_EMAIL`. |
| `EMAIL_HOST_PASSWORD` | empty | Secret; never log or document real value. |
| `EMAIL_USE_TLS` | `True` | Boolean strings: `1`, `true`, `yes`, `on`. |
| `EMAIL_USE_SSL` | `False` | Boolean strings: `1`, `true`, `yes`, `on`. |

## DevOps, WebSSH, Notifications, Audit

| Env var | Default | Notes |
|---|---:|---|
| `DEVOPS_TASK_RETRY_COUNT` | `0` | Number of retries for command/file/deployment operations where supported. |
| `DEVOPS_SSH_CONNECT_TIMEOUT_SECONDS` | `10` | SSH connection timeout. |
| `DEVOPS_COMMAND_TIMEOUT_SECONDS` | `60` | Remote command timeout. |
| `DEVOPS_COMMAND_OUTPUT_MAX_BYTES` | `204800` | Output capture limit. Add to `.env.example` if changed; currently in README but may be absent from `.env.example`. |
| `WEBSSH_SESSION_TIMEOUT_SECONDS` | `1800` | WebSSH session timeout. |
| `NOTIFICATION_DEDUP_SECONDS` | `300` | Notification deduplication window. |
| `NOTIFICATION_RETRY_COUNT` | `0` | Notification send retry count. |
| `NOTIFICATION_TIMEOUT_SECONDS` | `5` | Notification HTTP timeout. |
| `AUDIT_LOG_RETENTION_DAYS` | `0` | `0` means no retention cleanup by default. |

`DEVOPS_SYNC_TASKS` is not env-driven; it is true during `manage.py test` via `sys.argv`.

## K8s Detail Cache

| Env var | Default | Notes |
|---|---:|---|
| `K8S_CACHE_DIR` | `<BASE_DIR>/.cache/k8s` | Local file-cache directory. Relative paths resolve from `BASE_DIR`. It must be writable; use a persistent mount when cache data must survive container replacement. |
| `K8S_DETAIL_CACHE_TIMEOUT_SECONDS` | `86400` | K8s detail cache lifetime in seconds. Must be a positive integer. |

The cache contains only safe resource summaries used by the cluster detail page. It must not contain kubeconfig content, access tokens, client certificates, or raw Kubernetes Secret values. A user-requested refresh bypasses the cached result and replaces it with a fresh K8s API query.

## Gunicorn Deployment Vars

These appear in `.env.example` for deployment scripts/configs, not in `PyLinux/settings.py`:

| Env var | Default example | Notes |
|---|---|---|
| `GUNICORN_BIND` | `0.0.0.0:8000` | Bind address. |
| `GUNICORN_WORKERS` | `3` | Worker count. |
| `GUNICORN_TIMEOUT` | `120` | Worker timeout. |
| `GUNICORN_ACCESS_LOG` | `logs/gunicorn-access.log` | Access log path. |
| `GUNICORN_ERROR_LOG` | `logs/gunicorn-error.log` | Error log path. |

## Change Checklist

When adding or changing an env var:

1. Update `PyLinux/settings.py` or deployment config.
2. Add validation in `PyLinux/checks.py` if unsafe production values are possible.
3. Update `.env.example`.
4. Update `README.md` or deployment docs.
5. Do not include real secrets.
6. Run `.venv/bin/python manage.py check`.
