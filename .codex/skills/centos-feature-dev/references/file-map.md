# File Map

High-value landmarks for fast navigation.

## Project And Runtime

- `manage.py` - run Django commands from the repository root.
- `PyLinux/settings.py` - installed apps, middleware, static/media paths, env-driven settings, `DEVOPS_SYNC_TASKS`.
- `PyLinux/checks.py` - production/runtime checks.
- `PyLinux/security.py` - shared security decorators/helpers.
- `PyLinux/vue.py` - Vue page payload wrapper and form/model serialization helpers.
- `PyLinux/urls.py` - root routing.

## Auth

- `userprofile/views.py` - login, logout, register, password verification, session setup.
- `userprofile/decorators.py` - `session_login_required`.
- `RemoteLinux/models.py` - custom `User` model and `NewLinux` host model.
- `RemoteLinux/forms.py` - user and host forms.

## Host And SSH

- `RemoteLinux/views.py` - host CRUD, import, connection test, status API, WebSSH.
- `RemoteLinux/ssh_utils.py` - SSH client creation and error classification.
- `RemoteLinux/collectors.py` - remote detail and usage parsers.
- `templates/linux/` - host list/detail/form pages.
- `static/xterm/js/ssh.js` - WebSSH browser behavior.

## Local Dashboard

- `linux/views.py` - index, local info page, host search.
- `linux/collectors.py` - local command parsing and system info collection.
- `templates/linux/index.html`, `templates/linux/local.html`, `templates/linux/detail.html`.

## Monitoring And Alerts

- `monitor/models.py`, `monitor/forms.py`, `monitor/views.py` - threshold configuration UI.
- `monitor/crontab.py` - scheduled remote metric collection and alert creation/resolution.
- `devops/services.py` - metric samples and alert lifecycle helpers.

## Password Vault

- `password/models.py`, `password/forms.py`, `password/views.py` - per-user encrypted password registry.
- `templates/password/` - vault list/form pages.
- `PyLinux/crypto.py` - encryption/decryption helpers.

## DevOps

- `devops/models.py` - roles, permissions, scopes, commands, tasks, files, deployments, approvals, alerts, metrics, notifications, audits.
- `devops/services.py` - reusable workflow logic, host scope, policies, background jobs, notifications, alert/metric helpers, audits.
- `devops/views.py` - template-backed DevOps pages.
- `devops/api.py` - JSON API endpoints and serializers.
- `devops/forms.py` - workflow/admin forms.
- `devops/urls.py` - DevOps page and API routes.
- `docs/devops_json_api.md` - API reference.

## AIOps

- `aiops/views.py` - dashboard aggregation, LLM fallback, config save, Alertmanager webhook.
- `aiops/models.py` - integration config and alert analysis storage.
- `templates/aiops/dashboard.html`, `static/js/aiops-vue.js`, `static/css/aiops-vue.css`.

## Frontend

- `templates/base.html`, `templates/header.html`, `templates/footer.html` - shared shell.
- `templates/vue/page.html` - Vue bridge page.
- `static/css/app-modern.css`, `static/css/custom.css`, `static/css/devops-vue.css`, `static/css/aiops-vue.css`, `static/css/ops-vue-pages.css`.
- `static/js/devops-vue.js`, `static/js/aiops-vue.js`, `static/js/ops-vue-pages.js`, `static/js/custom.js`.

