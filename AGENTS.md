# Codex Development Standards

This file defines the working standard for Codex agents developing this repository. Follow it before making code, test, documentation, deployment, or UI changes.

## Project Baseline

- This is a legacy Django 2.1 operations platform. Keep changes compatible with the existing style unless the task explicitly asks for modernization.
- `manage.py` is at the repository root. Run Django commands from the repository root.
- Runtime code is split by feature:
  - `PyLinux/`: settings, root URLs, WSGI, shared crypto/security/Vue helpers.
  - `userprofile/`: login, logout, registration, session auth.
  - `RemoteLinux/`: server assets, SSH credentials, remote collection, WebSSH.
  - `linux/`: local Linux dashboard, local collectors, search.
  - `monitor/`: threshold config and scheduled metric collection.
  - `password/`: per-user encrypted password/account registry.
  - `devops/`: roles, permissions, host scopes, commands, tasks, files, deployments, approvals, alerts, metrics, notifications, audit, JSON APIs.
  - `aiops/`: analysis dashboard, anomaly/correlation/root-cause summaries, Alertmanager webhook, optional LLM analysis.
  - `templates/` and `static/`: server templates, Vue pages, CSS, JS, vendored frontend assets.
  - `deploy/` and `k8s/`: runtime packaging and deployment manifests.

## Skill Selection

Before focused work, read the matching project skill under `.codex/skills/`:

- Fast development router for implementation/debugging/planning: `centos-feature-dev`.
- Broad project context: `centos-info-collect-dev`.
- Auth/user work: `centos-auth-user-dev`.
- Host inventory, SSH, import, WebSSH: `centos-host-ssh-dev`.
- Local dashboard/search: `centos-local-dashboard-dev`.
- Monitoring, alerts, metrics: `centos-monitor-alert-dev`.
- Password vault: `centos-password-vault-dev`.
- DevOps automation/API: `centos-devops-automation-dev`.
- AIOps analysis/webhook/LLM: `centos-aiops-dev`.
- Templates/static UI: `centos-frontend-ui-dev`.
- Settings/deploy/runtime: `centos-deploy-runtime-dev`.

Use the smallest relevant skill set. Do not treat this file as a replacement for feature-specific instructions.

When changing skill files, validate metadata and local references:

```bash
python3 .codex/skills/centos-feature-dev/scripts/check_skill_links.py
```

## Working Method

- Read routing, models/forms, views/services, templates/static files, and tests for the feature before editing.
- Prefer small, local changes that preserve existing behavior outside the requested scope.
- Match the current function-based Django style unless a tighter pattern is needed to fix a bug.
- Put reusable business logic in service/helper modules, not only in views.
- Keep model table names stable. Many models use explicit legacy `db_table` values.
- When changing a model field, add or update migrations and update forms, templates, serializers/payload helpers, and tests together.
- Do not revert unrelated user changes in the working tree.

## Security Rules

- Never expose host SSH passwords, private keys, private key passphrases, password-vault secrets, webhook URLs, or notification secrets in templates, JSON, logs, audits, or test output.
- Preserve encrypted storage through `PyLinux.crypto` for host credentials, password-vault values, and notification secrets.
- Keep custom session auth conventions: `is_login`, `user_id`, and `user_name`.
- For DevOps actions, enforce role, module permission, and host scope before exposing data or executing work.
- Use `visible_hosts_for_request`, `can_access_host`, `require_host_access`, or related helpers for host-scoped behavior.
- Validate redirect targets, remote paths, uploaded files, and webhook payloads defensively.
- Avoid adding user-controlled shell interpolation. Managed commands should target remote hosts through the existing SSH execution flow.

## Feature Rules

### Auth

- `RemoteLinux.models.User` is the active user model for app login.
- Support existing hashed and legacy plaintext passwords; upgrade plaintext only through the established login flow.
- Clear any new session state on logout.

### Host And SSH

- Preserve existing credentials when update forms leave password/key fields blank.
- Use `RemoteLinux.ssh_utils` for SSH clients and error formatting.
- Keep remote/local command parsing in collector modules where practical.
- Use mocked SSH in tests unless live integration is explicitly requested.

### Monitoring And Alerts

- Parse thresholds numerically; do not compare raw percentage strings.
- Use `record_metric_sample`, `record_alert`, `resolve_alert`, and `update_alert_status` rather than open-coded alert writes.
- One failing host must not stop the whole scheduled collection run.

### DevOps

- Keep command policy checks, approval creation, status transitions, per-host result rows, notifications, and audits consistent.
- Make background jobs testable with `DEVOPS_SYNC_TASKS`.
- Validate file distribution paths with `validate_remote_path`.
- Do not serialize encrypted or sensitive fields in `/devops/api/*`.

### AIOps

- Treat AIOps as an analysis layer over DevOps data. Do not duplicate execution or alert lifecycle logic there.
- Dashboard and tests must work without external LLM/network access.
- Respect host scope in all user-facing analysis.

### Frontend

- Keep the app operational and dense, not marketing-oriented.
- Coordinate template, static JS/CSS, and Python payload changes.
- Keep CSRF behavior intact for POST forms and fetch calls.
- Avoid remote CDN dependencies; prefer vendored/static assets already in the repo.

## Testing And Validation

Run the narrowest useful tests first, then broaden when the change affects shared behavior:

```bash
.venv/bin/python manage.py check
.venv/bin/python manage.py test
```

Focused examples:

```bash
.venv/bin/python manage.py test userprofile
.venv/bin/python manage.py test RemoteLinux
.venv/bin/python manage.py test linux
.venv/bin/python manage.py test monitor
.venv/bin/python manage.py test password
.venv/bin/python manage.py test devops
.venv/bin/python manage.py test aiops
```

If the local Python environment cannot run the legacy dependency set, state that clearly and do not claim runtime verification.

For SSH, SMTP, cron, webhooks, deployment, and browser UI flows, prefer unit tests with mocks. Manual verification should state which external systems were or were not exercised.

## Documentation

- Update `README.md`, `docs/`, `.env.example`, or the relevant skill when behavior, setup, API, or operational assumptions change.
- For new DevOps JSON APIs, document endpoint shape, auth behavior, sensitive-field omissions, and permission/host-scope rules.
- Keep documentation factual and current with code. Remove or revise outdated security notes when the code has been hardened.
