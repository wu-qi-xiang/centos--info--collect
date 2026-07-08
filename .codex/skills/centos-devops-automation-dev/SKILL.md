---
name: centos-devops-automation-dev
description: Work on DevOps automation in centos--info--collect: roles, module permissions, host scopes, commands, batch tasks, services, file distribution, deployments, rollbacks, approvals, notifications, audit logs, JSON APIs, and Vue-backed DevOps pages.
---

# Centos Devops Automation Dev

## When To Use

Use for the `devops` app: roles, permissions, host scope, command execution, background jobs, batch tasks, services, file distribution, deployments, rollbacks, approvals, alerts, metrics, notifications, audits, JSON APIs, and DevOps UI.

## Execution Rule

For development work, the main agent plans and delegates after user confirmation. Subagents perform implementation within explicit file/responsibility ownership. The main agent reviews, integrates, validates, and reports.

## Fast Path

### Add or change DevOps JSON API

Read:
1. `devops/api.py`
2. `devops/urls.py`
3. `devops/services.py`
4. `devops/models.py`
5. `docs/devops_json_api.md`
6. `devops/tests.py`

Change:
1. Keep session auth and JSON error shape: `{ok: false, code, message}`.
2. Enforce role/module permission and host scope.
3. Serialize safe fields only.
4. Update docs and focused API tests.

### Change commands, tasks, deployments, files, or services

Read:
1. `devops/views.py`
2. `devops/services.py`
3. `devops/forms.py`
4. `devops/models.py`
5. related templates/static files
6. `devops/tests.py`

Change:
1. Put reusable workflow logic in `devops/services.py`.
2. Keep `DEVOPS_SYNC_TASKS` path testable.
3. Preserve parent/per-host status transitions for success, partial, failed, blocked, and approval paths.
4. Validate remote paths with `validate_remote_path`.
5. Add audits for privileged actions and background failures.

### Change permissions or host scope

Read:
1. `devops/services.py`
2. `devops/models.py`
3. `devops/views.py`
4. `devops/api.py`
5. affected feature tests

Change:
1. Use `visible_hosts_for_request`, `can_access_host`, `can_access_hosts`, or `require_host_access`.
2. Keep bootstrap/menu behavior consistent.
3. Add regression tests for admin/operator/viewer and scoped/unscoped users.

## Invariants

- Do not run user-provided shell text locally.
- Managed commands target remote hosts through SSH.
- Do not expose encrypted webhook URLs, secrets, host credentials, or private keys.
- `bootstrap` should remain the first-call endpoint for menus/current user/roles/counts.
- Notifications support WeCom, DingTalk, and generic webhook channels with encrypted URL/secret and deduplication.

## Validation

```bash
.venv/bin/python manage.py test devops
.venv/bin/python manage.py check
```

Mock SSH, notification receivers, deployment targets, and uploads unless live integration is explicitly requested.

## Shared References

- `../centos-feature-dev/references/change-recipes.md`
- `../centos-feature-dev/references/django-legacy-standards.md`
- `../centos-feature-dev/references/devops-api-dictionary.md`
- `../centos-feature-dev/references/devops-state-models.md`
- `../centos-feature-dev/references/security-checkpoints.md`
- `../centos-feature-dev/references/test-matrix.md`
- `../centos-feature-dev/references/test-patterns.md`
- `../centos-feature-dev/references/documentation-rules.md`
- `../centos-feature-dev/references/review-checklist.md`
- `../centos-feature-dev/references/file-map.md`
- `../centos-feature-dev/templates/api-doc-entry.md`
