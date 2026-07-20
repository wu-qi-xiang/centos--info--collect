---
name: centos-info-collect-dev
description: Broad project development guide for centos--info--collect, a Python 3.11/Django 4.2.16 operations platform with legacy application conventions for server inventory, SSH collection, alerting, WebSSH, login, password management, DevOps automation, and AIOps. Use for repository-wide analysis, modification, debugging, testing, running, containerizing, or review.
---

# Centos Info Collect Dev

## When To Use

Use for broad repository context or changes that span multiple apps. For direct implementation, read `centos-feature-dev` first, then the most specific feature skill.

Before any new feature, optimization, requirement change, or multi-step development request, follow `centos-feature-dev` plan-before-execution rules: the main agent drafts the plan first, waits for user confirmation or an explicit proceed instruction, then delegates implementation to subagents. The main agent reviews, integrates, validates, and reports; subagents perform the development changes.

## Project Shape

- `PyLinux/`: settings, root URLs, WSGI, shared crypto/security/Vue helpers.
- `RemoteLinux/`: server inventory, SSH credentials, remote collection, WebSSH, custom `User`.
- `linux/`: local dashboard, local collectors, search.
- `monitor/`: threshold configuration and scheduled remote metric collection.
- `password/`: per-user encrypted password/account registry.
- `userprofile/`: login/logout/register using custom session auth.
- `devops/`: roles, permissions, host scopes, commands, tasks, files, deployments, approvals, alerts, metrics, notifications, audits, JSON APIs.
- `aiops/`: analysis dashboard, anomaly/correlation/root-cause summaries, Alertmanager webhook, optional LLM analysis.
- `templates/` and `static/`: direct Django template/static roots.
- `deploy/` and `k8s/`: runtime packaging and deployment manifests.

## Fast Path

### Start any development task

Read:
1. `../centos-feature-dev/SKILL.md`
2. `../centos-feature-dev/references/task-router.md`
3. the matching feature skill
4. `../centos-feature-dev/references/file-map.md` if navigation is unclear

Then:
1. Follow the task-specific read order.
2. Use a recipe from `change-recipes.md` for common changes.
3. Check security invariants before finishing.
4. Run the focused tests in `test-matrix.md`.

### Run or validate the project

Use commands from the repository root:

```bash
.venv/bin/python manage.py check
.venv/bin/python manage.py test
.venv/bin/python manage.py runserver 127.0.0.1:8000
```

The README may mention running from `PyLinux`, but `manage.py` is at the repository root.

## Legacy Constraints

- Keep Python 3.11/Django 4.2.16 compatibility and preserve established application conventions unless modernization is explicitly requested.
- Preserve explicit legacy table names such as `linux-info`, `monitor-info`, `password_manage`, and `user`.
- Match function-based views, ModelForms, direct templates, and local static assets unless a safer helper is already established.
- Do not casually rename URLs, tables, session keys, or deployment paths.

## Security Hotspots

- Hard-coded development defaults exist in settings; do not add new secrets.
- Host SSH credentials, password-vault secrets, notification secrets, and webhook URLs must not leak.
- Host scope and DevOps permissions are central to safe behavior.
- Remote SSH command handling must avoid local execution of user-provided shell text.

## Validation

Use the focused commands in `../centos-feature-dev/references/test-matrix.md`. If the configured dependency set cannot run locally, report the failure and avoid claiming runtime verification.

## Shared References

- `../centos-feature-dev/references/task-router.md`
- `../centos-feature-dev/references/change-recipes.md`
- `../centos-feature-dev/references/requirements-triage.md`
- `../centos-feature-dev/references/django-legacy-standards.md`
- `../centos-feature-dev/references/devops-api-dictionary.md`
- `../centos-feature-dev/references/devops-state-models.md`
- `../centos-feature-dev/references/aiops-llm-contract.md`
- `../centos-feature-dev/references/security-checkpoints.md`
- `../centos-feature-dev/references/test-matrix.md`
- `../centos-feature-dev/references/test-patterns.md`
- `../centos-feature-dev/references/review-checklist.md`
- `../centos-feature-dev/references/documentation-rules.md`
- `../centos-feature-dev/references/runtime-env-dictionary.md`
- `../centos-feature-dev/references/ui-standards.md`
- `../centos-feature-dev/references/file-map.md`
