---
name: centos-feature-dev
description: Fast development router for the centos--info--collect Django project. Use when implementing, debugging, testing, reviewing, or planning any code change in this repository, especially when the request could touch multiple apps, APIs, UI payloads, security, SSH, monitoring, DevOps automation, AIOps, deployment, or documentation.
---

# Centos Feature Dev

Use this as the first skill for development work in `centos--info--collect`. Its job is to route a user request to the smallest useful implementation path.

## Plan Before Execution

For every new feature, optimization, requirement change, or multi-step development request, the main agent must first produce an implementation plan before any file edits or subagent delegation. The plan should identify scope, affected files/modules, security and permission considerations, tests, and rollback/runtime risks. Begin implementation only after the user confirms the plan or explicitly asks to proceed.

All development implementation tasks must be executed by subagents after the main-agent plan exists. The main agent owns planning, decomposition, delegation, review, integration, validation, and reporting; subagents own the concrete code/document/test changes assigned to them. Each subagent task must have explicit file or responsibility ownership and must not start independent implementation before the main plan exists.

Direct main-agent edits are exempt only for non-development housekeeping or a tiny, specific correction with no design choice, permission impact, schema/API/runtime change, cross-module behavior, or implementation work.

## Fast Workflow

1. Classify the request with `references/task-router.md`.
2. For feature, optimization, or requirement work, produce the main-agent plan before any edit or delegation, then delegate implementation to subagents after confirmation; use `references/requirements-triage.md` when the request is ambiguous, risky, or has multiple viable designs.
3. Read the matching feature skill after this entry skill.
4. Use the closest recipe from `references/change-recipes.md`.
5. Follow legacy Django style in `references/django-legacy-standards.md`.
6. Check invariants in `references/security-checkpoints.md`.
7. For DevOps workflow changes, check `references/devops-state-models.md`; for DevOps API changes, check `references/devops-api-dictionary.md`.
8. For UI work, apply `references/ui-standards.md`; for docs/API/env behavior, apply `references/documentation-rules.md`.
9. Choose test cases with `references/test-patterns.md`.
10. For every feature, optimization, or requirement, plan before editing or delegating; for medium or risky changes, use `templates/implementation-plan.md`.
11. Validate with `references/test-matrix.md`.
12. Review with `references/review-checklist.md`.
13. Report verification using `templates/test-report.md` when tests or manual checks matter.

## Project Constraints

- This project runs on Python 3.11 and Django 4.2.16. Preserve its established function-based views, templates, forms, migrations, and direct static assets unless modernization is explicitly requested.
- `manage.py` is at the repository root.
- Runtime code lives at the repository top level to preserve legacy imports.
- Prefer focused changes that preserve existing table names, session keys, URL shapes, and deployment assumptions.

## Feature Skill Map

- Broad project context: `centos-info-collect-dev`.
- Auth/login/register/session: `centos-auth-user-dev`.
- Host inventory, SSH, import, WebSSH: `centos-host-ssh-dev`.
- Local dashboard/search/local collectors: `centos-local-dashboard-dev`.
- Monitoring, cron collection, metrics, alert events: `centos-monitor-alert-dev`.
- Password/account vault: `centos-password-vault-dev`.
- DevOps roles, permissions, APIs, commands, tasks, deployments, notifications, audits: `centos-devops-automation-dev`.
- AIOps dashboard, webhook, LLM fallback: `centos-aiops-dev`.
- Templates, Vue payloads, static CSS/JS: `centos-frontend-ui-dev`.
- Settings, environment, Docker, Compose, Kubernetes: `centos-deploy-runtime-dev`.

## Shared References

- `references/task-router.md` - map user requests to read/edit/test paths.
- `references/change-recipes.md` - repeatable implementation recipes.
- `references/requirements-triage.md` - decide when to ask, plan, or compare options.
- `references/django-legacy-standards.md` - coding standards for this Django 4.2.16 codebase with legacy application conventions.
- `references/devops-api-dictionary.md` - `/devops/api/*` contract and endpoint dictionary.
- `references/devops-state-models.md` - DevOps workflow status models and transitions.
- `references/aiops-llm-contract.md` - AIOps LLM, Alertmanager webhook, and analysis storage contract.
- `references/security-checkpoints.md` - mandatory security and data exposure checks.
- `references/test-matrix.md` - focused validation by change type.
- `references/test-patterns.md` - test case patterns for common changes.
- `references/review-checklist.md` - final self-review checklist.
- `references/documentation-rules.md` - docs/API/env update rules.
- `references/runtime-env-dictionary.md` - runtime environment variable contract.
- `references/optimization-roadmap.md` - completed and recommended optimization phases.
- `references/ui-standards.md` - UI and Vue/static conventions.
- `references/file-map.md` - high-value code landmarks.
- `skill-map.yaml` - machine-readable route map for skills, references, and tests.
- `templates/review-report.md` - review report structure.
- `templates/api-doc-entry.md` - DevOps API documentation entry template.
- `templates/subagent-task.md` - standard subagent delegation prompt template.
- `scripts/check_skill_links.py` - validate skill metadata and local references.
- `examples/` - concrete development paths for common request types.
