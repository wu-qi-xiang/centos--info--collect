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

## Subagent Workflow

Use subagents for complex project work after the main agent has read the relevant skill instructions and produced a clear plan. Complex work includes new features, optimizations, requirement changes, cross-module fixes, schema/API/runtime changes, security-sensitive changes, frontend flows that require coordinated Python/template/static edits, and any task that needs multiple investigation or implementation tracks.

The main agent is responsible for assigning work, coordinating subagents, collecting and merging their findings, reviewing results, validating the integrated change, and summarizing what changed for the user. It should keep the overall context, decisions, risks, and final report centralized.

Subagents are responsible for completing the concrete requirements assigned to them. They should implement the requested code, tests, documentation, or focused investigation within their stated ownership boundaries, then report files changed, behavior changed, validation results, and any blockers back to the main agent.

When delegating, give each subagent explicit ownership:

- Objective and expected outcome.
- Files, modules, or responsibility area it may change.
- Files or areas it must not modify.
- Required project skill and reference files to read.
- Security constraints and sensitive data that must not be exposed.
- Narrow validation commands to run, or the exact reason validation is skipped.

Use `.codex/skills/centos-feature-dev/templates/subagent-task.md` as the default delegation prompt. Direct main-agent edits are reserved for non-development housekeeping or tiny, specific corrections with no design choice, permission impact, schema/API/runtime change, cross-module behavior, or substantive implementation work.

## Task TODO Visibility

At the start of every task, publish a user-facing TODO list before investigation, delegation, implementation, or validation begins. This step is mandatory even when the task is small.

- List the concrete investigation, implementation, validation, and completion steps that are currently known.
- Mark each item as pending, in progress, completed, or blocked, and keep at most one main-agent item in progress at a time.
- Update the printed TODO whenever an item completes, becomes blocked, changes scope, or creates new follow-up work; do not wait until the final response to mark everything complete.
- Include planned subagent assignments in the TODO and keep their visible status synchronized with subagent progress.
- For a tiny direct task, print a one-item or short TODO instead of omitting the list.
- Include final validation and the completion self-check as explicit TODO items.
- Never include secrets, credentials, sensitive URLs, or confidential data in the printed TODO.
- Do not silently execute work that is absent from the current user-facing TODO; update the TODO first.

## Subagent Task Visibility

At the start of every task, publish the subagent delegation decision to the user before spawning or assigning work. This visibility step is mandatory for every task.

- When subagents are used, print each task assignment in a readable block before dispatch. Include the subagent name, objective, owned files or responsibility area, prohibited files or areas, required validation, and relevant security constraints.
- Print follow-up or reassigned subagent task contents before sending them as well; do not silently expand an agent's ownership or objective.
- Never include passwords, private keys, tokens, webhook secrets, sensitive URLs, or other confidential values in the printed assignment.
- When a subagent finishes, report its completion status, files changed, validation result, and important findings before or during integration.
- When no subagent is used, explicitly state that decision and why direct execution is more efficient or safer for the task.
- Do not silently spawn, reassign, or omit the task contents from user-facing progress updates.

## Concurrency And Efficiency

At the start of every task, before beginning sequential investigation or implementation, explicitly assess whether the work can be split into independent tracks and executed concurrently. Use concurrency when it shortens the critical path without creating file conflicts or duplicated work.

- Run independent repository searches, file reads, diagnostics, and validation commands in parallel when possible.
- Delegate bounded investigation, implementation, test, and review tracks to subagents when they have clear, non-overlapping ownership.
- Keep useful main-agent work moving while subagents run; do not wait on one track when another independent track can proceed.
- Keep dependent steps and edits to the same files serial unless ownership and merge order are unambiguous.
- For tiny or tightly coupled tasks, execute directly when coordination overhead would cost more than concurrency saves.
- Reassess concurrency after new findings change the task scope, and parallelize newly independent follow-up work.

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

## Completion Self-Check

After every task, Codex must complete and report a self-check before handing work back to the user:

- Confirm the implemented changes match the user's latest request and do not include unrelated refactors or reversions.
- Run the narrowest useful validation commands for the change, such as `manage.py check`, focused tests, syntax checks, or browser/UI checks when available.
- If a validation step cannot run, state the exact reason and do not claim it passed.
- Summarize the modified files and the important changes in each file.
- Summarize the user-visible functionality implemented or fixed.
- Call out any remaining risks, skipped external integrations, or manual checks the user should know about.

## Documentation

- Update `README.md`, `docs/`, `.env.example`, or the relevant skill when behavior, setup, API, or operational assumptions change.
- For new DevOps JSON APIs, document endpoint shape, auth behavior, sensitive-field omissions, and permission/host-scope rules.
- Keep documentation factual and current with code. Remove or revise outdated security notes when the code has been hardened.
