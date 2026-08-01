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

### Frontend Skill Routing

For work that changes `templates/`, `static/`, Vue-rendered pages, or shared UI
styles, always read `centos-frontend-ui-dev` first. Then select the smallest
additional frontend skill set that matches the requested behavior:

- New visual direction, dashboard re-theme, or a distinctive AIOps/DevOps
  experience: `frontend-design` and `visual-design-foundations`.
- Shared tokens, component conventions, themes, or a reusable UI foundation:
  `design-system-patterns`.
- Desktop/mobile layout changes, data-table adaptation, or component-level
  sizing: `responsive-design`.
- Purposeful state transitions, progressive disclosure, loading feedback, or
  reduced-motion-aware microinteractions: `interaction-design`.
- Reusable Vue/HTML component structure or scoped component styling:
  `web-component-design`.
- UI review, accessibility audit, keyboard navigation, semantic markup, or
  pre-completion visual quality checks: `web-design-guidelines` and
  `accessibility-compliance`.

Do not load every frontend skill by default. The project-specific UI skill,
existing Django/Vue conventions, operational density, security rules, and user
requirements take precedence over third-party design guidance. In particular,
these skills must not turn operational pages into marketing layouts, add remote
runtime dependencies, replace existing CSRF handling, expose sensitive data, or
add motion that impairs monitoring and incident-response workflows.

Use the smallest relevant skill set. Do not treat this file as a replacement for feature-specific instructions.

## Execution Model

### Instruction Priority

Resolve instruction conflicts in this order:

1. The user's latest confirmed requirement.
2. Security, permission, data-protection, and legacy-compatibility rules in this file and the relevant feature skill.
3. Feature-specific project skills and references.
4. General coding guidance, including `karpathy-guidelines`.

General guidance is a quality lens, not an exception to project controls. In particular, prefer minimal, surgical changes and explicit success criteria, but never reduce required validation, authorization, encryption, or failure handling.

### Task Triage

Classify work before implementation. State the level in the user-facing TODO and use the lightest process that preserves safety and verification.

- **L1 - low risk:** Read-only analysis, documentation-only corrections, or tiny isolated changes with no design choice and no effect on permissions, models, APIs, runtime configuration, external systems, or user-visible behavior. Use a short TODO, state any minor assumption, make the focused change directly, and run the narrowest relevant check.
- **L2 - bounded change:** A single-module feature or bug fix with clear behavior and no schema, permission, or external-system contract change. Publish an execution contract, use a focused plan and validation, and delegate only when it creates a genuinely independent implementation or review track.
- **L3 - high risk or cross-cutting:** Any model or migration change, permission/authentication work, SSH or remote execution, secrets, file handling, webhook or external integration, DevOps state transition, deployment/runtime change, or coordinated multi-module/UI/API work. Publish a full plan, confirm material requirements, use subagents for independent tracks, and include security, rollback, and integration validation.

An explicit user request to implement, fix, or start work authorizes execution after the plan is published when the acceptance criteria are clear. It does not override a need to clarify a material ambiguity.

### Execution Contract

For L2 and L3 work, publish one concise execution contract before editing or delegating. It replaces repeated plan, assumption, and validation narration while preserving the required information:

```text
Scope: files/modules and behavior being changed.
Assumptions: only minor, reversible assumptions; list material questions separately.
Acceptance: observable behavior that proves the request is complete.
Validation: focused tests/checks and any external integration intentionally not exercised.
Risks: permissions, data, runtime, rollback, or compatibility concerns when applicable.
```

## Requirement Confirmation

After analyzing a request, separate confirmed requirements from assumptions and unresolved questions before planning implementation or modifying files.

- If any uncertainty could materially affect functionality, user interaction, API behavior, data handling, permissions, scope, or acceptance criteria, ask the user a focused clarification question and wait for confirmation before editing code or delegating implementation. Do not block L1 work for a minor, reversible detail; state that assumption in the TODO or execution contract instead.
- Do not substitute an inferred interpretation when the user can reasonably confirm the intended behavior. Present concrete options or examples when they make the decision easier to answer.
- Begin implementation only when the required behavior and acceptance criteria are sufficiently clear. Treat the user's confirmed answer as the authoritative requirement and update the TODO and implementation plan accordingly.
- Reasonable assumptions are allowed only for minor, reversible details that do not change the requested outcome. State any such assumption explicitly before relying on it.
- If new uncertainty appears during investigation or implementation, pause the affected work, report what was learned, and obtain confirmation before continuing with a materially different solution.

## Subagent Workflow

Use subagents for L3 work and for L2 work only when the task has independent, non-overlapping investigation, implementation, or review tracks. Complex project work includes new features, optimizations, requirement changes, cross-module fixes, schema/API/runtime changes, security-sensitive changes, frontend flows that require coordinated Python/template/static edits, and any task that needs multiple investigation or implementation tracks.

The main agent is responsible for assigning work, coordinating subagents, collecting and merging their findings, reviewing results, validating the integrated change, and summarizing what changed for the user. It should keep the overall context, decisions, risks, and final report centralized.

Subagents are responsible for completing the concrete requirements assigned to them. They should implement the requested code, tests, documentation, or focused investigation within their stated ownership boundaries, then report files changed, behavior changed, validation results, and any blockers back to the main agent.

When delegating, give each subagent explicit ownership:

- Objective and expected outcome.
- Files, modules, or responsibility area it may change.
- Files or areas it must not modify.
- Required project skill and reference files to read.
- Security constraints and sensitive data that must not be exposed.
- Narrow validation commands to run, or the exact reason validation is skipped.

Use `.codex/skills/centos-feature-dev/templates/subagent-task.md` as the default delegation prompt. L1 tasks and tightly coupled L2 tasks may be implemented directly when delegation would add coordination cost without improving safety, review quality, or elapsed time. All other implementation follows the ownership model above.

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
- For tiny or tightly coupled tasks, execute directly when coordination overhead would cost more than concurrency saves; record that decision in the user-facing TODO.
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
- General advice to omit handling for "impossible" scenarios never applies to authentication, authorization, untrusted input, encrypted values, uploads, paths, SSH, remote commands, webhooks, network calls, or background jobs. These boundaries require defensive validation and failure handling appropriate to their risk.

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
