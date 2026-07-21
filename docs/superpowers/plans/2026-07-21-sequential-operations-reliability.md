# Sequential Operations Reliability Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver P0-P4 reliability improvements in order without changing the local SQLite workflow, session authentication, host-scope checks, command policy, or default remote-execution behavior.

**Architecture:** Keep production topology additive. Make the AIOps webhook sanitizer the only input path for persistence and LLM calls. Extend the existing DevOps service, approval, audit, and Worker layers for SLOs and Runbooks; do not add an alternate execution path.

**Tech Stack:** Django 4.2.16, Python 3.11, Django TestCase, mocked HTTP/SSH, Docker Compose, PostgreSQL 16, Nginx.

---

## File Map

- `aiops/models.py`, `aiops/views.py`, `aiops/tests.py`: sanitized alert analysis, encrypted LLM key, and retention.
- `PyLinux/settings.py`, `PyLinux/checks.py`, `.env.example`: retention setting and runtime validation.
- `deploy/`, `docs/production_deployment.md`, `PyLinux/tests.py`: opt-in PostgreSQL/Nginx reference.
- `devops/models.py`, `devops/forms.py`, `devops/services.py`, `devops/views.py`, `devops/api.py`, `devops/urls.py`: RBAC closure, SLOs, and Runbooks.
- `devops/tests.py`, `aiops/tests.py`, `docs/devops_json_api.md`, `templates/devops/`: contract tests and user-facing management views.

### Task 1: P0 AIOps Data And Secret Governance

**Files:**
- Modify: `aiops/models.py`, `aiops/views.py`, `aiops/tests.py`, `PyLinux/settings.py`, `PyLinux/checks.py`, `.env.example`, `README.md`
- Create: `aiops/migrations/0003_aiops_safe_analysis.py`, `aiops/management/commands/cleanup_aiops_analyses.py`

- [ ] **Step 1: Add failing data-governance tests.** Add `AiopsDataGovernanceTests` for: encrypted-at-rest key with blank update preserving its prior value; webhook input containing URLs, tokens, commands, oversized labels and control characters; safe stored fields and LLM request body; positive retention deletion and non-positive no-op cleanup.
- [ ] **Step 2: Run the focused RED test.** Run `.venv/bin/python manage.py test aiops.tests.AiopsDataGovernanceTests`; expect failure because raw payload, raw LLM response, and plaintext key storage still exist.
- [ ] **Step 3: Implement the bounded analysis contract.** Add `sanitize_alert(alert)` that permits only `alertname`, `severity`, `instance`/`host`, `summary`/`description`, and labels `service`, `job`, `environment`; strip controls and URLs and truncate values. Make `_alert_text`, `_fallback_suggestion`, `_call_llm`, and `_save_alert_analysis` consume its return value. Encrypt `AiopsIntegration.llm_api_key`; preserve it when configuration input is blank. Add safe analysis fields and stop persisting `raw_payload`/`llm_response`.
- [ ] **Step 4: Implement retention.** Add `AIOPS_ANALYSIS_RETENTION_DAYS`, reject negative values in checks, and make the cleanup command delete only `created_at` records older than a positive cutoff while reporting only a count.
- [ ] **Step 5: Verify GREEN.** Run `.venv/bin/python manage.py test aiops`, `.venv/bin/python manage.py check`, and `.venv/bin/python manage.py makemigrations --check --dry-run`; expect success without network access.

### Task 2: P1 Opt-In PostgreSQL And Nginx Production Reference

**Files:**
- Create: `deploy/docker-compose.production.yml`, `deploy/nginx/default.conf`, `docs/production_deployment.md`
- Modify: `.env.example`, `README.md`, `PyLinux/tests.py`

- [ ] **Step 1: Add failing reference tests.** Add `ProductionComposeReferenceTests` that assert the additive Compose file defines `postgres`, `web`, `worker`, and `nginx`; uses `DB_ENGINE=postgresql`; does not contain literal credentials or expose the database; and routes liveness/readiness through Nginx.
- [ ] **Step 2: Run the focused RED test.** Run `.venv/bin/python manage.py test PyLinux.tests.ProductionComposeReferenceTests`; expect failure because the files are absent.
- [ ] **Step 3: Add additive topology assets.** Create an override with a named PostgreSQL volume, environment-only database values, existing `web`/`worker` image contracts, shared static/media volumes, and Nginx on port 80. Serve `/static/` and `/uploads/`; proxy application requests to `web:8000`; do not include TLS certificates or database port publishing.
- [ ] **Step 4: Document use and rollback.** Describe untracked environment setup, migration then collectstatic order, `check --deploy`, health probes, encrypted-backup preflight, and stopping only the override stack to return to local development.
- [ ] **Step 5: Verify GREEN.** Run `.venv/bin/python manage.py test PyLinux.tests.ProductionComposeReferenceTests`, `.venv/bin/python manage.py check`, and `docker compose -f deploy/docker-compose.yml -f deploy/docker-compose.production.yml config`; use temporary environment values only for Compose rendering.

### Task 3: P2 RBAC Administration Closure

**Files:**
- Modify: `devops/services.py`, `devops/views.py`, `devops/urls.py`, `devops/forms.py`, `devops/tests.py`, `templates/devops/security.html`, `templates/header.html`

- [ ] **Step 1: Add failing authorization tests.** Add tests proving a security administrator can revoke one module permission and clear a selected user's module permissions, each producing audits with before/after summaries; a viewer/operator cannot mutate them; and the shared sidebar does not render DevOps module entries unavailable to the current user.
- [ ] **Step 2: Run the focused RED test.** Run `.venv/bin/python manage.py test devops.tests.RbacAdministrationClosureTests`; expect failure because revoke/clear endpoints and conditional shared navigation are absent.
- [ ] **Step 3: Implement auditable service functions.** Add `revoke_module_permission(request, permission)` and `clear_module_permissions(request, user)` in `devops/services.py`. Require existing security-admin authorization in views, delete only explicit `DevOpsModulePermission` rows, and write summary-only audit details containing user, module, old role, and resulting state.
- [ ] **Step 4: Add management actions and navigation context.** Add CSRF-protected POST routes/forms for per-row revoke and per-user clear. Pass the existing module-permission context to the shared header and hide only DevOps-specific navigation entries the user cannot read; do not hide asset, monitor, password, or K8s routes with unrelated policy.
- [ ] **Step 5: Verify GREEN.** Run `.venv/bin/python manage.py test devops.tests.RbacAdministrationClosureTests`, `.venv/bin/python manage.py test devops`, and `.venv/bin/python manage.py check`.

### Task 4: P3 Service SLO And Error-Budget Release Gate

**Files:**
- Create: `devops/migrations/0023_service_slo.py`, `templates/devops/service_slos.html`
- Modify: `devops/models.py`, `devops/forms.py`, `devops/services.py`, `devops/views.py`, `devops/api.py`, `devops/urls.py`, `devops/tests.py`, `docs/devops_json_api.md`

- [ ] **Step 1: Add failing SLO workflow tests.** Cover invalid metric kind/target, forbidden viewer mutations, out-of-scope service reads, unavailable Prometheus, healthy budget release enqueue, exhausted budget approval creation/reuse, and omission of raw Prometheus data from responses/audits.
- [ ] **Step 2: Run the focused RED test.** Run `.venv/bin/python manage.py test devops.tests.ServiceSloTests`; expect failure because no SLO schema or gate exists.
- [ ] **Step 3: Implement SLO model and evaluator.** Add `ServiceSlo` linked to `ServiceCatalog`, with closed metric choices (`availability`, `latency`, `error_rate`), bounded numeric target and window, enabled flag, and safe last-result summary. Map choices to fixed server-side Prometheus templates, accept only finite numeric results, and store `healthy`, `exhausted`, or `unavailable`.
- [ ] **Step 4: Gate the existing release path.** Before a deployment release is queued, evaluate relevant enabled SLOs. For exhausted budgets create or reuse `ApprovalRequest.TYPE_DEPLOYMENT`; unavailable metrics must preserve the existing path. Use summary-only audits and never execute a rollback automatically.
- [ ] **Step 5: Add protected surfaces and docs.** Provide security-admin writes plus service/host-scope-safe reads under `/devops/service-slos/` and `/devops/api/service-slos/`. Document auth, permissions, scope, states, and omitted fields.
- [ ] **Step 6: Verify GREEN.** Run `.venv/bin/python manage.py test devops.tests.ServiceSloTests`, `.venv/bin/python manage.py test devops`, `.venv/bin/python manage.py check`, and `.venv/bin/python manage.py makemigrations --check --dry-run`.

### Task 5: P4 Approval-Gated Runbooks

**Files:**
- Create: `devops/migrations/0024_runbook_template.py`, `templates/devops/runbooks.html`
- Modify: `devops/models.py`, `devops/forms.py`, `devops/services.py`, `devops/views.py`, `devops/api.py`, `devops/urls.py`, `devops/tests.py`, `aiops/views.py`, `aiops/tests.py`, `docs/devops_json_api.md`

- [ ] **Step 1: Add failing runbook tests.** Cover rejection of interpolation, substitutions, multiline templates, viewer and out-of-scope initiators, creation of a pending command plus approval for an authorized initiator, no SSH before approval, Worker execution after approval, and AIOps suggestion without command creation.
- [ ] **Step 2: Run the focused RED tests.** Run `.venv/bin/python manage.py test devops.tests.RunbookTemplateTests aiops.tests.AiopsRunbookSuggestionTests`; expect failure because Runbook models/endpoints are absent.
- [ ] **Step 3: Implement fixed, versioned Runbooks.** Add `RunbookTemplate` with name, version, trigger kind, fixed command template, linked service, approved hosts, enabled flag, required approval, and audit fields. Validate the command has no braces, shell substitutions, newlines, or caller parameters; exclude its body from serializers and lists.
- [ ] **Step 4: Reuse command policy and approval flow.** Add `initiate_runbook(request, runbook, host)` to enforce command permission, enabled state, host scope and template target membership. It creates an existing `CommandExecution`, evaluates policy, creates a command approval, and lets existing approval logic enqueue the Worker. It must never directly call SSH or add a job type.
- [ ] **Step 5: Add protected management and suggestion surfaces.** Add management/list/initiation endpoints and CSRF-protected forms. Security admins manage templates; command operators initiate within scope. Replace static AIOps runbook text with safe identifiers/links only.
- [ ] **Step 6: Verify GREEN.** Run `.venv/bin/python manage.py test devops.tests.RunbookTemplateTests aiops.tests.AiopsRunbookSuggestionTests`, `.venv/bin/python manage.py test devops aiops`, `.venv/bin/python manage.py check`, and `.venv/bin/python manage.py makemigrations --check --dry-run`.

### Task 6: Integration Review

- [ ] **Step 1: Run complete validation.** Run `.venv/bin/python manage.py test`, `.venv/bin/python manage.py check`, `.venv/bin/python manage.py makemigrations --check --dry-run`, `docker compose -f deploy/docker-compose.yml -f deploy/docker-compose.production.yml config`, and `git diff --check`.
- [ ] **Step 2: Review sensitive boundaries.** Confirm diffs do not serialize secrets, raw payloads, LLM responses, command templates, command output, credentials, or host data outside scope; ensure SLO/runbook mutations retain role, module, host-scope, approval, and audit enforcement.
- [ ] **Step 3: Record external validation limits.** Report that live PostgreSQL migration, Nginx traffic, Prometheus evaluation, LLM egress, SSH execution, and production deployment remain intentionally unexercised.
