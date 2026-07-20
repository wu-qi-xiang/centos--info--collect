# Operations Reliability Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver the approved P0-P4 reliability improvements without changing existing local SQLite development, custom session authentication, host scope, command policy, or default remote-execution behavior.

**Architecture:** Keep P0/P1 as documentation and opt-in deployment assets. Put AIOps sanitization in a narrow helper before any persistence or LLM request. Add SLO and runbook models in `devops`, then compose them with the existing permissions, approvals, durable `BackgroundJob` Worker, and `CommandExecution` services rather than adding a second execution path.

**Tech Stack:** Django 4.2.16, Python 3.11, PostgreSQL 16 container reference, Nginx, Django TestCase, mocked Prometheus/SSH/LLM.

---

## File Map

- `README.md`, `docs/devops_next_optimizations.md`, `docs/project_layout.md`, `.codex/skills/*`: runtime baseline and current roadmap.
- `deploy/docker-compose.production.yml`, `deploy/nginx/default.conf`, `docs/production_deployment.md`: opt-in PostgreSQL/Nginx reference.
- `aiops/models.py`, `aiops/views.py`, `aiops/management/commands/cleanup_aiops_analyses.py`, `aiops/tests.py`: sanitized analysis persistence and retention.
- `devops/models.py`, `devops/forms.py`, `devops/services.py`, `devops/api.py`, `devops/views.py`, `devops/urls.py`: SLO and runbook workflows.
- `devops/migrations/0022_*.py`, `devops/migrations/0023_*.py`, `devops/tests.py`, `docs/devops_json_api.md`: schema, contracts, tests, and API documentation.

### Task 1: P0 Documentation Baseline

**Files:**
- Modify: `README.md`, `docs/devops_next_optimizations.md`, `docs/project_layout.md`
- Modify: `.codex/skills/centos-info-collect-dev/SKILL.md`, `.codex/skills/centos-feature-dev/references/optimization-roadmap.md`
- Test: repository text search and `.codex/skills/centos-feature-dev/scripts/check_skill_links.py`

- [ ] **Step 1: Add the failing consistency check to the task record**

Run:
```bash
rg -n "Django 2\\.1|Python 3\\.6" README.md docs .codex/skills
```
Expected: active project instructions still contain stale baseline references.

- [ ] **Step 2: Update the documents to the verified runtime baseline**

Replace active run instructions with Python 3.11 and Django 4.2.16. Keep historical Django-generated comments only where they are explicitly labelled as generated legacy metadata. Move delivered notification retry/template, tag scope, independent Worker, and database environment-variable work out of future recommendations; retain Nginx as the remaining deployment recommendation until Task 2 is complete.

- [ ] **Step 3: Verify the documentation update**

Run:
```bash
rg -n "Django 2\\.1|Python 3\\.6" README.md docs .codex/skills
python3 .codex/skills/centos-feature-dev/scripts/check_skill_links.py
```
Expected: no active contradictory instruction; skill-link checker exits 0.

- [ ] **Step 4: Commit the isolated documentation change**

```bash
git add README.md docs/devops_next_optimizations.md docs/project_layout.md .codex/skills
git commit -m "docs: align runtime baseline and roadmap"
```

### Task 2: P1 PostgreSQL And Nginx Reference

**Files:**
- Create: `deploy/docker-compose.production.yml`, `deploy/nginx/default.conf`, `docs/production_deployment.md`
- Modify: `.env.example`, `README.md`, `PyLinux/tests.py`

- [ ] **Step 1: Add failing configuration tests**

Add `ProductionComposeReferenceTests` in `PyLinux/tests.py` that reads the production Compose file and asserts it contains `postgres`, `web`, `worker`, `nginx`, `DB_ENGINE=postgresql`, liveness/readiness health paths, and no literal credential. Add a test that `database_config_from_env` maps the reference PostgreSQL environment to `django.db.backends.postgresql`.

- [ ] **Step 2: Run the focused test before implementation**

Run:
```bash
.venv/bin/python manage.py test PyLinux.tests.ProductionComposeReferenceTests
```
Expected: FAIL because the reference files are absent.

- [ ] **Step 3: Add the opt-in topology**

Create a Compose override with a named PostgreSQL volume, `web` and `worker` services using the current Dockerfile, a shared static/media volume, and Nginx bound to port 80. Use `${POSTGRES_DB}`, `${POSTGRES_USER}`, and `${POSTGRES_PASSWORD}` with no default secret. Set `DB_ENGINE=postgresql`, `DB_HOST=postgres`, and `DJANGO_STATIC_ROOT=/app/staticfiles` only in the production reference. The Nginx config serves `/static/` and `/uploads/`, forwards all other requests to `web:8000`, and sets standard forwarded headers. Do not add a TLS certificate or expose the database port.

- [ ] **Step 4: Document the safe startup and rollback sequence**

Document copying `.env.example` to an untracked production env file, setting non-default secrets, `docker compose -f deploy/docker-compose.yml -f deploy/docker-compose.production.yml run --rm web python manage.py migrate`, `collectstatic --noinput`, `check --deploy`, health endpoint checks, encrypted backup preflight, and rollback by stopping the override stack without touching the SQLite development stack.

- [ ] **Step 5: Verify configuration**

Run:
```bash
.venv/bin/python manage.py test PyLinux.tests.ProductionComposeReferenceTests
docker compose -f deploy/docker-compose.yml -f deploy/docker-compose.production.yml config
```
Expected: focused tests pass and Compose renders without unresolved required secrets when supplied through a temporary non-committed env file.

- [ ] **Step 6: Commit the isolated production-reference change**

```bash
git add deploy .env.example README.md docs/production_deployment.md PyLinux/tests.py
git commit -m "docs: add PostgreSQL and Nginx production reference"
```

### Task 3: P2 AIOps Data Minimization And Retention

**Files:**
- Modify: `PyLinux/settings.py`, `PyLinux/checks.py`, `aiops/models.py`, `aiops/views.py`, `aiops/tests.py`, `.env.example`, `README.md`
- Create: `aiops/migrations/0003_safe_analysis_fields.py`, `aiops/management/commands/cleanup_aiops_analyses.py`

- [ ] **Step 1: Add failing sanitizer and cleanup tests**

Add tests that submit labels/annotations containing URL, token, password, command, and oversized content to `aiops:webhook`; assert that only `alert_name`, `severity`, a bounded `instance`, a bounded summary, and an allowlisted `safe_labels` map are persisted. Assert that the mocked LLM receives no rejected content, no LLM response text is stored, an analysis older than `AIOPS_ANALYSIS_RETENTION_DAYS` is deleted, and a zero retention setting deletes nothing.

- [ ] **Step 2: Run the focused tests before implementation**

Run:
```bash
.venv/bin/python manage.py test aiops.tests.AiopsDataGovernanceTests
```
Expected: FAIL because raw payload and LLM response are still persisted.

- [ ] **Step 3: Implement the sanitized analysis contract**

Add `sanitize_alert(alert)` in `aiops/views.py`. It must accept only scalar `alertname`, `severity`, `instance`/`host`, `summary`/`description`, and the fixed labels `service`, `job`, `environment`; strip control characters and URLs, truncate every field, and return a safe dict. Change `_alert_text`, `_fallback_suggestion`, `_call_llm`, and `_save_alert_analysis` to accept that dict. Add `safe_labels` and `source_summary` fields, stop writing `raw_payload` and `llm_response`, and migrate existing fields to nullable/blank compatibility without exposing their old contents.

- [ ] **Step 4: Add retention settings and cleanup**

Define `AIOPS_ANALYSIS_RETENTION_DAYS = env_int(..., 30)` and reject negative values in settings. Register production checks using the existing retention helper. The command deletes `created_at__lt=cutoff` only when the configured value is positive and emits a count without record contents.

- [ ] **Step 5: Verify data governance**

Run:
```bash
.venv/bin/python manage.py test aiops
.venv/bin/python manage.py check
```
Expected: all AIOps tests and system checks pass without live LLM access.

- [ ] **Step 6: Commit the isolated data-governance change**

```bash
git add PyLinux aiops .env.example README.md
git commit -m "fix: minimize retained AIOps analysis data"
```

### Task 4: P3 Service SLO And Error-Budget Gating

**Files:**
- Modify: `devops/models.py`, `devops/forms.py`, `devops/services.py`, `devops/api.py`, `devops/views.py`, `devops/urls.py`, `devops/tests.py`, `docs/devops_json_api.md`
- Create: `devops/migrations/0023_service_slo.py`, `templates/devops/service_slos.html`

- [ ] **Step 1: Add failing SLO workflow tests**

Add `ServiceSloTests` that create a visible service and configured Prometheus mock. Cover: invalid metric kind/target rejected; viewer cannot mutate; out-of-scope service returns 404; unavailable Prometheus returns `unavailable`; exhausted availability budget causes a release submission to create/reuse a pending deployment approval instead of enqueueing it; a healthy budget preserves the existing release path.

- [ ] **Step 2: Run the focused tests before implementation**

Run:
```bash
.venv/bin/python manage.py test devops.tests.ServiceSloTests
```
Expected: FAIL because no SLO model or release gate exists.

- [ ] **Step 3: Add SLO schema and bounded evaluation service**

Add `ServiceSlo` linked to `ServiceCatalog` with `metric_kind` choices `availability`, `latency`, `error_rate`; `target_percent` decimal; `window_hours`; `enabled`; `last_state`; `last_value`; `last_checked_at`. Add `evaluate_service_slo(slo, prometheus_client=query_prometheus)` that maps choices to fixed backend PromQL templates, accepts a finite numeric result only, calculates remaining budget, and records `healthy`, `exhausted`, or `unavailable`. Never store raw Prometheus payloads or user-authored PromQL.

- [ ] **Step 4: Gate release submission through existing approvals**

Before `enqueue_background_job(execute_deployment_release, ...)`, call `require_service_slo_approval(release, requester)`. It finds enabled SLOs linked through the release app/service mapping, evaluates them, and creates/reuses an `ApprovalRequest.TYPE_DEPLOYMENT` only for exhausted budgets. Unavailable data must not be treated as exhausted. Audit the evaluation and the gate using summary-only text.

- [ ] **Step 5: Add guarded UI/API endpoints and documentation**

Expose a read-only list/detail API and classic page under `/devops/service-slos/`; require security-admin permission for writes and service visibility/host scope for reads. Return safe SLO summary fields only. Document authentication, permission, host scope, result states, and absence of raw Prometheus data in `docs/devops_json_api.md`.

- [ ] **Step 6: Verify SLO behavior**

Run:
```bash
.venv/bin/python manage.py test devops.tests.ServiceSloTests
.venv/bin/python manage.py test devops
.venv/bin/python manage.py check
```
Expected: SLO tests, DevOps regression suite, and checks pass.

- [ ] **Step 7: Commit the isolated SLO change**

```bash
git add devops templates/devops docs/devops_json_api.md
git commit -m "feat: add service SLO release gating"
```

### Task 5: P4 Approval-Gated Runbooks

**Files:**
- Modify: `devops/models.py`, `devops/forms.py`, `devops/services.py`, `devops/api.py`, `devops/views.py`, `devops/urls.py`, `devops/tests.py`, `aiops/views.py`, `aiops/tests.py`, `docs/devops_json_api.md`
- Create: `devops/migrations/0024_runbook_template.py`, `templates/devops/runbooks.html`

- [ ] **Step 1: Add failing authorization and execution tests**

Add `RunbookTemplateTests` covering: a runbook command with forbidden interpolation tokens is invalid; viewer and out-of-scope operator cannot initiate; an authorized initiation creates a pending `CommandExecution` and a command approval; no SSH call occurs before approval; approval uses the existing Worker path; an AIOps dashboard suggestion does not create a command; API/list responses omit full command templates and command output.

- [ ] **Step 2: Run the focused tests before implementation**

Run:
```bash
.venv/bin/python manage.py test devops.tests.RunbookTemplateTests aiops.tests.AiopsRunbookSuggestionTests
```
Expected: FAIL because runbook models and endpoints are absent.

- [ ] **Step 3: Add versioned, non-interpolated runbook templates**

Add `RunbookTemplate` with `name`, `version`, `trigger_kind`, `command_template`, `service`, approved host relations, `enabled`, `requires_approval=True`, creator/timestamps. Validate a closed command form: no braces, shell substitutions, newlines, or user-provided parameters; all target hosts must be the template's explicit managed hosts or hosts visible through its linked service. Add an audit-safe serializer that excludes `command_template`.

- [ ] **Step 4: Reuse existing command and approval services**

Implement `initiate_runbook(request, runbook, host)` to enforce operator command permission, host scope, enabled status, and target membership. It creates `CommandExecution` with the fixed template, evaluates existing command policy, creates `ApprovalRequest.TYPE_COMMAND` when required, and only then uses existing approval decision logic to enqueue the durable Worker. Do not create a new task type or direct SSH path.

- [ ] **Step 5: Add guarded management and initiation surfaces**

Add `/devops/runbooks/` classic management and `/devops/api/runbooks/` safe list endpoint plus a POST initiation endpoint. Management requires security admin; initiation requires command operator and host scope. Add AIOps `runbook_suggestions` as links/identifiers only; it must not call initiation or queue work. Preserve CSRF for every POST.

- [ ] **Step 6: Document and verify controlled execution**

Document permissions, explicit-initiation rule, sensitive-field omission, and approval/Worker behavior. Run:
```bash
.venv/bin/python manage.py test devops.tests.RunbookTemplateTests aiops.tests.AiopsRunbookSuggestionTests
.venv/bin/python manage.py test devops aiops
.venv/bin/python manage.py check
```
Expected: no test contacts SSH or an LLM; all tests and checks pass.

- [ ] **Step 7: Commit the isolated runbook change**

```bash
git add devops aiops templates/devops docs/devops_json_api.md
git commit -m "feat: add approval-gated runbooks"
```

### Task 6: Integration Verification And Completion Review

**Files:**
- Modify: `README.md`, `docs/devops_next_optimizations.md` only if Tasks 1-5 changed user-facing operational behavior not already documented.

- [ ] **Step 1: Validate schema and complete suite**

Run:
```bash
.venv/bin/python manage.py makemigrations --check --dry-run
.venv/bin/python manage.py check
.venv/bin/python manage.py test
```
Expected: no uncommitted migrations, no system-check errors, and the complete suite passes.

- [ ] **Step 2: Review security boundaries**

Inspect diffs and assert: no credentials/payloads/LLM responses appear in serializers or audits; SLO values are bounded; runbooks have no automatic initiation, interpolation, or direct SSH; new host-specific reads and writes use existing scope helpers.

- [ ] **Step 3: Verify deployment artifacts without a live stack**

Run:
```bash
docker compose -f deploy/docker-compose.yml -f deploy/docker-compose.production.yml config
```
Expected: syntax is valid; no external database, SSH host, LLM, or webhook is contacted.

- [ ] **Step 4: Report remaining external validation**

State that live PostgreSQL migration, Nginx traffic, Prometheus evaluation, LLM egress, and SSH execution remain intentionally unexercised unless explicitly requested.
