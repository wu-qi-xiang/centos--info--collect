# Operations Governance Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add deployment-ready CI, periodic SLO history, scoped capacity forecasts, a local-only recovery drill command, and accurate roadmap documentation.

**Architecture:** Extend existing Django services, `django-crontab`, `MetricSample`, notification utilities, and backup preflight logic. New persisted data is limited to safe SLO evaluation history; capacity forecasts are computed from existing samples, and restore drills invoke no network or production service.

**Tech Stack:** Python 3.11, Django 4.2.16, Django TestCase, SQLite, Docker Compose configuration rendering, GitHub Actions.

---

## File Map

- `.github/workflows/django.yml`, `PyLinux/tests.py`: offline production configuration and Compose CI guard.
- `devops/models.py`, `devops/migrations/0032_service_slo_evaluation.py`, `devops/services.py`, `monitor/crontab.py`, `devops/tests.py`, `monitor/tests.py`: periodic safe SLO history and transition notification.
- `devops/services.py`, `devops/api.py`, `devops/urls.py`, `devops/views.py`, `templates/devops/metrics.html`, `devops/tests.py`, `docs/devops_json_api.md`: host-scoped capacity forecasting.
- `devops/management/commands/restore_runtime.py`, `devops/tests.py`, `docs/runtime_recovery.md`: local archive recovery drill wrapper and documentation.
- `docs/devops_next_optimizations.md`, `README.md`: completed-state and operator documentation.

### Task 1: Deployment-Ready CI Guard

**Files:**
- Modify: `.github/workflows/django.yml`, `PyLinux/tests.py`

- [ ] **Step 1: Write failing production guard tests.** Add `ProductionCiGuardTests` in `PyLinux/tests.py` that read the workflow and assert it installs `deploy/requirements-prod.txt`, provides non-secret production values, runs `manage.py check --deploy`, `collectstatic --noinput`, and renders both Compose files without calling `up`, `build`, or a network probe.
- [ ] **Step 2: Run the RED test.** Run `.venv/bin/python manage.py test PyLinux.tests.ProductionCiGuardTests`. Expected: failure because the workflow only runs the base Django test suite.
- [ ] **Step 3: Implement the workflow guard.** In `.github/workflows/django.yml`, install production requirements after base requirements; set only placeholder `DJANGO_SECRET_KEY`, `DATA_ENCRYPTION_KEY`, `DJANGO_ALLOWED_HOSTS`, `DB_*`, and `DJANGO_ENV=production` values in the guard step; run `python manage.py check --deploy`, `python manage.py collectstatic --noinput`, and `docker compose -f deploy/docker-compose.yml -f deploy/docker-compose.production.yml config --quiet`. Do not echo values or start containers.
- [ ] **Step 4: Run the GREEN tests.** Run `.venv/bin/python manage.py test PyLinux.tests.ProductionCiGuardTests` and `.venv/bin/python manage.py check`. Expected: pass without Docker daemon, database connection, or external network access.

### Task 2: Periodic SLO Evaluation History

**Files:**
- Create: `devops/migrations/0032_service_slo_evaluation.py`
- Modify: `devops/models.py`, `devops/services.py`, `monitor/crontab.py`, `devops/tests.py`, `monitor/tests.py`

- [ ] **Step 1: Write failing SLO scheduler tests.** Add tests proving `evaluate_enabled_service_slos()` evaluates every enabled SLO, records only `slo`, `state`, `summary`, and `evaluated_at`, does not persist query or raw response data, and calls `send_notifications(NotificationLog.EVENT_ALERT, ...)` exactly once when the preceding state is not `exhausted` and the new state is `exhausted`.
- [ ] **Step 2: Run the RED tests.** Run `.venv/bin/python manage.py test devops.tests.ServiceSloHistoryTests monitor.tests.SloScheduleTests`. Expected: failure because no history model or scheduler function exists.
- [ ] **Step 3: Add the safe history contract.** Add `ServiceSloEvaluation` with `slo=ForeignKey(ServiceSlo)`, choice-constrained `state`, `summary=CharField(max_length=200)`, and `evaluated_at`; add an index on `(slo, -evaluated_at)`. Add `evaluate_enabled_service_slos(now=None)` which invokes the existing evaluator per SLO under per-SLO exception isolation, writes one history record, and sends a bounded alert notification only on an exhausted transition. Notification errors must be caught so history remains durable.
- [ ] **Step 4: Schedule it.** Add `evaluate_service_slos_periodically()` in `monitor/crontab.py`, write only a bounded aggregate audit detail, and register it in `PyLinux/settings.py` at a non-overlapping fixed interval. It must not contact SSH or create a background job.
- [ ] **Step 5: Run the GREEN tests.** Run `.venv/bin/python manage.py test devops.tests.ServiceSloHistoryTests monitor.tests.SloScheduleTests`, then `.venv/bin/python manage.py test devops monitor` and `.venv/bin/python manage.py makemigrations --check --dry-run`.

### Task 3: Host-Scoped Capacity Forecast

**Files:**
- Modify: `devops/services.py`, `devops/api.py`, `devops/urls.py`, `devops/views.py`, `templates/devops/metrics.html`, `devops/tests.py`, `docs/devops_json_api.md`

- [ ] **Step 1: Write failing forecast tests.** Add tests for a rising sample series that reaches 100 percent, a stable/decreasing series, sparse or duplicate-timestamp input, and an out-of-scope host. Assert output contains only host ID/name, metric, state, sample count, and bounded days-to-threshold; it must not contain sample values, timestamps, source URLs, labels, or credentials.
- [ ] **Step 2: Run the RED test.** Run `.venv/bin/python manage.py test devops.tests.CapacityForecastTests`. Expected: failure because no forecast helper or endpoint exists.
- [ ] **Step 3: Add the forecasting service.** Add `forecast_host_capacity(hosts, now=None)` in `devops/services.py`. Use a bounded recent window of existing `MetricSample` rows, collapse duplicate timestamps, calculate a least-squares slope in percentage points per day, and return `risk`, `stable`, or `insufficient_data`. Return a positive integer `days_to_threshold` only when a rising finite slope reaches 100 percent; cap displayed results to a fixed host/metric count.
- [ ] **Step 4: Add protected API and page context.** Add `GET /devops/api/capacity-forecast/`, requiring the existing metrics read permission and `visible_hosts_for_request`. Add the same safe summary to the metrics-history page context and render a compact table without raw samples. Document method, permission, host scope, result states, limits, and omitted fields in `docs/devops_json_api.md`.
- [ ] **Step 5: Run the GREEN tests.** Run `.venv/bin/python manage.py test devops.tests.CapacityForecastTests`, `.venv/bin/python manage.py test devops`, and `.venv/bin/python manage.py check`.

### Task 4: Local-Only Restore Drill Command

**Files:**
- Create: `devops/management/commands/restore_runtime.py`
- Modify: `devops/tests.py`, `docs/runtime_recovery.md`

- [ ] **Step 1: Write failing command tests.** Add tests that build a temporary encrypted SQLite archive with `scripts/backup_local.py`, invoke `call_command('restore_runtime', '--archive=...', '--target-dir=...')`, and assert restored database integrity and uploads. Add rejection tests for a non-empty target, symlink target, parent traversal, malformed archive, and no S3 command invocation.
- [ ] **Step 2: Run the RED tests.** Run `.venv/bin/python manage.py test devops.tests.RestoreRuntimeCommandTests`. Expected: failure because `restore_runtime` is absent.
- [ ] **Step 3: Implement the thin management-command wrapper.** Import `scripts/restore_preflight.py` through an explicit repository-root path, parse only required `--archive` and `--target-dir`, call its validated preflight function, and translate controlled `ValueError`, archive, crypto, and SQLite errors into `CommandError` without exposing file contents or encryption material. Do not add upload, URL, database-connection, SSH, SMTP, webhook, deletion, overwrite, or force options.
- [ ] **Step 4: Document the boundary.** In `docs/runtime_recovery.md`, document the exact command, required empty isolated target directory, preserved output for human inspection, and the fact that it never downloads from S3 or accesses production services.
- [ ] **Step 5: Run the GREEN tests.** Run `.venv/bin/python manage.py test devops.tests.RestoreRuntimeCommandTests`, `.venv/bin/python manage.py test devops`, and `.venv/bin/python manage.py check`.

### Task 5: Documentation Reconciliation

**Files:**
- Modify: `docs/devops_next_optimizations.md`, `README.md`

- [ ] **Step 1: Write failing documentation assertions.** Add `DocumentationStatusTests` in `PyLinux/tests.py` that assert the roadmap no longer lists shared navigation permissions, Nginx production reference, or AIOps LLM key encryption as pending, and that the README names periodic SLO evaluation, capacity forecast, and local restore drill boundaries.
- [ ] **Step 2: Run the RED test.** Run `.venv/bin/python manage.py test PyLinux.tests.DocumentationStatusTests`. Expected: failure because the roadmap is stale and the README omits new behavior.
- [ ] **Step 3: Update only affected documentation.** Move completed work to the completed section, add the new operator-facing capabilities, and retain explicit local-only restore constraints. Do not alter unrelated setup or historical claims.
- [ ] **Step 4: Run the GREEN tests.** Run `.venv/bin/python manage.py test PyLinux.tests.DocumentationStatusTests` and `.venv/bin/python manage.py check`.

### Task 6: Integration Validation And Review

- [ ] **Step 1: Run full validation.** Run `.venv/bin/python manage.py test`, `.venv/bin/python manage.py check`, `.venv/bin/python manage.py makemigrations --check --dry-run`, `docker compose -f deploy/docker-compose.yml -f deploy/docker-compose.production.yml config --quiet`, and `git diff --check`.
- [ ] **Step 2: Review sensitive boundaries.** Verify no diff exposes credentials, webhook URLs, PromQL, monitoring raw responses, archive content, or decrypted data; verify capacity API follows metrics permission and host scope.
- [ ] **Step 3: Record external limits.** State that no Docker daemon, production database, S3, Prometheus, SSH, SMTP, webhook, or live CI run was exercised locally.
