# Operations Platform Next Wave Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make scheduled operations durable and observable, provide WeCom bot notification links, and add bounded security and configuration-governance capabilities.

**Architecture:** Preserve the existing Django/DevOps Worker model. A dedicated scheduler command records bounded run metadata and invokes the current monitor functions under a database lease; the current cron hooks remain as a compatibility fallback until deployment is switched. WeCom bots remain outbound-only and link users to existing authenticated approval/incident pages. Vulnerability and GitOps capabilities begin as read-only findings and never execute package changes or Kubernetes writes.

**Tech Stack:** Django 4.2, existing SQLite/PostgreSQL-compatible ORM, django-crontab compatibility, Docker Compose, GitHub Actions.

---

### Task 1: Durable Scheduler Foundation (P0)

**Files:**
- Create: `devops/scheduler.py`, `devops/management/commands/devops_scheduler.py`, `devops/migrations/0032_scheduledtaskrun.py`
- Modify: `devops/models.py`, `PyLinux/settings.py`, `deploy/docker-compose.yml`, `README.md`
- Test: `devops/test_scheduler.py`

- [ ] Write tests proving a due task is leased once, records a safe success/failure summary, and another invocation cannot run it while leased.
- [ ] Run `manage.py test devops.test_scheduler` and confirm the missing scheduler API causes the expected failure.
- [ ] Add a `ScheduledTaskRun` state record and `run_due_scheduled_tasks()` registry for the existing monitor, Alertmanager, on-call, SLO, and compliance callables. Store no alert body, request payload, command text, or secret.
- [ ] Add `devops_scheduler --once` and a Compose `scheduler` service. Keep `CRONJOBS` as a documented fallback for one release.
- [ ] Re-run scheduler tests and `manage.py check`.

### Task 2: WeCom Bot Notification Entry Points (P0)

**Files:**
- Modify: `devops/services.py`, `devops/models.py`, `devops/tests.py`, `README.md`

- [ ] Write tests proving approval notifications sent to a WeCom bot contain only a signed, expiry-bound local approval link; disabled or non-WeCom channels keep existing payload behavior.
- [ ] Run the focused notification tests and confirm the link helper is initially absent.
- [ ] Add a short-lived HMAC link token derived from `SECRET_KEY`, limited to the approval ID and event version; keep all authorization decisions in the existing logged-in approval endpoint.
- [ ] Render a WeCom-safe markdown link without webhook URLs, secrets, command text, or host credentials; log only the existing safe notification outcome.
- [ ] Re-run focused tests and the DevOps suite.

### Task 3: Platform Metrics and CI Security Gates (P1)

**Files:**
- Modify: `PyLinux/health.py`, `PyLinux/urls.py`, `PyLinux/tests.py`, `.github/workflows/django.yml`, `README.md`

- [ ] Write tests for an authenticated safe metrics response containing only aggregate request-independent queue, scheduler, and integration-health gauges.
- [ ] Add a Prometheus text endpoint protected by the existing DevOps administrator session check, without configuration, IDs, error details, or credentials.
- [ ] Add CI dependency-audit and secret-scan jobs in report-only mode, retaining the existing required Django test gate.
- [ ] Run focused health tests, `manage.py check`, and workflow syntax validation.

### Task 4: Vulnerability and Patch Governance (P2)

**Files:**
- Create: `devops/vulnerability.py`, `devops/test_vulnerability.py`, `devops/migrations/0033_vulnerabilityfinding.py`
- Modify: `devops/models.py`, `devops/services.py`, `devops/api.py`, `devops/urls.py`, `docs/devops_json_api.md`

- [ ] Write tests for validated, secret-free package inventory ingestion, scoped read access, deduplicated findings, and operator rejection of any automatic remote patch execution.
- [ ] Add `VulnerabilityFinding` and a pure matching service that accepts a supplied advisory feed; do not download feeds or persist package command output.
- [ ] Add read-only APIs guarded by the security module and host scope, returning only host, package, advisory ID, severity, status, and timestamps.
- [ ] Run focused tests, DevOps tests, and migration checks.

### Task 5: GitOps Drift Governance (P2)

**Files:**
- Create: `devops/gitops.py`, `devops/test_gitops.py`, `devops/migrations/0034_gitopsdriftfinding.py`
- Modify: `devops/models.py`, `devops/services.py`, `devops/api.py`, `devops/urls.py`, `docs/devops_json_api.md`

- [ ] Write tests for digest-only desired/observed state comparison, K8s module permission enforcement, deduplication, and no Kubernetes mutation.
- [ ] Add a read-only drift-finding service that receives already-fetched desired and observed manifests, validates fixed resource identity, and stores SHA-256 digests plus safe status only.
- [ ] Add scoped read-only API endpoints; remediation remains an existing PrometheusRule revision workflow or an external pull request, never an automatic apply.
- [ ] Run focused tests, DevOps tests, migration checks, and `manage.py check`.

### Task 6: Documentation, Integration, and Rollback Review

**Files:**
- Modify: `README.md`, `docs/devops_json_api.md`, `docs/production_deployment.md`

- [ ] Document environment-free configuration, scheduler deployment and rollback to cron, WeCom bot outbound-only limitations, metrics access, and read-only limits for vulnerability/GitOps findings.
- [ ] Run `manage.py makemigrations --check --dry-run`, relevant suites, the full test suite, `manage.py check`, and `git diff --check`.
- [ ] Confirm no webhook URL, secret, raw payload, command text, kubeconfig, or external live action appears in API responses, audit records, documentation examples, or test output.
