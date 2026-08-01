# User-Facing Operations Workflows Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans. Steps use checkbox syntax for tracking.

**Goal:** Deliver incident collaboration, inspection recommendations, deployment orchestration, CI status intake, service CMDB and cloud-cost workflows without weakening existing approval, RBAC, or host-scope rules.

**Architecture:** Add bounded DevOps records and services around existing `AlertEvent`, `Incident`, `RunbookTemplate`, `DeploymentRelease`, `ServiceCatalog`, Worker, and audit utilities. All external information enters through validated adapters; CI and cloud integrations store sanitized status/summary data and do not create remote side effects.

**Tech Stack:** Django 4.2, existing Django session/RBAC, ORM migrations, existing DevOps JSON API, mocked HTTP/SSH integrations.

---

### Task 1: Incident Command Center and Inspection Recommendations (P0)

**Files:** `devops/models.py`, `devops/services.py`, `devops/api.py`, `devops/urls.py`, `monitor/crontab.py`, `devops/test_incident_command_center.py`.

- [ ] Write failing tests for deduplicated incident creation from a critical alert, safe incident assignment/timeline, and a compliance/inspection finding that can only recommend an existing approval-required runbook.
- [ ] Add bounded incident ownership/SLA and inspection-recommendation records; preserve host scope and omit command bodies, credentials, alert payloads, and scan output.
- [ ] Add read/write APIs with alert/operator/security role checks; recommendation initiation must reuse `initiate_runbook()` and never bypass approval.
- [ ] Validate focused tests, DevOps/Monitor suites, and migration consistency.

### Task 2: Deployment Orchestration and CI Status Intake (P1)

**Files:** `devops/models.py`, `devops/services.py`, `devops/api.py`, `devops/urls.py`, `devops/github_integration.py`, `devops/test_delivery_orchestration.py`.

- [ ] Write failing tests for deployment batch state/health gate behavior, signed Jenkins/GitLab status validation, duplicate delivery rejection, and failed-quality-gate deployment blocking.
- [ ] Add release rollout summaries and sanitized CI delivery records; accept only configured provider, repository identity, allowed status and signed payload metadata.
- [ ] Reuse deployment approval and Worker behavior; no CI callback executes deployment or stores build logs, tokens, URLs, or artifact credentials.
- [ ] Validate focused tests, DevOps suite, and migration consistency.

### Task 3: Service CMDB and Cloud Cost Center (P2)

**Files:** `devops/models.py`, `devops/services.py`, `devops/api.py`, `devops/urls.py`, `devops/test_cmdb_cost_center.py`, `docs/devops_json_api.md`.

- [ ] Write failing tests for service ownership/lifecycle serialization, host-scope filtering, deduplicated cloud resource summaries, and cost aggregation without provider credentials.
- [ ] Add service lifecycle/ownership extensions plus cloud resource and daily cost summary records; accept only validated provider/resource/tag/cost inputs.
- [ ] Add read-only APIs protected by service/security module roles; no provider polling or cloud mutation occurs in request handling.
- [ ] Validate focused tests, DevOps suite, and migration consistency.

### Task 4: UI, Documentation and Full Validation

**Files:** `static/js/ops-vue-pages.js`, `templates/vue/page.html`, `README.md`, `docs/devops_json_api.md`.

- [ ] Add permission-aware console entry points and dense views for the new safe API summaries.
- [ ] Document configuration boundaries, approval behavior, and explicitly unsupported automatic external actions.
- [ ] Run `manage.py test`, `manage.py check`, `makemigrations --check --dry-run`, static syntax checks, and `git diff --check`.
