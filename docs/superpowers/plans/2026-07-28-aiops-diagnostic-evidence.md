# AIOps Diagnostic Evidence Pack Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give operators one safe, host-scoped, read-only evidence pack for incident investigation without issuing commands, collecting raw logs, or calling external systems.

**Architecture:** `aiops/evidence_pack.py` performs deterministic ORM aggregation over existing DevOps records. The AIOps GET endpoint authorizes the selected host, filters each evidence category by its own module-viewer permission, and returns only a bounded, metadata-only contract; the dashboard consumes the same result for a compact diagnostic tab.

**Tech Stack:** Django 4.2, existing custom session authentication, DevOps role/module permission and host-scope helpers, Vue static payload rendering, Django TestCase.

---

### Task 1: Evidence-Pack Aggregation

**Files:**
- Create: `aiops/evidence_pack.py`, `aiops/test_evidence_pack.py`

- [ ] **Step 1: Write failing tests** for a 24-hour host pack containing safe alert, metric state, incident, failed-command, deployment-health and CI evidence; test old records, different-host data, raw message/command/output exclusions, empty host list, and deterministic limits.
- [ ] **Step 2: Run RED check** with `.venv/bin/python manage.py test aiops.test_evidence_pack` and confirm the missing module/function failure.
- [ ] **Step 3: Implement minimal read-only aggregation** returning fixed `kind`, `summary`, `observed_at`, `severity`/`status` metadata and route URLs, with no model/migration, write, network, SSH, LLM, raw metric or raw text path.
- [ ] **Step 4: Run GREEN check** with `.venv/bin/python manage.py test aiops.test_evidence_pack`.

### Task 2: Authorized API And Documentation

**Files:**
- Modify: `aiops/views.py`, `aiops/urls.py`, `docs/devops_json_api.md`
- Create: `aiops/test_diagnostic_evidence_api.py`

- [ ] **Step 1: Write failing tests** for session denial, invalid host/window, visible-host success, hidden-host denial, module-specific evidence omission and no persistence.
- [ ] **Step 2: Run RED check** with `.venv/bin/python manage.py test aiops.test_diagnostic_evidence_api`.
- [ ] **Step 3: Implement the GET endpoint** `/aiops/api/diagnostic-evidence/`, resolve the host only through `visible_hosts_for_request`, require a viewer role in at least one evidence-owning module, and omit categories without their viewer permission.
- [ ] **Step 4: Document API contract** including the exact safe fields, permission matrix, host-scope behavior and external-call prohibition.
- [ ] **Step 5: Run GREEN check** with `.venv/bin/python manage.py test aiops.test_diagnostic_evidence_api`.

### Task 3: AIOps Workbench Entry

**Files:**
- Modify: `aiops/views.py`, `static/js/aiops-vue.js`, `aiops/tests.py`

- [ ] **Step 1: Write failing payload/UI-contract test** for safe visible host choices and an endpoint URL, while ensuring the dashboard does not embed command/log/alert raw data.
- [ ] **Step 2: Run RED check** with `.venv/bin/python manage.py test aiops.tests`.
- [ ] **Step 3: Add minimal dashboard data and diagnostic tab** with a host selector and explicit fetch to the protected GET API; render safe evidence rows and avoid automatic refresh or mutation.
- [ ] **Step 4: Run GREEN check** with `.venv/bin/python manage.py test aiops.tests` and `node --check static/js/aiops-vue.js`.

### Task 4: Integration Validation

**Files:**
- Modify only if an integration failure proves a contract mismatch.

- [ ] **Step 1: Run focused suites**: `.venv/bin/python manage.py test aiops.test_evidence_pack aiops.test_diagnostic_evidence_api aiops`.
- [ ] **Step 2: Run shared regression**: `.venv/bin/python manage.py test devops aiops`.
- [ ] **Step 3: Run structural checks**: `.venv/bin/python manage.py check`, `.venv/bin/python manage.py makemigrations --check --dry-run`, `git diff --check`, `node --check static/js/aiops-vue.js`.
- [ ] **Step 4: Start a temporary local server, verify login protection and stop it**; do not call SSH, CI, cloud, Kubernetes, Prometheus, Alertmanager, webhook, or LLM services.
