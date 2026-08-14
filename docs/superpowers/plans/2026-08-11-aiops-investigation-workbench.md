# AIOps Investigation Workbench Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a host-scoped AIOps investigation workbench that persists safe investigation metadata and builds deterministic evidence timelines and root-cause candidates from existing operational records.

**Architecture:** Keep analysis in `aiops` as a read-only layer over DevOps and monitoring data. Store only investigation scope and bounded result summaries; calculate evidence through a service layer with per-source safe failures. Expose permission-filtered JSON endpoints and add an investigation tab to the existing Vue workbench. Remediation remains behind existing runbook and DevOps approval services.

**Tech Stack:** Django 4.2 ORM/migrations, existing session/RBAC helpers, Vue vendored runtime, existing AIOps CSS, Django TestCase.

---

### Task 1: Investigation Model And Migration

**Files:**
- Modify: `aiops/models.py`
- Create: `aiops/migrations/0005_aiopsinvestigation.py`
- Test: `aiops/test_investigations.py`

- [ ] **Step 1: Write failing model contract tests**

  Add `AiopsInvestigationModelTests` covering status choices, bounded title, `window_key`, `risk`, `confidence`, host/service many-to-many relations, and the explicit table name `aiops_investigation`.

- [ ] **Step 2: Run the focused test to verify it fails**

  Run: `.venv/bin/python manage.py test aiops.test_investigations.AiopsInvestigationModelTests`

  Expected: import/model failure because `AiopsInvestigation` does not exist.

- [ ] **Step 3: Implement the minimal model**

  Add status values `open`, `analyzing`, `completed`, `partial`, `failed`; fields `title`, `created_by`, `window_key`, `window_start`, `window_end`, `risk`, `confidence`, `summary`, `root_cause_summary`, `created_at`, `updated_at`; and M2M fields to `RemoteLinux.NewLinux` and `devops.ServiceCatalog`. Do not add raw evidence or payload fields.

- [ ] **Step 4: Generate and inspect the migration**

  Run: `.venv/bin/python manage.py makemigrations aiops`

  Confirm the migration depends on the current `aiops` and `devops` migrations and creates only the new investigation table and relations.

- [ ] **Step 5: Run model tests and migration checks**

  Run: `.venv/bin/python manage.py test aiops.test_investigations.AiopsInvestigationModelTests`

  Expected: all model contract tests pass.

---

### Task 2: Read-Only Evidence And Root-Cause Service

**Files:**
- Create: `aiops/investigations.py`
- Modify: `aiops/models.py` only if service constants need model alignment
- Test: `aiops/test_investigations.py`

- [ ] **Step 1: Write failing deterministic analysis tests**

  Create fixtures for one visible and one hidden host, a service dependency, a critical alert, open incident, recent release, failed CI delivery, exhausted SLO, and metric samples. Assert `build_investigation_result()` returns bounded timeline items, stable ordering, a release-related root-cause candidate, and excludes hidden evidence and raw message/command content.

- [ ] **Step 2: Add partial-source failure test**

  Patch one source query helper to raise an exception and assert the result has `partial=True`, a fixed error code such as `source_unavailable`, and still contains evidence from other sources.

- [ ] **Step 3: Run tests to verify failure**

  Run: `.venv/bin/python manage.py test aiops.test_investigations.InvestigationAnalysisTests`

  Expected: import failure because `build_investigation_result()` is not defined.

- [ ] **Step 4: Implement bounded source collectors**

  Implement private collectors for alert, metric, incident, release/CI, SLO, and topology evidence. Each collector accepts authorized host/service IDs and a fixed time window, returns only allowlisted fields, caps its result count, and converts exceptions to fixed error categories.

- [ ] **Step 5: Implement deterministic root-cause scoring**

  Score only these initial candidates: `recent_release`, `critical_alert_cluster`, `exhausted_slo`, and `upstream_dependency`. Increase confidence only when matching evidence exists in the same bounded window; sort ties by fixed candidate key and cap the result list.

- [ ] **Step 6: Run analysis tests and security assertions**

  Run: `.venv/bin/python manage.py test aiops.test_investigations.InvestigationAnalysisTests`

  Expected: all analysis, ordering, partial failure, scope, and sensitive-field omission tests pass.

---

### Task 3: Permission-Scoped Investigation API

**Files:**
- Modify: `aiops/views.py`
- Modify: `aiops/urls.py`
- Test: `aiops/test_investigations.py`
- Verify: `docs/devops_json_api.md` only if the endpoint is documented there

- [ ] **Step 1: Write failing API tests**

  Add tests for unauthenticated `401`, missing AIOps viewer permission `403`, valid scoped `POST /aiops/api/investigations/` returning `201`, scoped `GET` list/detail, hidden-host rejection, invalid window rejection, and no audit/approval/background-job writes.

- [ ] **Step 2: Implement safe serializers**

  Add serializers that expose only investigation ID, title, status, window, safe scope counts, risk, confidence, summary, root causes, timeline, `partial`, and fixed errors. Never serialize model raw fields beyond this allowlist.

- [ ] **Step 3: Implement scoped create/list/detail views**

  Use the existing session auth and `has_role(request, ROLE_VIEWER, MODULE_...)` helpers. Build host queryset through `visible_hosts_for_request`; resolve posted host IDs against that queryset before creating the record; resolve services through `visible_catalog_services`; return `404/not_found` for inaccessible IDs.

- [ ] **Step 4: Add URL routes**

  Register `api/investigations/` and `api/investigations/<int:id>/` in `aiops/urls.py` with stable route names.

- [ ] **Step 5: Run API tests**

  Run: `.venv/bin/python manage.py test aiops.test_investigations.InvestigationApiTests`

  Expected: all auth, host-scope, safe serialization, read-only, and endpoint tests pass.

---

### Task 4: Investigation Workbench UI

**Files:**
- Modify: `static/js/aiops-vue.js`
- Modify: `static/css/aiops-vue.css`
- Modify: `templates/aiops/dashboard.html` only if the payload needs an endpoint entry
- Test: `aiops/tests.py`, `aiops/test_investigations.py`

- [ ] **Step 1: Write the page contract test**

  Assert the dashboard payload exposes the investigation list/create endpoints only for authorized users and the template contains the investigation tab label and JSON payload.

- [ ] **Step 2: Add Vue state and endpoint actions**

  Add investigation list, selected investigation, loading, error, empty, and partial states. Use existing CSRF handling for POST and render only API-safe fields.

- [ ] **Step 3: Add dense investigation tab**

  Add controls for title, host, service, and time window; render summary metrics, root-cause candidates with confidence, evidence timeline, and fixed partial-error messages. Keep the approved light, dense observability workspace style and responsive layout.

- [ ] **Step 4: Run frontend contract and syntax checks**

  Run: `.venv/bin/python manage.py test aiops.tests.AiopsDashboardTests aiops.test_investigations`

  Run: `node --check static/js/aiops-vue.js`

  Expected: all page contracts pass and JavaScript parses successfully.

---

### Task 5: Integrated Validation And Documentation

**Files:**
- Verify: `docs/superpowers/specs/2026-08-11-aiops-investigation-workbench-design.md`
- Update: `docs/devops_json_api.md` if endpoint documentation is in scope

- [ ] **Step 1: Run migration and system checks**

  Run: `.venv/bin/python manage.py makemigrations --check --dry-run` and `.venv/bin/python manage.py check`

- [ ] **Step 2: Run focused and full AIOps regression**

  Run: `.venv/bin/python manage.py test aiops`

- [ ] **Step 3: Run repository formatting and syntax checks**

  Run: `python3 -m compileall -q aiops` and `git diff --check`.

- [ ] **Step 4: Complete self-check**

  Confirm all API data is host-scoped, no sensitive fields are serialized, no command or external integration executes, and unrelated worktree changes remain untouched.
