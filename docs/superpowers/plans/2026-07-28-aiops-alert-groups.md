# AIOps Alert Group Workbench Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an explainable, host-scoped view of related active alerts without changing existing alert fingerprinting, silence, notification or incident state transitions.

**Architecture:** A new AIOps aggregation groups visible active alerts by public `metric + level`, derives counts and related-incident status from existing rows, and emits a bounded metadata-only result. A protected GET endpoint and dashboard tab render this analysis; neither writes to `AlertEvent` nor invokes any external integration.

**Tech Stack:** Django 4.2 ORM, existing DevOps alert permission/host-scope helpers, Vue static dashboard, Django TestCase.

---

### Task 1: Deterministic Alert Group Aggregation

**Files:**
- Create: `aiops/alert_groups.py`, `aiops/test_alert_groups.py`

- [ ] **Step 1: Write failing tests** for grouping visible open/processing/silenced alerts by metric and level, counts for hosts/repeats/silences, incident-state inclusion, exclusion of resolved/out-of-window/hidden hosts, deterministic sorting and raw-message omission.
- [ ] **Step 2: Run RED check** with `.venv/bin/python manage.py test aiops.test_alert_groups`.
- [ ] **Step 3: Implement minimal read-only aggregation** returning group key, metric, level, counts, bounded incident state and fixed recommendation; do not create incident, change alert state, send notification or make an external call.
- [ ] **Step 4: Run GREEN check** with `.venv/bin/python manage.py test aiops.test_alert_groups`.

### Task 2: Protected API And Documentation

**Files:**
- Modify: `aiops/views.py`, `aiops/urls.py`, `docs/devops_json_api.md`
- Create: `aiops/test_alert_groups_api.py`

- [ ] **Step 1: Write failing tests** for unauthenticated, missing alert permission, visible-host success, hidden-host exclusion, invalid window and no-write behavior.
- [ ] **Step 2: Run RED check** with `.venv/bin/python manage.py test aiops.test_alert_groups_api`.
- [ ] **Step 3: Implement `GET /aiops/api/alert-groups/?window=6h|24h`** using the existing session, `visible_hosts_for_request` and alert viewer role; return existing JSON error shape and bounded safe output.
- [ ] **Step 4: Document permission, scope, fields and no-side-effect guarantee.**
- [ ] **Step 5: Run GREEN check** with `.venv/bin/python manage.py test aiops.test_alert_groups_api`.

### Task 3: Dashboard Workbench Tab

**Files:**
- Modify: `aiops/views.py`, `static/js/aiops-vue.js`, `aiops/tests.py`

- [ ] **Step 1: Write failing dashboard payload test** for the alert-groups endpoint exposure and permission-limited empty data.
- [ ] **Step 2: Run RED check** with the focused `aiops.tests` test.
- [ ] **Step 3: Add a compact tab** that fetches a selected time window only on user request and renders group counts plus safe recommendations; no automatic polling or mutation action.
- [ ] **Step 4: Run GREEN check** with focused tests and `node --check static/js/aiops-vue.js`.

### Task 4: Integration Validation

- [ ] **Step 1: Run focused tests** for the new aggregation/API and `aiops`.
- [ ] **Step 2: Run `.venv/bin/python manage.py test devops aiops`.**
- [ ] **Step 3: Run `manage.py check`, `makemigrations --check --dry-run`, `git diff --check` and frontend syntax check.**
- [ ] **Step 4: Verify temporary local HTTP login protection and stop the server.**
