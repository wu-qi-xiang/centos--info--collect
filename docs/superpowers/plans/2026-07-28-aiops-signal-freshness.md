# AIOps Signal Freshness Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a host-scoped, permission-controlled AIOps assessment for stale or missing CPU, memory, and disk signals.

**Architecture:** A deterministic helper reads only local `MetricSample` rows for caller-supplied hosts. A GET endpoint applies session, module permission, and host-scope checks before returning a bounded metadata-only payload. The existing Vue dashboard renders it only after an explicit user action.

**Tech Stack:** Django 4.2 ORM, existing DevOps roles and host-scope helpers, Vue static dashboard, Django TestCase.

---

### Task 1: Read-only Signal Freshness Aggregation

**Files:**
- Create: `aiops/signal_freshness.py`, `aiops/test_signal_freshness.py`

- [ ] Write failing tests for healthy, partial, stale, absent, one-hour threshold and future-sample handling, deterministic ordering, result limit, and omission of metric values/IPs/timestamps.
- [ ] Run `.venv/bin/python manage.py test aiops.test_signal_freshness -v 1` and confirm the missing module causes RED.
- [ ] Implement `build_signal_freshness(hosts, now=None)` using only the three `MetricSample` categories and a fixed one-hour freshness threshold.
- [ ] Re-run the focused test and confirm GREEN.

### Task 2: Protected API and Documentation

**Files:**
- Modify: `aiops/views.py`, `aiops/urls.py`, `docs/devops_json_api.md`
- Create: `aiops/test_signal_freshness_api.py`

- [ ] Write failing tests for unauthenticated `401`, monitor permission `403`, host-scope filtering, invalid `window` `400`, GET-only `405`, and no-write behavior.
- [ ] Run `.venv/bin/python manage.py test aiops.test_signal_freshness_api -v 1` and confirm RED.
- [ ] Add `GET /aiops/api/signal-freshness/?window=6h|24h`; use it only to select accepted client context, never to alter freshness logic or stored data.
- [ ] Document authentication, monitor permission, host scope, response fields, and omitted fields.
- [ ] Re-run the focused API test and confirm GREEN.

### Task 3: Dashboard Workbench

**Files:**
- Modify: `aiops/views.py`, `aiops/tests.py`, `static/js/aiops-vue.js`

- [ ] Write a dashboard payload test for endpoint exposure only with monitor viewer permission.
- [ ] Run the focused dashboard test and confirm RED.
- [ ] Add a conditional Signal Freshness tab with a six/twenty-four-hour control, explicit GET, and safe result rendering.
- [ ] Run focused tests and `node --check static/js/aiops-vue.js`.

### Task 4: Integration Validation

- [ ] Run `.venv/bin/python manage.py test aiops` and `.venv/bin/python manage.py test devops aiops`.
- [ ] Run `manage.py check`, `makemigrations --check --dry-run`, and `git diff --check`.
- [ ] Start a temporary local server; confirm anonymous API returns `401` JSON and dashboard redirects to login; stop the server.
