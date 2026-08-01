# AIOps Service Impact Workbench Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Provide a read-only, host-scoped service impact summary that connects existing topology, alerts, incidents, SLO state, deployment health, and CI status.

**Architecture:** `aiops/service_impact.py` will aggregate only existing local records for services returned by the established visible service catalog rule. A protected AIOps GET endpoint and conditional dashboard tab expose bounded metadata and counts; neither alters lifecycle state nor executes an operation.

**Tech Stack:** Django ORM, existing service catalog and host-scope helpers, Vue static dashboard, Django TestCase.

---

### Task 1: Safe Service Impact Aggregation

**Files:** Create `aiops/service_impact.py`, `aiops/test_service_impact.py`.

- [ ] Write failing fixtures for a visible service with affected hosts, upstream dependency, exhausted SLO, unhealthy deployment health, failed CI, open alert and incident; assert a deterministic safe summary and that hidden hosts/services and private fields do not appear.
- [ ] Run `.venv/bin/python manage.py test aiops.test_service_impact -v 1` and confirm RED.
- [ ] Implement `build_service_impacts(services, visible_hosts, now=None)`, return at most 32 rows with only service name/id, criticality, host count, affected host count, dependency count, fixed evidence counts, bounded state and fixed recommendation.
- [ ] Run the focused test and confirm GREEN.

### Task 2: Protected AIOps API and Documentation

**Files:** Modify `aiops/views.py`, `aiops/urls.py`, `docs/devops_json_api.md`; create `aiops/test_service_impact_api.py`.

- [ ] Write failing tests for unauthenticated `401`, missing service-view permission `403`, host-scope filtering, invalid window `400`, POST `405`, and no-write behavior.
- [ ] Implement `GET /aiops/api/service-impacts/?window=6h|24h` using session auth, service module viewer role, `visible_hosts_for_request`, and `visible_catalog_services`.
- [ ] Document result fields and omission of host IPs, alert text, incident text, SLO query data, deployment scripts, CI repository/revision and credentials.
- [ ] Run API tests and confirm GREEN.

### Task 3: Conditional Dashboard Workbench

**Files:** Modify `aiops/views.py`, `aiops/tests.py`, `static/js/aiops-vue.js`.

- [ ] Add a failing test proving the endpoint is absent with explicit service-module denial and present for a service viewer.
- [ ] Add a user-triggered Service Impact tab with 6h/24h context, loading/error/empty states, and only safe output fields.
- [ ] Run focused dashboard tests and `node --check static/js/aiops-vue.js`.

### Task 4: Integrated Validation

- [ ] Run `manage.py test aiops` and `manage.py test devops aiops`.
- [ ] Run `manage.py check`, migration dry run, and `git diff --check`.
- [ ] Verify anonymous API `401` JSON and dashboard login redirect with a temporary local server, then stop it.
