# P0 Unified Context And P1 Release Risk Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Finish and verify a shared operational context from alerts through incidents and releases, then expose a safe release-risk gate before deployment execution.

**Architecture:** Reuse the existing `AlertEvent`, `Incident`, `DeploymentRelease`, `DeploymentHealthEvaluation`, `ServiceCatalog`, `ServiceDependency`, and `ServiceSlo` contracts. P0 remains a deterministic, host-scoped read-only aggregation for AIOps and incident detail; P1 consumes the same bounded risk signals in the deployment preview/approval path. No raw command output, credentials, webhook URLs, or unscoped hosts may enter APIs or persisted summaries.

**Tech Stack:** Django 4.2-compatible Python, ORM aggregation, existing DevOps JSON API, Vue/static AIOps workbench, unittest mocks.

---

### Task 1: P0 Operational Context Audit And Completion

**Files:**
- Modify only if needed: `aiops/service_impact.py`, `aiops/service_workbench.py`, `devops/services.py`
- Test: `aiops/test_service_impact.py`, `aiops/test_service_impact_api.py`, `aiops/test_service_workbench.py`, `devops/test_incident_command_center.py`

- [ ] Run the existing P0 tests and inspect failures.
- [ ] Add a failing regression test for the missing contract: a visible service response must include bounded counts for active alerts, open incidents, unhealthy deployments, failed CI deliveries, exhausted SLOs, and a deterministic recommendation while excluding a hidden host's evidence.
- [ ] Implement the smallest missing aggregation/correlation change, reusing existing helpers and host-scope checks.
- [ ] Run the focused AIOps/DevOps tests and confirm all P0 cases pass.

### Task 2: P1 Release Risk Preview And Approval Gate

**Files:**
- Modify only if needed: `devops/services.py`, `devops/views.py`, `devops/api.py`, `devops/urls.py`
- Test: `devops/test_release_impact.py`, `devops/test_deployment_health_guard.py`, `devops/tests.py`

- [ ] Run the existing deployment risk, release impact, SLO gate, and health-guard tests.
- [ ] Add a failing test that a release preview remains read-only, is host-scoped, returns a stable risk level/reasons, and blocks an approval when a critical active signal or exhausted SLO is present.
- [ ] Implement only the missing gate wiring; preserve explicit approval, maintenance-window, CI-quality, and rollback checks.
- [ ] Run focused DevOps tests and verify safe JSON fields only.

### Task 3: AIOps/DevOps UI Contract Review

**Files:**
- Modify only if needed: `static/js/aiops-vue.js`, `static/css/aiops-vue.css`, `templates/aiops/dashboard.html`, `templates/devops/*.html`
- Test: `aiops/tests.py`, relevant DevOps view tests

- [ ] Confirm the service-impact and release-risk data are reachable from the existing workbench without introducing a second execution path.
- [ ] Add only labels, empty/error states, or links required to make the P0/P1 workflow discoverable; keep the repository's light dense Dashboard visual standard.
- [ ] Run JavaScript syntax checks and focused page-contract tests.

### Task 4: Integrated Validation And Documentation

**Files:**
- Verify: `docs/devops_json_api.md`
- Update only if endpoint behavior changed: `docs/devops_json_api.md`

- [ ] Run `.venv/bin/python manage.py test aiops devops` and `.venv/bin/python manage.py check`.
- [ ] Run `node --check static/js/aiops-vue.js` and `git diff --check`.
- [ ] Verify API authorization, host scope, sensitive-field omissions, read-only preview behavior, and no external LLM/network requirement in tests.

