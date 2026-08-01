# AIOps Feedback And Capacity Simulation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add governed runbook outcome feedback and read-only capacity/cost change simulation to improve AIOps decisions without adding automatic execution.

**Architecture:** Feedback is durable DevOps evidence linked to an approved, completed runbook execution and exposed only through scoped, permission-checked APIs. AIOps aggregates only safe classifications to rank existing runbook identifiers. Capacity simulation is a pure calculation over scoped metric samples and local cloud cost summaries; it persists nothing and calls no external service.

**Tech Stack:** Django 4.2, legacy function views, Django ORM, Django TestCase, existing DevOps roles and host scopes.

---

### Task 1: Runbook Outcome Feedback

**Files:**
- Modify: `devops/models.py`
- Create: `devops/migrations/0040_runbook_outcome_feedback.py`
- Modify: `devops/api.py`, `devops/urls.py`, `docs/devops_json_api.md`
- Create: `devops/test_runbook_outcome_feedback.py`

- [ ] **Step 1: Write failing tests** for a completed execution and approval only accepting an operator's `effective`, `partial`, or `ineffective` classification; reject approved-but-pending records; test viewer denial, hidden out-of-scope approval, audit creation, and no command/output fields in JSON.
- [ ] **Step 2: Run RED check** with `.venv/bin/python manage.py test devops.test_runbook_outcome_feedback` and confirm the endpoint/model is missing.
- [ ] **Step 3: Implement minimal model and API**: link outcome rows to `ApprovalRequest`, validate it is a completed runbook command, enforce command-module operator/viewer roles plus host scope, serialize classifications and timestamps only, and create an audit record.
- [ ] **Step 4: Run GREEN check** with `.venv/bin/python manage.py test devops.test_runbook_outcome_feedback`.

### Task 2: Safe AIOps Runbook Ranking

**Files:**
- Create: `aiops/runbook_effectiveness.py`, `aiops/test_runbook_effectiveness.py`
- Modify: `aiops/views.py`, `static/js/aiops-vue.js`

- [ ] **Step 1: Write failing tests** for deterministic safe ranking using visible-host feedback, empty results, permission denial, and omission of command, output, notes, and approval descriptions.
- [ ] **Step 2: Run RED check** with `.venv/bin/python manage.py test aiops.test_runbook_effectiveness`.
- [ ] **Step 3: Implement minimal aggregation** returning existing runbook identifiers, effectiveness counts/score and safe initiation URL; preserve the existing approval-only initiation behavior.
- [ ] **Step 4: Run GREEN check** with `.venv/bin/python manage.py test aiops.test_runbook_effectiveness` and `node --check static/js/aiops-vue.js`.

### Task 3: Read-only Capacity And Cost Simulation

**Files:**
- Modify: `devops/services.py`, `devops/api.py`, `devops/urls.py`, `docs/devops_json_api.md`
- Create: `devops/test_capacity_cost_simulation.py`

- [ ] **Step 1: Write failing tests** for a scoped operator’s valid simulation, zero/default metric data, invalid/over-bound deltas, missing module roles, and exclusion of non-visible host/cost data.
- [ ] **Step 2: Run RED check** with `.venv/bin/python manage.py test devops.test_capacity_cost_simulation`.
- [ ] **Step 3: Implement a pure bounded calculation** over allowed hosts and local summaries: accept numeric CPU/memory load deltas from -50 to 100 percent and instance delta -10 to 20; return aggregate baseline/projected risk and currency-separated cost deltas without identifiers, secrets, cloud calls, or writes.
- [ ] **Step 4: Run GREEN check** with `.venv/bin/python manage.py test devops.test_capacity_cost_simulation`.

### Task 4: Integration Validation

**Files:**
- Modify only if a failing integration test proves a contract mismatch.

- [ ] **Step 1: Run focused regressions**: `.venv/bin/python manage.py test devops aiops`.
- [ ] **Step 2: Run structural checks**: `.venv/bin/python manage.py check`, `.venv/bin/python manage.py makemigrations --check --dry-run`, `git diff --check`, and `node --check static/js/aiops-vue.js`.
- [ ] **Step 3: Run a temporary local server and authenticated test-client HTTP verification**; stop the process afterward. Do not call SSH, CI, cloud, WeCom, Kubernetes, Prometheus, Alertmanager, or LLM integrations.
