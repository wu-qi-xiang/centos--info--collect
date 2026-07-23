# On-Call Coverage Inspection Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Provide security administrators a read-only list of service on-call coverage risks before alerts need delivery.

**Architecture:** A pure service helper evaluates the existing service catalog, on-call policies, channels, and rotation members without writing data. A protected classic Django view renders its normalized output in the current on-call management page.

**Tech Stack:** Django 4.2, existing function-based DevOps views, Django `TestCase`.

---

### Task 1: Pure Coverage Evaluator

**Files:**
- Modify: `devops/services.py`
- Create: `devops/test_oncall_coverage.py`

- [ ] Write tests for a service without a policy, a disabled policy, disabled primary or backup channel, an empty rotation roster, an all-disabled roster, non-contiguous positions, and a healthy roster.
- [ ] Run `.venv/bin/python manage.py test devops.test_oncall_coverage --verbosity 1` and confirm the new helper is initially absent or the behavior fails.
- [ ] Add `inspect_oncall_coverage()` returning only `service_id`, `service_name`, `status`, and `issues`; prefetch policies, routes, and rotation members; make no model writes or notification calls.
- [ ] Treat an empty roster as static-primary fallback, and treat a non-empty roster with no enabled member on an enabled channel as a risk.
- [ ] Re-run `.venv/bin/python manage.py test devops.test_oncall_coverage --verbosity 1` and confirm all tests pass.

### Task 2: Protected Management View

**Files:**
- Modify: `devops/views.py`
- Modify: `devops/urls.py`
- Modify: `templates/devops/oncall.html`
- Create: `devops/test_oncall_coverage_management.py`

- [ ] Write tests proving only a `security` administrator can load the coverage page, the risk text is rendered for an incomplete policy, and channel secrets/URLs are absent.
- [ ] Add a GET-only view guarded by `require_devops_role(request, DevOpsRole.ROLE_ADMIN, MODULE_SECURITY)` and pass the service helper output to the template.
- [ ] Add a read-only link and compact table to `templates/devops/oncall.html`; use status badges and issue text, with no forms or outbound actions.
- [ ] Re-run `.venv/bin/python manage.py test devops.test_oncall_coverage_management --verbosity 1` and confirm all tests pass.

### Task 3: Integration And Documentation

**Files:**
- Modify: `README.md`
- Review: `devops/services.py`, `devops/views.py`, `devops/urls.py`, `templates/devops/oncall.html`

- [ ] Document the read-only scope, security-admin requirement, and the fact that coverage is configuration-based rather than a channel-delivery probe.
- [ ] Run `.venv/bin/python manage.py test devops --verbosity 0`.
- [ ] Run `.venv/bin/python manage.py check`, `.venv/bin/python manage.py makemigrations --check --dry-run`, and `git diff --check`.
- [ ] Confirm the change has no migration, cron entry, notification dispatch, policy mutation, secret serialization, or unrelated reversion.
