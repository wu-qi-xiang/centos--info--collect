# Host Agent Health Operations Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn Host Agent heartbeat data into a safe offline/stale alert lifecycle and host-scoped operational management view.

**Architecture:** A fixed scheduler callback reads only `HostAgent` heartbeat metadata and calls the existing `record_alert`/`resolve_alert` lifecycle with one fixed `agent_heartbeat` metric. The classic Django fleet page reads only safe Agent metadata for visible hosts; its POST actions call the existing revocation/credential-rotation helpers and retain session, CSRF, security-module role, and host-scope checks.

**Tech Stack:** Django 4.2, existing `RemoteLinux.HostAgent`, DevOps scheduler, `AlertEvent` services, server-rendered Geist templates, Django TestCase.

---

### Task 1: Scheduled Agent Health Alert Lifecycle

**Files:**
- Create: `RemoteLinux/agent_health.py`
- Modify: `PyLinux/settings.py`, `.env.example`, `devops/scheduler.py`, `RemoteLinux/tests.py`, `devops/test_scheduler.py`

- [ ] Write failing tests for Agent with no heartbeat, Agent beyond the default 600-second timeout, stale collection delay, recovery closing the existing alert, and revoked registrations being excluded.
- [ ] Run the focused tests and confirm they fail because no evaluator/scheduler task exists.
- [ ] Implement a fixed, no-network evaluator. It shall inspect only HostAgent state, use metric `agent_heartbeat`, create critical alerts through `record_alert`, and close them through `resolve_alert`.
- [ ] Add validated `AGENT_HEARTBEAT_TIMEOUT_SECONDS=600` and scheduler interval settings; register one fixed `agent_health` scheduler task and include only aggregate counters in its result.
- [ ] Re-run focused Agent and scheduler tests until green.

### Task 2: Host-Scoped Agent Fleet Operations

**Files:**
- Modify: `RemoteLinux/views.py`, `RemoteLinux/tests.py`, `PyLinux/urls.py`
- Create: `templates/linux/agent_fleet.html`

- [ ] Write failing page tests for viewer/unauthenticated denial, visible-host-only rows, state filter, bulk revoke, and one-time credential rotation limited to one visible host at a time.
- [ ] Run focused tests and confirm the fleet route/actions do not exist.
- [ ] Implement a session-authenticated fleet page and POST-only operations. Require security operator role and host scope for every selected ID; reject blank/malformed/bulk credential-rotation input before data changes.
- [ ] Render a compact Geist fleet table with health state, last heartbeat, delay, filter, and stable action controls. Do not render registration secrets except the single rotation response.
- [ ] Register routes and run focused UI/permission tests until green.

### Task 3: Integration Verification

**Files:**
- Modify: `README.md` only if Agent health settings/operations need operator documentation.

- [ ] Run ` .venv/bin/python manage.py test RemoteLinux devops monitor`, ` .venv/bin/python manage.py check`, ` .venv/bin/python manage.py makemigrations --check --dry-run`, and `git diff --check`.
- [ ] Start the local service and inspect the Agent fleet empty state and a populated test fixture where feasible. Do not call SSH, real Agent clients, or notification channels.
- [ ] Review alert messages, scheduler summaries, template context, route access, and audits for host/IP/credential leakage or unauthorized bulk effects.
