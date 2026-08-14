# Host Agent, Status Page, and WeCom ChatOps Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver outbound Host Agent heartbeats, a publicly safe service status page, and restricted signed WeCom ChatOps.

**Architecture:** `RemoteLinux` owns the durable Agent registration and heartbeat boundary. `devops` owns public service-state aggregation and signed ChatOps authorization, reusing service, alert, incident, approval, audit, and module-permission workflows. Classic Django templates use the existing Geist CSS; no frontend build dependency or remote integration is required for automated tests.

**Tech Stack:** Python 3.11, Django 4.2, Django TestCase/client, existing `PyLinux.crypto` and DevOps services, local static CSS.

---

### Task 1: Host Agent Registration and Heartbeats

**Files:**
- Modify: `RemoteLinux/models.py`, `RemoteLinux/views.py`, `PyLinux/urls.py`, `RemoteLinux/tests.py`
- Create: `RemoteLinux/agent.py`, `RemoteLinux/migrations/00xx_host_agent.py`, `templates/linux/agent_management.html`

- [ ] Write failing tests for an authorized registration response that exposes an opaque credential once, an accepted bounded heartbeat, rejection of invalid/revoked credentials and unsafe payload fields, and host-scope denial.
- [ ] Run ` .venv/bin/python manage.py test RemoteLinux` and confirm the new tests fail because the model/endpoints do not exist.
- [ ] Add `HostAgent` with a `NewLinux` relationship, password-hashed credential, revocation state, safe summary fields, and indexed heartbeat timestamp; generate and review its migration.
- [ ] Add focused registration, revocation, status, and heartbeat helpers. Validate bearer credentials in constant time through Django password hashing and permit only `agent_version`, `collection_delay_seconds`, and bounded summary keys/values.
- [ ] Add authenticated host-scoped management routes and the unauthenticated heartbeat route. Return only safe metadata, audit create/revoke operations, and retain a compact Geist management page.
- [ ] Run the focused tests again and confirm they pass.

### Task 2: Public Sanitized Service Status

**Files:**
- Modify: `PyLinux/urls.py`, `devops/views.py`, `devops/tests.py`, `static/css/geist-classic-pages.css`
- Create: `devops/public_status.py`, `templates/devops/public_status.html`

- [ ] Write failing tests proving anonymous users receive derived service status, current maintenance, and generic incidents, while host data, alert/incident text, owners, URLs, and versions are absent.
- [ ] Run ` .venv/bin/python manage.py test devops` and confirm the new tests fail because the route/aggregator do not exist.
- [ ] Implement a dedicated derived public-status serializer with fixed allowlists and deterministic aggregate state. It must never serialize model dictionaries or user-authored alert/incident body text.
- [ ] Add `/status/` and a dense responsive Geist template with aggregate state, service rows, maintenance notices, and sanitized timeline.
- [ ] Run focused DevOps tests and inspect desktop/mobile layout with data and empty-state fixtures.

### Task 3: Signed WeCom ChatOps

**Files:**
- Modify: `PyLinux/settings.py`, `.env.example`, `README.md`, `devops/models.py`, `devops/api.py`, `devops/urls.py`, `devops/tests.py`, `docs/devops_json_api.md`
- Create: `devops/chatops.py`, `devops/migrations/00yy_chatops_identity.py`

- [ ] Write failing tests for invalid signatures, unknown/disabled identity, denied permission, safe status and pending-approval results, alert acknowledgement, no raw-message audit leakage, and denial of command/deploy/rollback/runbook actions.
- [ ] Run ` .venv/bin/python manage.py test devops` and confirm the tests fail because ChatOps does not exist.
- [ ] Add `ChatOpsIdentity` mapping a unique WeCom user ID to a local user with enable/revoke control; generate and review its migration.
- [ ] Add strict HMAC verification over raw request bytes before JSON parsing; impose an allowlist and per-action required DevOps module permissions. Reuse alert lifecycle helpers and existing authenticated page URLs; do not create an execution path.
- [ ] Add the environment configuration and factual API/operator documentation without values or live callback URLs.
- [ ] Run focused DevOps tests and confirm pass.

### Task 4: Integration and Completion

**Files:**
- Modify only files needed to reconcile the task outputs and document behavior.

- [ ] Run ` .venv/bin/python manage.py makemigrations --check --dry-run`, ` .venv/bin/python manage.py check`, ` .venv/bin/python manage.py test RemoteLinux devops monitor`, and `git diff --check`.
- [ ] Inspect routes and all new JSON/template output for sensitive fields, CSRF posture, role/host scope, and duplicate migration dependencies.
- [ ] Start the local server and verify the public status page in desktop and narrow viewport. Do not send live WeCom callbacks or Agent heartbeats.
- [ ] Review the integrated diff for scope, rollback safety, and documentation accuracy; then commit only after all validations pass.
