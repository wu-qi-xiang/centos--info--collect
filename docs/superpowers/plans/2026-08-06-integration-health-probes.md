# Integration Health Probes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Periodically record safe reachability outcomes for configured Prometheus, Alertmanager, and enterprise WeCom notification integrations.

**Architecture:** `monitor.services` owns fixed endpoint and transport probes without exposing remote response bodies. `devops.services` persists fixed categories into `IntegrationHealthEvent`, and the existing scheduler runs one bounded job. Existing health serializers expose only safe metadata.

**Tech Stack:** Django 4.2, existing urllib/curl monitor helpers, Django ORM, existing `ScheduledTaskRun` scheduler, unittest mocks.

---

### Task 1: Probe service and safety tests

**Files:**
- Modify: `monitor/services.py`
- Modify: `monitor/tests.py`
- Do not modify: notification POST delivery functions or alert lifecycle logic

- [ ] Add failing tests for configured Prometheus and Alertmanager probes. Assert each result only exposes `source_id`, `source_name`, `ok`, and a fixed category.
- [ ] Add a failing WeCom transport test. Mock `urlrequest.urlopen`, assert the request method is `HEAD`, and treat an `HTTPError(405)` as reachable transport.
- [ ] Implement `probe_monitor_integrations()` using `test_prometheus_connection()` and `test_alertmanager_connection()` for enabled configurations. Implement `probe_wecom_notification_transport()` with a HEAD-only request and no response-body read.
- [ ] Map only fixed categories: `ok`, `timeout`, `http_error`, `request_error`, and `configuration`.
- [ ] Run `.venv/bin/python manage.py test monitor` and confirm it passes.

### Task 2: Event persistence and scheduler

**Files:**
- Modify: `devops/services.py`
- Modify: `devops/scheduler.py`
- Modify: `PyLinux/settings.py`
- Modify: `.env.example`
- Modify: `devops/tests.py`, `devops/test_scheduler.py`
- Do not modify: existing notification sends, SSH, Kubernetes, or alert state transitions

- [ ] Add a failing test for `probe_configured_integrations()` which mocks monitor results and asserts only fixed health events are written.
- [ ] Implement `probe_configured_integrations()`; map Prometheus, Alertmanager, and WeCom to their existing integration event types and append one event per configured source.
- [ ] Return bounded `checked`, `success`, `failed`, and `skipped` counters to the scheduler.
- [ ] Register fixed `integration_health` task with `DEVOPS_SCHEDULER_INTEGRATION_HEALTH_INTERVAL_SECONDS`, default `300`, and validate the value is positive.
- [ ] Run `.venv/bin/python manage.py test devops.test_scheduler devops.tests.IntegrationHealthTests` and confirm it passes.

### Task 3: Health API projection and documentation

**Files:**
- Modify: `devops/api.py`
- Modify: `docs/devops_json_api.md`
- Modify: `devops/tests.py`

- [ ] Add a failing administrator API test for monitor notification health. Assert `monitor_notifications` is returned and webhook/URL text is absent.
- [ ] Add a safe `monitor_notifications` section to the existing integration health endpoint, using `AlertNotificationConfig.objects.only('id', 'name', 'enabled', 'provider')` and existing health summaries.
- [ ] Document the permission, interval, fixed failure categories, and that HEAD validates transport only while manual test messages validate delivery.
- [ ] Run `.venv/bin/python manage.py test devops.tests.IntegrationHealthTests` and confirm it passes.

### Task 4: Full verification

**Files:** no additional production files

- [ ] Run `.venv/bin/python manage.py test monitor devops`.
- [ ] Run `.venv/bin/python manage.py check`.
- [ ] Run `.venv/bin/python manage.py makemigrations --check --dry-run`.
- [ ] Run `git diff --check`.
