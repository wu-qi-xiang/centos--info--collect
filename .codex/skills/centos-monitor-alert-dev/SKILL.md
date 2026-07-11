---
name: centos-monitor-alert-dev
description: Work on monitoring threshold configuration, scheduled remote metric collection, email alerts, DevOps alert events, alert silences, alert history, and metric samples in centos--info--collect.
---

# Centos Monitor Alert Dev

## When To Use

Use for `monitor` threshold pages, `django-crontab` collection, remote metric samples, DevOps alert events, alert silences/history, and email notification behavior.

## Execution Rule

For development work, the main agent plans and delegates after user confirmation. Subagents perform implementation within explicit file/responsibility ownership. The main agent reviews, integrates, validates, and reports.

## Fast Path

### Change threshold configuration UI

Read:
1. `monitor/models.py`
2. `monitor/forms.py`
3. `monitor/views.py`
4. `templates/monitor/`
5. `monitor/tests.py`

Change:
1. Keep threshold parsing explicit.
2. Preserve CSRF and form error rendering.
3. Add tests for valid, invalid, and update paths.

### Change cron metric or alert behavior

Read:
1. `monitor/crontab.py`
2. `RemoteLinux/collectors.py`
3. `devops/services.py`
4. `devops/models.py`
5. `monitor/tests.py`, `devops/tests.py`

Change:
1. Record metric samples before threshold comparison.
2. Use `record_alert`, `resolve_alert`, and `update_alert_status`.
3. Catch per-host exceptions.
4. Keep email sending limited to new, non-silenced threshold alerts with SMTP settings.
5. Mock SSH, SMTP, and cron in tests.

## Invariants

- `Monitor` stores threshold strings such as `80%`; compare parsed numeric values, not raw strings.
- The cron job currently uses the first `Monitor` row.
- Alert fingerprint/repeat behavior lives in DevOps services.

## Validation

```bash
.venv/bin/python manage.py test monitor
.venv/bin/python manage.py test devops
.venv/bin/python manage.py check
```

Cron manual checks:

```bash
.venv/bin/python manage.py crontab show
.venv/bin/python manage.py crontab add
.venv/bin/python manage.py crontab remove
```

## Shared References

- `../centos-feature-dev/references/change-recipes.md`
- `../centos-feature-dev/references/django-legacy-standards.md`
- `../centos-feature-dev/references/devops-state-models.md`
- `../centos-feature-dev/references/test-matrix.md`
- `../centos-feature-dev/references/test-patterns.md`
- `../centos-feature-dev/references/security-checkpoints.md`
- `../centos-feature-dev/references/review-checklist.md`
