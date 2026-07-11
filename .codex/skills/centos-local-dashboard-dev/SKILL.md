---
name: centos-local-dashboard-dev
description: Work on the local Linux dashboard, local system information collection, host search, dashboard charts, and linux app views in centos--info--collect.
---

# Centos Local Dashboard Dev

## When To Use

Use for `/index/`, `/linux/`, `/search/`, local collectors, host search payloads, and local dashboard/chart behavior.

## Execution Rule

For development work, the main agent plans and delegates after user confirmation. Subagents perform implementation within explicit file/responsibility ownership. The main agent reviews, integrates, validates, and reports.

## Fast Path

### Change local collection

Read:
1. `linux/collectors.py`
2. `linux/views.py`
3. `linux/tests.py`

Change:
1. Keep OS command execution/parsing in `linux/collectors.py`.
2. Make parsers tolerant of missing commands, non-CentOS output, and empty results.
3. Mock external IP lookup and system commands in tests.

### Change dashboard/search UI or payload

Read:
1. `linux/views.py`
2. `templates/linux/index.html`, `templates/linux/local.html`, `templates/linux/detail.html`
3. `PyLinux/vue.py` if the page uses Vue payloads
4. related static CSS/JS
5. `linux/tests.py`

Change:
1. Use `visible_hosts_for_request` for host search/list data.
2. Keep pagination/context keys compatible with existing templates.
3. Update server-rendered context and Vue payloads together when both exist.

## Invariants

- Local collection assumes Linux/CentOS-like commands, but tests should not require that runtime.
- Do not hard-code one network interface unless the feature specifically asks for it.
- Do not require a live external IP service for tests.

## Validation

```bash
.venv/bin/python manage.py test linux
.venv/bin/python manage.py check
```

Manual verification on macOS or non-CentOS may not match production Linux output.

## Shared References

- `../centos-feature-dev/references/task-router.md`
- `../centos-feature-dev/references/django-legacy-standards.md`
- `../centos-feature-dev/references/test-matrix.md`
- `../centos-feature-dev/references/test-patterns.md`
- `../centos-feature-dev/references/ui-standards.md`
- `../centos-feature-dev/references/review-checklist.md`
- `../centos-feature-dev/references/file-map.md`
