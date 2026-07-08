# Task Router

Use this table to quickly choose the implementation path. Read only the rows relevant to the request.

| Request type | Read first | Usually edit | Validate |
|---|---|---|---|
| Add or change a DevOps JSON API | `devops/api.py`, `devops/urls.py`, `docs/devops_json_api.md`, `devops/tests.py` | API view, route, serializer/payload, permission checks, docs, tests | `.venv/bin/python manage.py test devops`; `check` |
| Change DevOps command/task/deployment workflow | `devops/views.py`, `devops/services.py`, `devops/models.py`, `devops/tests.py` | forms, services, status transitions, result rows, approvals, audits, notifications | `.venv/bin/python manage.py test devops`; consider affected UI |
| Add a host inventory field | `RemoteLinux/models.py`, `RemoteLinux/forms.py`, `RemoteLinux/views.py`, `templates/linux/`, `RemoteLinux/tests.py` | model, migration, form, create/update/copy/import payloads, templates, tests | `.venv/bin/python manage.py test RemoteLinux`; `check` |
| Fix SSH collection or connection behavior | `RemoteLinux/ssh_utils.py`, `RemoteLinux/collectors.py`, `RemoteLinux/views.py`, `RemoteLinux/tests.py` | SSH helpers, parser, view error handling, tests with mocks | `.venv/bin/python manage.py test RemoteLinux` |
| Change WebSSH | `RemoteLinux/views.py`, `static/xterm/js/ssh.js`, `templates/linux/`, `RemoteLinux/tests.py` | WebSocket loops, Paramiko channel handling, UI JS, cleanup paths | `test RemoteLinux`; manual reachable-host check if requested |
| Change login/register/session auth | `userprofile/views.py`, `userprofile/decorators.py`, `RemoteLinux/models.py`, `RemoteLinux/forms.py`, `templates/login.html`, `templates/register.html` | password verification, session state, templates, tests | `.venv/bin/python manage.py test userprofile`; `check` |
| Change password vault behavior | `password/views.py`, `password/models.py`, `password/forms.py`, `templates/password/`, `password/tests.py` | owner filtering, encryption/reveal, CRUD/search UI, tests | `.venv/bin/python manage.py test password` |
| Change monitoring thresholds or cron alerts | `monitor/crontab.py`, `monitor/views.py`, `monitor/models.py`, `devops/services.py`, `monitor/tests.py`, `devops/tests.py` | threshold parsing, metric samples, alert lifecycle, email behavior | `.venv/bin/python manage.py test monitor devops` |
| Change local dashboard/search/collectors | `linux/views.py`, `linux/collectors.py`, `templates/linux/`, `linux/tests.py` | collectors, context/payload, templates, tests | `.venv/bin/python manage.py test linux`; `check` |
| Change AIOps dashboard/webhook/LLM analysis | `aiops/views.py`, `aiops/models.py`, `templates/aiops/dashboard.html`, `static/js/aiops-vue.js`, `aiops/tests.py` | aggregators, webhook parsing, LLM fallback, payload/UI, tests | `.venv/bin/python manage.py test aiops`; `check` |
| Change Vue-backed UI | `PyLinux/vue.py`, target view payload builder, `templates/vue/page.html`, matching `static/js/*.js`, `static/css/*.css` | payload, JS consumer, template, CSRF, responsive CSS | affected app tests; browser inspect if UI-heavy |
| Change classic template UI | `templates/base.html`, `templates/header.html`, feature template, matching view, static CSS/JS | template context, form errors, CSRF, static style | `check`; affected app tests; browser inspect |
| Change settings/deployment/runtime | `PyLinux/settings.py`, `PyLinux/checks.py`, `deploy/`, `k8s/`, `README.md` | env defaults, production checks, Docker/Compose/K8s, docs | `.venv/bin/python manage.py check`; `docker compose -f deploy/docker-compose.yml config` if Compose changes |
| Add or change model fields | target `models.py`, `forms.py`, `views.py`, templates/API payloads, tests, migrations | model, migration, all serializers/forms/templates/importers/tests | affected app tests; `check` |
| Security hardening | `PyLinux/security.py`, `devops/services.py`, affected views/APIs/templates/tests | auth checks, host scope, secret omission, CSRF, audits | affected app tests plus targeted regression tests |

If the request spans rows, start from the row that owns the durable data or business workflow, then add UI/API rows as secondary paths.

