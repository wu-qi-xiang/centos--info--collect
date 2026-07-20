# Test Matrix

Use the narrowest meaningful validation first. Broaden when shared behavior changes.

## Base Commands

```bash
.venv/bin/python manage.py check
.venv/bin/python manage.py test
```

The dependency set targets Python 3.11 and Django 4.2.16. If the local environment cannot run that baseline, report the exact failure and do not claim verification succeeded.

## Focused Tests

| Change area | Command |
|---|---|
| Auth/login/register/session | `.venv/bin/python manage.py test userprofile` |
| Host inventory, SSH helpers, import, WebSSH | `.venv/bin/python manage.py test RemoteLinux` |
| Local dashboard, search, local collectors | `.venv/bin/python manage.py test linux` |
| Monitoring thresholds, cron collection, alert generation | `.venv/bin/python manage.py test monitor` |
| Password vault | `.venv/bin/python manage.py test password` |
| DevOps workflows, APIs, roles, host scope, approvals, notifications | `.venv/bin/python manage.py test devops` |
| AIOps dashboard, webhook, LLM fallback | `.venv/bin/python manage.py test aiops` |
| Settings/runtime checks | `.venv/bin/python manage.py check` |

## Combined Validation

- Monitoring alert lifecycle: `test monitor devops`.
- Host scope affecting dashboard/search/devops: `test RemoteLinux linux devops`.
- Auth changes affecting all protected pages: `test userprofile RemoteLinux linux monitor password devops aiops`.
- UI payload changes: affected app tests plus `check`; browser inspect when layout or JS behavior changes.
- Deployment changes: `check`; `docker compose -f deploy/docker-compose.yml config` for Compose edits.

## Mocking Rules

- Mock SSH/Paramiko for collectors, command execution, connection test, and WebSSH unit tests.
- Mock SMTP/email sending.
- Mock cron execution by calling collection functions directly.
- Mock webhook receivers and LLM provider calls.
- Mock external public IP lookup in local dashboard tests.

## Manual Verification Notes

State explicitly when a path was not exercised because it needs a reachable SSH host, SMTP account, cron installation, Alertmanager, LLM credentials, Docker daemon, Kubernetes cluster, or browser session.
