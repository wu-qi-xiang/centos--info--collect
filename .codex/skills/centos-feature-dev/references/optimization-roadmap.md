# Optimization Roadmap

Use this to avoid repeating completed optimization work and to choose the next useful phase.

## Completed

- DevOps API host-scope hardening for dashboard, alerts, approvals, tasks, deployments, and files.
- Notification log filtering, response preview truncation, and sensitive-field omission.
- Production checks for debug, secret, allowed hosts, SQLite, timeout, audit retention, and metric retention settings.
- Background task idempotency for commands, batch tasks, file distribution, deployment, and rollback.
- Metric sample retention with `METRIC_SAMPLE_RETENTION_DAYS`.
- AIOps dashboard host-scope filtering for stored alert analysis.
- DevOps Vue console module tabs filtered by bootstrap permissions and short status refresh for running work.
- Skill workflow rule: main agent plans first, subagents perform development implementation, main agent reviews and validates.

## Recommended Next Work

1. Shared sidebar permission context so classic navigation matches DevOps Vue permissions.
2. Permission deletion/clear flows with audit details.
3. Independent worker/Celery/RQ option for production task execution.
4. CI pipeline for `manage.py check`, migration checks, focused tests, and skill validation.
5. Nginx/static/media reverse-proxy example for production deployment.
6. AIOps LLM key encryption and blank-update behavior.

## Selection Rules

- Prefer security, host-scope, secret handling, and production safety before UI polish.
- Prefer small phases with focused tests over broad refactors.
- Do not introduce new infrastructure dependencies unless the user confirms the runtime tradeoff.
