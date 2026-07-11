# Review Checklist

Use this after implementation and before final reporting.

## Scope

- The change matches the user request and does not include unrelated refactors.
- All touched files belong to the expected feature path from `task-router.md`.
- Any schema, API, env, or UI behavior change has corresponding docs/tests.

## Security

- Login-required views and APIs enforce the correct auth path.
- DevOps role/module permissions are checked before privileged actions.
- Host scope is applied before exposing host data or executing host actions.
- Secrets are not exposed in templates, JSON, logs, audits, notifications, or test output.
- CSRF behavior is preserved for POST forms and fetch calls.
- Remote command/file behavior does not introduce local shell interpolation or unsafe paths.

## Data And Compatibility

- Legacy `db_table` names are preserved.
- Migrations exist for model changes.
- Existing rows have safe defaults or migration behavior.
- Existing URL names, session keys, payload keys, and template context keys remain compatible unless intentionally changed.

## Workflow Correctness

- Background jobs work with `DEVOPS_SYNC_TASKS`.
- Parent and per-host status rows remain consistent.
- Alert lifecycle uses DevOps service helpers.
- Approval, silence, notification, audit, and deduplication behavior remain coherent.

## UI

- Python payload builders and JS consumers were updated together.
- Text fits buttons, tables, cards, and mobile layouts.
- Operational UI remains dense and task-focused.
- No remote CDN or new build step was added without explicit request.

## Tests

- Focused tests were run or the blocker is stated.
- SSH, SMTP, cron, webhook, external IP, and LLM behavior are mocked unless live testing was requested.
- New behavior has success, failure, permission/ownership, and edge-case coverage as appropriate.

## Docs

- DevOps API docs reflect endpoint shape and permission behavior.
- New env vars or runtime behavior are documented.
- Outdated notes were revised rather than left contradictory.

