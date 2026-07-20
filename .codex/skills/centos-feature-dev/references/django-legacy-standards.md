# Django Legacy Standards

Follow these standards when changing this Django 4.2.16 codebase with legacy compatibility constraints.

## General Style

- Match nearby function-based views, forms, templates, and helper functions.
- Prefer small local helpers for view-only formatting; use service/helper modules for reusable business workflows.
- Do not introduce class-based views, DRF, a frontend build system, Celery, or major framework patterns unless explicitly requested.
- Keep imports compatible with the supported Python 3.11/Django 4.2.16 baseline and the project's legacy module paths.
- Preserve explicit `db_table` values and legacy URL names unless the task is a deliberate migration.

## View Rules

- Read request input defensively with `.get()` unless nearby code intentionally requires a field.
- Return `404` for missing rows and `403` for forbidden access where existing helpers support it.
- Keep POST redirects and form re-render behavior consistent with neighboring views.
- Keep CSRF tokens in forms and fetch payloads.
- Do not put long reusable business workflows only in views; move reusable logic to `devops/services.py`, collectors, or app helpers.

## Model And Migration Rules

- Add migrations when changing model fields.
- Consider existing data and default values.
- Update forms, templates, import/export mappings, serializers/payload helpers, and tests together.
- Do not rename legacy tables casually.

## Forms

- Preserve `ModelForm` conventions used by the app.
- When a secret field is left blank on update, preserve the existing encrypted value.
- Keep server-side validation authoritative; UI validation is only assistive.

## JSON API

- DevOps API errors use `{ok: false, code, message}`.
- Unauthenticated API requests should return `401`.
- Permission failures should return `403`.
- Serialize simple dictionaries; keep shape stable for existing Vue consumers.
- Omit sensitive fields by default.

## ORM And Performance

- Use filtered querysets before pagination or serialization.
- Apply host scope before counting or aggregating host-specific data.
- Watch for N+1 queries in list/detail pages; use `select_related` or `prefetch_related` when the model relationships warrant it.
- Keep dashboard aggregations deterministic and testable with ORM fixtures.

## Error Handling

- Use existing error formatters such as `describe_ssh_error`.
- Do not leak raw exception details to users when they may contain secrets or internals.
- Record audits for privileged actions and background failures where DevOps already does so.

## Comments

- Add comments only for non-obvious legacy compatibility, security-sensitive behavior, or complex state transitions.
- Do not add comments that merely restate code.
