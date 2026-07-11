---
name: centos-auth-user-dev
description: Work on login, logout, registration, session authentication, custom RemoteLinux.models.User passwords, password hash migration, auth decorators, and login/register templates in centos--info--collect.
---

# Centos Auth User Dev

## When To Use

Use for changes under `userprofile`, custom users in `RemoteLinux.models.User`, login/register templates, session access checks, or password handling.

## Execution Rule

For development work, the main agent plans and delegates after user confirmation. Subagents perform implementation within explicit file/responsibility ownership. The main agent reviews, integrates, validates, and reports.

## Fast Path

### Change login or registration behavior

Read:
1. `userprofile/views.py`
2. `userprofile/decorators.py`
3. `RemoteLinux/models.py`
4. `RemoteLinux/forms.py`
5. `templates/login.html`, `templates/register.html`
6. `userprofile/tests.py`

Change:
1. Preserve custom session keys: `is_login`, `user_id`, `user_name`.
2. Keep hashed-password and legacy-plaintext compatibility unless explicitly migrating.
3. Validate form input without revealing whether a username/email exists unless required.
4. Keep CSRF and rendered error payloads intact.
5. Add tests for success, invalid credentials/input, session state, and legacy password behavior.

### Add auth checks to another feature

Read:
1. The target view/API.
2. `userprofile/decorators.py`.
3. `PyLinux/security.py` and `devops/services.py` if roles/host scope are involved.

Change:
1. Prefer `session_login_required` for page views.
2. For DevOps APIs, preserve the JSON `401` pattern in `devops/api.py`.
3. Clear any new session state during logout.

## Invariants

- Do not replace the custom user system with Django auth as a side effect.
- Do not log raw passwords or confirmation values.
- Use Django password hash helpers for new or upgraded passwords.
- Validate `next` redirects before using them.

## Validation

```bash
.venv/bin/python manage.py test userprofile
.venv/bin/python manage.py check
```

Broaden tests when auth behavior affects protected feature pages.

## Shared References

- `../centos-feature-dev/references/task-router.md`
- `../centos-feature-dev/references/django-legacy-standards.md`
- `../centos-feature-dev/references/security-checkpoints.md`
- `../centos-feature-dev/references/test-matrix.md`
- `../centos-feature-dev/references/test-patterns.md`
- `../centos-feature-dev/references/review-checklist.md`
