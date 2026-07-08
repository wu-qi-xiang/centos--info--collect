---
name: centos-password-vault-dev
description: Work on the per-user password/account registry, encrypted stored secrets, password reveal flow, CRUD, and search in centos--info--collect.
---

# Centos Password Vault Dev

## When To Use

Use for the `password` app: password/account CRUD, owner filtering, encrypted storage, reveal endpoint, search, and password templates.

## Execution Rule

For development work, the main agent plans and delegates after user confirmation. Subagents perform implementation within explicit file/responsibility ownership. The main agent reviews, integrates, validates, and reports.

## Fast Path

### Change vault CRUD/search

Read:
1. `password/models.py`
2. `password/forms.py`
3. `password/views.py`
4. `templates/password/`
5. `password/tests.py`

Change:
1. Keep querysets scoped by `auther=request.session.get("user_name")`.
2. Preserve encryption for stored secret values.
3. Keep decrypted values out of list pages and JSON payloads.
4. Update form, template, payload helpers, and tests together.

### Change reveal/copy behavior

Read:
1. `password/views.py`
2. `PyLinux/crypto.py`
3. `templates/password/`
4. `password/tests.py`

Change:
1. Make reveal explicit and owner-scoped.
2. Do not log plaintext secrets.
3. Add tests for authorized reveal, unauthorized access, and missing rows.

## Invariants

- `Password` uses `db_table = "password_manage"`.
- Ownership follows the custom session user, not Django auth.
- Secrets must not appear in audits, errors, or test output.

## Validation

```bash
.venv/bin/python manage.py test password
.venv/bin/python manage.py check
```

## Shared References

- `../centos-feature-dev/references/django-legacy-standards.md`
- `../centos-feature-dev/references/security-checkpoints.md`
- `../centos-feature-dev/references/test-matrix.md`
- `../centos-feature-dev/references/test-patterns.md`
- `../centos-feature-dev/references/review-checklist.md`
