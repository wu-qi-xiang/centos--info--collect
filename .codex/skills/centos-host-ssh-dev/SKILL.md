---
name: centos-host-ssh-dev
description: Work on server asset inventory, SSH credentials, host CRUD/import/export, remote information collection, connection tests, WebSSH, and host visibility rules in centos--info--collect.
---

# Centos Host SSH Dev

## When To Use

Use for `RemoteLinux` host inventory, SSH credential storage, remote collectors, connection tests, host import/export, WebSSH, and host scope behavior.

## Execution Rule

For development work, the main agent plans and delegates after user confirmation. Subagents perform implementation within explicit file/responsibility ownership. The main agent reviews, integrates, validates, and reports.

## Fast Path

### Add or change a host field

Read:
1. `RemoteLinux/models.py`
2. `RemoteLinux/forms.py`
3. `RemoteLinux/views.py`
4. `templates/linux/`
5. `RemoteLinux/tests.py`

Change:
1. Add/update model field and migration.
2. Update forms, create/update/copy/import logic, payload helpers, templates, and tests.
3. If importable, update CSV header aliases and normalization.
4. If sensitive, encrypt on write and omit from JSON/templates.

### Change SSH collection or connection testing

Read:
1. `RemoteLinux/ssh_utils.py`
2. `RemoteLinux/collectors.py`
3. `RemoteLinux/views.py`
4. `RemoteLinux/tests.py`

Change:
1. Keep SSH client creation and error formatting in helpers.
2. Keep command parsing in collectors where practical.
3. Use `describe_ssh_error` for user-facing SSH failures.
4. Test with mocked Paramiko/SSH clients.

### Change WebSSH

Read:
1. `RemoteLinux/views.py`
2. `static/xterm/js/ssh.js`
3. `templates/linux/`
4. `RemoteLinux/tests.py`

Change:
1. Preserve host access checks before opening WebSSH.
2. Handle byte/string encoding carefully across websocket frames and Paramiko channels.
3. Close SSH clients/channels on normal and failure paths.

## Invariants

- `NewLinux` uses `db_table = "linux-info"`.
- Host credentials are encrypted through `PyLinux.crypto`.
- Blank password/key fields on update must preserve existing encrypted credentials.
- Non-admin users creating/importing hosts should keep personal scope/group behavior.
- Host-specific pages/APIs must use host visibility helpers.

## Validation

```bash
.venv/bin/python manage.py test RemoteLinux
.venv/bin/python manage.py check
```

Manual SSH/WebSSH verification requires a reachable host.

## Shared References

- `../centos-feature-dev/references/change-recipes.md`
- `../centos-feature-dev/references/django-legacy-standards.md`
- `../centos-feature-dev/references/security-checkpoints.md`
- `../centos-feature-dev/references/file-map.md`
- `../centos-feature-dev/references/test-matrix.md`
- `../centos-feature-dev/references/test-patterns.md`
- `../centos-feature-dev/references/review-checklist.md`
