# Security Checkpoints

Run the relevant checks before finishing any change.

## Authentication And Sessions

- Custom login uses `RemoteLinux.models.User`, not Django's built-in auth user model.
- Session keys are `is_login`, `user_id`, and `user_name`.
- Views that require login should use `session_login_required` unless the local pattern intentionally differs.
- Clear newly added session state on logout.
- Validate `next` redirects before redirecting.

## Host Scope And DevOps Permissions

- Host-specific data must respect `visible_hosts_for_request`, `can_access_host`, `can_access_hosts`, or `require_host_access`.
- DevOps actions must enforce role/module permission before execution or data exposure.
- Non-admin host ownership/scope behavior must be preserved for create/import flows.
- High-risk commands should go through existing command policy and approval paths.

## Secret Handling

- Never expose `linux_passwd`, `linux_private_key`, `linux_private_key_passphrase`, password-vault secrets, webhook URLs, notification secrets, API keys, or raw passwords in templates, JSON, logs, audits, test output, or notification messages.
- Preserve encrypted host credentials and notification secrets when update forms leave secret fields blank.
- Password-vault list pages should not render decrypted values; reveal must be explicit and owner-scoped.
- Do not log raw webhook payload secrets or LLM credentials.

## Remote Execution And Files

- Do not run user-provided shell text locally.
- Managed commands should target remote hosts through established SSH execution helpers.
- Validate remote distribution paths with `validate_remote_path`.
- Treat uploaded files defensively: path, name, size, and destination should be controlled.
- WebSSH must close SSH clients/channels on normal and failure paths.

## API And UI

- DevOps JSON API errors should use `{ok: false, code, message}`.
- JSON serializers must omit sensitive/encrypted fields.
- CSRF behavior must remain intact for POST forms and fetch calls.
- Avoid remote CDN dependencies; prefer static assets already vendored in the repo.

## External Integrations

- Tests must not require live SSH, SMTP, cron, external IP service, Alertmanager, webhook receivers, or LLM providers unless the user explicitly asks for live integration.
- AIOps dashboard and analysis must fall back without LLM/network availability.

