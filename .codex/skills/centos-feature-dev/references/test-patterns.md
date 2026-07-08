# Test Patterns

Use these patterns to choose test cases, not just commands.

## Django Page View Pattern

Cover:

- GET renders expected template/status.
- Valid POST changes data and redirects or returns expected status.
- Invalid POST renders form errors and does not change data.
- Unauthenticated request follows existing login behavior.
- Permission/ownership denial returns expected forbidden/empty result.

## DevOps API Pattern

Cover:

- Unauthenticated request returns `401` and `code="unauthorized"`.
- Logged-in user without role/module permission gets `403`.
- Host outside scope is not visible or action is denied.
- Invalid JSON returns `400` and `code="invalid_json"` where JSON parsing is used.
- Missing required fields return `400`.
- Success response has stable `ok: true` shape.
- Sensitive fields are absent from serialized JSON.

## Host SSH Mock Pattern

Cover:

- Success path with fake SSH client output.
- Timeout/auth/network failure mapped through `describe_ssh_error`.
- Saved encrypted credentials are decrypted only inside SSH helper paths.
- Blank credential update preserves old encrypted values.
- Private key and passphrase auth path works without exposing raw values.

## Secret Update Pattern

Cover:

- Creating a secret stores encrypted or hashed value as appropriate.
- Updating with a new secret replaces the stored encrypted value.
- Updating with blank secret preserves existing encrypted value.
- List/detail/API output omits the raw secret.
- Explicit reveal endpoint is owner-scoped and does not leak another user's data.

## Background Job Pattern

Cover:

- `DEVOPS_SYNC_TASKS` executes synchronously in tests.
- Parent starts as `running` and ends as `success`, `partial`, `failed`, or `blocked`.
- Per-host result rows are created for each selected host where applicable.
- One host failure does not stop all remaining hosts.
- Background exceptions create failure status and audit/log evidence where the app supports it.

## Monitoring Pattern

Cover:

- Threshold parser accepts percent strings, numbers, and fractions.
- Metric sample is recorded before threshold comparison.
- New threshold breach creates alert.
- Repeated breach increments/updates existing alert rather than duplicating unexpectedly.
- Recovery resolves alert.
- Silenced alert does not send normal alert notification.
- SSH and SMTP are mocked.

## AIOps Pattern

Cover:

- Dashboard data respects host scope.
- Empty data produces deterministic empty summaries.
- Missing webhook labels/annotations do not crash.
- LLM config missing or call failure uses local fallback.
- Raw LLM/API credentials are not rendered or logged.

## Vue Payload Pattern

Cover:

- Python payload contains the keys consumed by static JS.
- Permission-limited user sees filtered data.
- CSRF token is present where POST/fetch needs it.
- Empty and error states are represented.

