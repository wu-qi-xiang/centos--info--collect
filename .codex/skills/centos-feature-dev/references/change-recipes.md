# Change Recipes

Use these recipes to avoid missing the common follow-up files in this legacy Django project.

## Add A DevOps JSON API

1. Add or update the endpoint in `devops/api.py`.
2. Wire the URL in `devops/urls.py`.
3. Keep session auth behavior: unauthenticated requests return `401` with `{ok: false, code, message}`.
4. Enforce role/module permission and host scope before exposing host-specific data.
5. Serialize only safe fields. Never include credentials, private keys, webhook URLs, notification secrets, or encrypted secret values.
6. Keep error responses in the existing `{ok: false, code, message}` shape.
7. Add focused tests in `devops/tests.py`.
8. Update `docs/devops_json_api.md` with method, request, response, permission, and sensitive-field behavior.

## Add A Host Inventory Field

1. Update `RemoteLinux/models.py` and add a migration.
2. Update `RemoteLinux/forms.py`.
3. Update create, update, copy, import, list/detail payloads in `RemoteLinux/views.py`.
4. Update CSV header mapping if the field is importable.
5. Update templates under `templates/linux/` and any Vue payload consumers.
6. If the field is sensitive, encrypt at write time and omit from list/detail payloads.
7. Add tests for create/update/import/list visibility and blank update behavior where relevant.

## Add Or Change A Classic Form Page

1. Read the view, form, template, URL, and tests for that feature.
2. Preserve server-side validation and existing error rendering.
3. Keep `{% csrf_token %}` or explicit CSRF token payloads intact.
4. Redirect or render with status codes matching nearby views.
5. Add tests for GET, valid POST, invalid POST, and permission/ownership behavior.

## Add Or Change A Vue-Backed Page

1. Read `PyLinux/vue.py`, `templates/vue/page.html`, the Python payload builder, and the matching static JS/CSS.
2. Update Python payload and JS consumer together.
3. Preserve CSRF handling for fetch/POST.
4. Avoid remote CDN assets; use vendored static assets.
5. Add server-side tests for payload shape and permission filtering.
6. For visual changes, run the dev server and inspect desktop and mobile widths.

## Add Or Change Background Work

1. Put reusable logic in `devops/services.py` or an app helper, not only in a view.
2. Use `DEVOPS_SYNC_TASKS` so tests can run synchronously.
3. Store parent and per-host result rows consistently.
4. Catch per-host exceptions so one target does not fail the entire batch.
5. Record audits for privileged actions and background failures.
6. Test success, partial failure, full failure, blocked/approval paths, and synchronous execution.

## Add Or Change Monitoring Alert Logic

1. Parse thresholds numerically before comparison.
2. Record metric samples before threshold comparison.
3. Use `record_alert`, `resolve_alert`, and `update_alert_status` rather than open-coded alert writes.
4. Keep each host isolated in cron collection.
5. Do not require live SSH, SMTP, or cron in tests.
6. Cover new alert identity/fingerprint behavior with tests.

## Add Or Change Secrets Handling

1. Identify whether the value is a host credential, password-vault secret, webhook URL, notification secret, API key, or session credential.
2. Store with existing crypto helpers where the project already encrypts that category.
3. Do not return the value in list pages, JSON payloads, logs, audits, or notification messages.
4. Preserve existing encrypted values when update forms leave secret fields blank.
5. Test both changed-secret and blank-secret update paths.

## Add Or Change Deployment Runtime Behavior

1. Read `PyLinux/settings.py`, `PyLinux/checks.py`, deployment manifests, and `README.md`.
2. Add environment-driven settings with safe defaults.
3. Do not bake real secrets into settings, Docker, Compose, Kubernetes, or docs.
4. Keep local SQLite behavior unless the task explicitly changes it.
5. Document new environment variables.
6. Run `manage.py check`; validate Compose syntax if Compose changed.

