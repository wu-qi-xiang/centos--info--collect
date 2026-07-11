# Example: Harden Secret Output

## User Request

Ensure notification webhook URLs are never returned in DevOps APIs or rendered in templates.

## Skill Path

1. `centos-feature-dev`
2. `centos-devops-automation-dev`
3. `../references/security-checkpoints.md`
4. `../references/devops-api-dictionary.md`
5. `../references/review-checklist.md`

## Read Order

1. `devops/models.py`
2. `devops/api.py`
3. `devops/views.py`
4. `templates/devops/`
5. `devops/tests.py`

## Implementation Notes

- Keep encrypted storage through the existing model behavior.
- Do not serialize webhook URL or secret.
- Do not render existing secret values in edit forms.
- Preserve blank-secret update behavior.
- Avoid raw secret values in audits, logs, notification messages, and test output.

## Tests

- Notification list API omits webhook URL and secret.
- Template context does not expose raw webhook URL or secret.
- Updating without secret preserves existing encrypted secret.
- Updating with a new secret replaces it.

## Validation

```bash
.venv/bin/python manage.py test devops
.venv/bin/python manage.py check
```

