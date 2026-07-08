# Example: Add A Host Field

## User Request

Add an environment field to hosts and allow operators to import it from CSV.

## Skill Path

1. `centos-feature-dev`
2. `centos-host-ssh-dev`
3. `../references/change-recipes.md`
4. `../references/test-patterns.md`
5. `../references/review-checklist.md`

## Read Order

1. `RemoteLinux/models.py`
2. `RemoteLinux/forms.py`
3. `RemoteLinux/views.py`
4. `templates/linux/`
5. `RemoteLinux/tests.py`

## Implementation Notes

- Add the model field and migration.
- Add the form field.
- Update create, update, copy, list/detail payloads.
- Update CSV header aliases and normalization.
- Update list/detail/form templates.
- Do not treat the field as secret unless requested.

## Tests

- Create host stores the environment.
- Update host changes the environment.
- CSV import accepts English and Chinese header aliases if needed.
- Host scope list/detail still filters visible hosts.

## Validation

```bash
.venv/bin/python manage.py test RemoteLinux
.venv/bin/python manage.py check
```

