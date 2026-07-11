# Example: Fix Monitoring Alert Behavior

## User Request

Fix repeated CPU alerts so they update the existing open alert instead of creating duplicates.

## Skill Path

1. `centos-feature-dev`
2. `centos-monitor-alert-dev`
3. `../references/devops-state-models.md`
4. `../references/test-patterns.md`
5. `../references/security-checkpoints.md`

## Read Order

1. `monitor/crontab.py`
2. `devops/services.py`
3. `devops/models.py`
4. `monitor/tests.py`
5. `devops/tests.py`

## Implementation Notes

- Keep threshold parsing numeric.
- Keep metric sample recording before alert comparison.
- Use `record_alert` rather than direct `AlertEvent` writes.
- Preserve silence behavior and repeat count semantics.
- Do not require live SSH or SMTP in tests.

## Tests

- First threshold breach creates one open alert.
- Repeated breach updates repeat count/message on the same active alert.
- Recovery resolves the alert.
- Silenced alert remains silenced and avoids normal notification.

## Validation

```bash
.venv/bin/python manage.py test monitor
.venv/bin/python manage.py test devops
.venv/bin/python manage.py check
```

