# Example: Add A DevOps API

## User Request

Add an API that returns recent failed command executions for the current user's visible hosts.

## Skill Path

1. `centos-feature-dev`
2. `centos-devops-automation-dev`
3. `../references/devops-api-dictionary.md`
4. `../references/test-patterns.md`
5. `../references/documentation-rules.md`

## Read Order

1. `devops/api.py`
2. `devops/urls.py`
3. `devops/services.py`
4. `docs/devops_json_api.md`
5. `devops/tests.py`

## Implementation Notes

- Add the endpoint and route.
- Use `api_login_required` and `require_http_methods(["GET"])`.
- Filter commands by `host__in=visible_hosts_for_request(request)`.
- Use existing command serializer or add a safe serializer.
- Keep host credentials omitted.
- Clamp `limit` with `limit_queryset`.

## Tests

- Unauthenticated request returns `401`.
- Visible host failed commands are returned.
- Out-of-scope host commands are excluded.
- Response has no host credential fields.

## Validation

```bash
.venv/bin/python manage.py test devops
.venv/bin/python manage.py check
python3 .codex/skills/centos-feature-dev/scripts/check_skill_links.py
```

