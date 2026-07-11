# Example: Change AIOps LLM Analysis

## User Request

Support a new OpenAI-compatible LLM gateway for Alertmanager analysis and make sure dashboard still works when the gateway is down.

## Skill Path

1. `centos-feature-dev`
2. `centos-aiops-dev`
3. `../references/aiops-llm-contract.md`
4. `../references/test-patterns.md`
5. `../references/security-checkpoints.md`

## Read Order

1. `aiops/models.py`
2. `aiops/views.py`
3. `static/js/aiops-vue.js`
4. `templates/aiops/dashboard.html`
5. `aiops/tests.py`

## Implementation Notes

- Keep provider behavior OpenAI-compatible unless explicitly adding another format.
- Keep endpoint normalization in or near `_llm_endpoint`.
- Keep external calls isolated in `_call_llm`.
- Preserve fallback suggestion for missing config, HTTP error, invalid JSON, and exceptions.
- Do not render or log `llm_api_key`; expose only `llm_api_key_set`.
- Keep Alertmanager webhook parsing tolerant of missing labels and annotations.

## Tests

- LLM success stores analyzed suggestion.
- LLM HTTP error stores fallback suggestion and error.
- LLM exception stores fallback suggestion and failed status.
- Missing `llm_url` does not call network.
- Dashboard response does not contain raw API key.

## Validation

```bash
.venv/bin/python manage.py test aiops
.venv/bin/python manage.py check
python3 .codex/skills/centos-feature-dev/scripts/check_skill_links.py
```

