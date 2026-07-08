---
name: centos-aiops-dev
description: Work on the AIOps dashboard, anomaly summaries, event correlation, root-cause suggestions, Alertmanager webhook intake, and optional LLM integration in centos--info--collect.
---

# Centos Aiops Dev

## When To Use

Use for the `aiops` app: dashboard aggregation, anomaly/correlation/root-cause/capacity summaries, Alertmanager webhook, LLM configuration, and stored alert analysis.

## Execution Rule

For development work, the main agent plans and delegates after user confirmation. Subagents perform implementation within explicit file/responsibility ownership. The main agent reviews, integrates, validates, and reports.

## Fast Path

### Change dashboard insight logic

Read:
1. `aiops/views.py`
2. `aiops/models.py`
3. `devops/models.py`
4. `devops/services.py`
5. `templates/aiops/dashboard.html`
6. `static/js/aiops-vue.js`, `static/css/aiops-vue.css`
7. `aiops/tests.py`

Change:
1. Treat AIOps as an analysis layer over existing DevOps data.
2. Respect `visible_hosts_for_request` for all user-facing data.
3. Keep aggregation deterministic with ORM fixtures.
4. Update Python payload and JS consumer together.

### Change webhook or LLM analysis

Read:
1. `aiops/views.py`
2. `aiops/models.py`
3. `devops/models.py`
4. `aiops/tests.py`

Change:
1. Validate webhook shape defensively.
2. Do not crash on missing labels or annotations.
3. Keep local rule-based fallback when LLM config is unavailable or calls fail.
4. Do not log or render raw secrets.
5. Mock network/LLM calls in tests.

## Invariants

- AIOps must not duplicate command execution or alert lifecycle logic.
- Dashboard rendering and tests must not require external network or LLM access.
- Alert analysis storage uses `AiopsIntegration` and `AiopsAlertAnalysis`.

## Validation

```bash
.venv/bin/python manage.py test aiops
.venv/bin/python manage.py check
```

## Shared References

- `../centos-feature-dev/references/django-legacy-standards.md`
- `../centos-feature-dev/references/aiops-llm-contract.md`
- `../centos-feature-dev/references/security-checkpoints.md`
- `../centos-feature-dev/references/test-matrix.md`
- `../centos-feature-dev/references/test-patterns.md`
- `../centos-feature-dev/references/ui-standards.md`
- `../centos-feature-dev/references/review-checklist.md`
- `../centos-feature-dev/references/file-map.md`
