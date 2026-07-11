# AIOps LLM Contract

Use this when changing `aiops` LLM configuration, Alertmanager webhook intake, alert analysis storage, or dashboard analysis behavior.

## Current Data Model

### `AiopsIntegration`

| Field | Meaning | Current behavior |
|---|---|---|
| `alertmanager_url` | External Alertmanager base URL/reference | Stored for UI/config reference. |
| `llm_url` | LLM base URL or full chat-completions URL | `_llm_endpoint` appends `/v1/chat/completions` unless the URL already ends with `/chat/completions`. |
| `llm_api_key` | Bearer token for LLM provider | Stored as plain text today. Treat as sensitive; do not render/log/serialize raw value. |
| `llm_model` | Chat model name | Defaults to `gpt-4o-mini`. |
| `enabled` | Webhook intake switch | Disabled webhook returns `403`. |
| `updated_by`, `updated_at` | Config metadata | Set from custom session user on save. |

### `AiopsAlertAnalysis`

| Field | Meaning |
|---|---|
| `alert_name`, `severity`, `instance` | Extracted from Alertmanager labels. |
| `source` | Defaults to `alertmanager`. |
| `raw_payload` | Full alert JSON string. Treat as operational data. |
| `summary` | Alert summary/description. |
| `suggestion` | LLM or fallback recommendation. |
| `llm_response` | Raw LLM response text, truncated in code to 4000 chars. |
| `status` | `received`, `analyzed`, or `failed`. |
| `error` | LLM or processing error message. |

## LLM API Contract

- Provider shape is OpenAI-compatible chat completions.
- Empty `llm_url` means no external call; use fallback suggestion.
- Full `/v1/chat/completions` or `/chat/completions` endpoint is used as-is.
- Otherwise append `/v1/chat/completions`.
- Add `Authorization: Bearer <llm_api_key>` only when a key is configured.
- Request uses configured `llm_model` or `gpt-4o-mini`, system/user messages, and `temperature: 0.2`.
- Timeout is currently hard-coded to 20 seconds.
- HTTP status >= 400 returns fallback suggestion, raw response text, and an error.
- Unexpected JSON must not crash the webhook path; fallback suggestion should be used.

## Alertmanager Webhook Contract

- Endpoint: `POST /aiops/webhook/`.
- CSRF exempt by current design.
- Disabled integration returns `403`.
- Invalid JSON returns `400`.
- Payload can be Alertmanager object with `alerts: [...]` or a single alert object.
- Only dictionary alerts are processed.
- Missing labels/annotations must not crash.
- Response shape: `{ok: true, created, ids}`.

## Extraction Rules

| Analysis field | Source |
|---|---|
| `alert_name` | `labels.alertname` or top-level `alertname` |
| `severity` | `labels.severity` |
| `instance` | `labels.instance` or `labels.host` |
| `summary` | `annotations.summary`, `annotations.description`, or top-level `summary` |

Prompt text should include alert name, severity, instance, summary, and a bounded serialized alert body.

## Fallback Rules

Fallback must be deterministic and local when:

- `llm_url` is empty.
- LLM request raises an exception.
- LLM returns HTTP error.
- LLM response lacks expected `choices[0].message.content`.

Dashboard rendering and tests must never require LLM/network access.

## Security Rules

- Treat `llm_api_key` as sensitive even though it is currently stored plain text.
- Do not render raw key; UI should expose only `llm_api_key_set`.
- Do not log request headers, raw key, or full provider errors that may contain credentials.
- Avoid storing secrets inside `raw_payload`, `llm_response`, or `error`.
- If future work encrypts `llm_api_key`, preserve blank-update behavior.
- Webhook payload may contain operational labels/annotations; do not forward more than needed to LLM.

## Test Pattern

Cover these cases in `aiops/tests.py`:

- Dashboard renders without LLM config.
- Config save sets URL/model/enabled and preserves API key when blank if that behavior is implemented.
- Webhook disabled returns `403`.
- Invalid JSON returns `400`.
- Missing labels/annotations creates a record with safe defaults.
- LLM success stores analyzed suggestion.
- LLM HTTP error stores fallback suggestion and error.
- LLM exception stores fallback suggestion and failed status.
- Raw `llm_api_key` is not rendered in dashboard response.

## Change Checklist

1. Read `aiops/models.py`, `aiops/views.py`, `aiops/tests.py`, `static/js/aiops-vue.js`, and `templates/aiops/dashboard.html`.
2. Preserve local fallback before adding provider-specific behavior.
3. Keep provider-specific assumptions isolated in `_call_llm` or a helper.
4. Keep Alertmanager parsing defensive.
5. Add or update tests with mocked `requests.post`.
6. Run `.venv/bin/python manage.py test aiops` and `.venv/bin/python manage.py check`.

