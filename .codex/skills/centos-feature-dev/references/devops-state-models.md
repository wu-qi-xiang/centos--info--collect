# DevOps State Models

Use this when changing DevOps workflows, approvals, alerts, tasks, deployments, or notifications.

## Shared Status Semantics

| Status | Meaning |
|---|---|
| `pending` | Created but not started |
| `running` | Background or remote work in progress |
| `success` | All intended work succeeded |
| `partial` | Some hosts succeeded and some failed |
| `failed` | Work failed or no host succeeded |
| `blocked` | Policy prevented execution |

## CommandExecution

Statuses:

- `pending`
- `running`
- `success`
- `failed`
- `blocked`

Typical flow:

```text
pending -> blocked
pending -> running -> success
pending -> running -> failed
```

Rules:

- Policy block sets `blocked`.
- Remote SSH command execution sets `running` before attempts.
- Finished commands should set `finished_at`, output/error, and duration where available.

## BatchTask

Statuses:

- `pending`
- `running`
- `success`
- `partial`
- `failed`
- `blocked`

Typical flow:

```text
pending -> blocked
pending -> running -> success
pending -> running -> partial
pending -> running -> failed
```

Rules:

- Create per-host `BatchTaskResult` rows.
- If command policy blocks the task, parent is `blocked` and per-host command records should reflect block where created.
- `partial` means at least one host succeeded and at least one failed.

## FileDistribution

Statuses mirror `BatchTask`.

Rules:

- Validate remote path with `validate_remote_path` before execution.
- Create per-host `FileDistributionResult` rows.
- Preserve uploaded file safety and do not expose unsafe local paths.

## DeploymentRelease

Statuses:

- `pending`
- `running`
- `success`
- `partial`
- `failed`
- `blocked`
- `rolled_back`

Deploy flow:

```text
pending -> blocked
pending -> running -> success
pending -> running -> partial
pending -> running -> failed
```

Rollback flow:

```text
success|partial|failed -> rolled_back
success|partial|failed -> failed
```

Rules:

- Create `DeploymentResult` rows for deploy/rollback actions.
- Deployment approvals may defer execution.
- Forced deploy/rollback approval settings must be respected.
- Notify deployment result through existing service helpers where used.

## ApprovalRequest

Types:

- command
- deployment
- rollback

Statuses:

- `pending`
- `approved`
- `rejected`
- `executed`
- `failed`

Typical flow:

```text
pending -> rejected
pending -> approved -> executed
pending -> approved -> failed
```

Rules:

- Approval decision should record approver/comment/decided time.
- Execution status should reflect downstream command/deployment result.
- Approval actions should notify and audit where existing workflow does.

## AlertEvent

Levels:

- `info`
- `warning`
- `critical`

Statuses:

- `open`
- `processing`
- `resolved`
- `closed`
- `silenced`

Typical flow:

```text
open -> processing -> resolved
open -> silenced -> resolved
open -> closed
```

Rules:

- Use `record_alert`, `resolve_alert`, and `update_alert_status`.
- Alert identity is based on host and metric fingerprint.
- Repeated alert updates repeat count and message, rather than blindly duplicating active alerts.
- Silenced alerts should record silence remark and avoid normal notification behavior.
- Status changes should create `AlertHistory`.

## NotificationLog

Statuses:

- `success`
- `failed`

Event types include alert, approval, deployment, command, and system categories.

Rules:

- Notification channel URL/secret are encrypted and must not be serialized.
- Deduplication behavior should be preserved when changing send logic.
- Failed sends should record failure without crashing the originating workflow.

