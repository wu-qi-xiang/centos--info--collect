# DevOps JSON API

这些接口用于后续 Vue 前端逐步替换 Django 模板页面。当前认证沿用现有 session 登录；未登录统一返回 `401`。

## 通用响应

成功：

```json
{"ok": true}
```

失败：

```json
{"ok": false, "code": "forbidden", "message": "没有权限"}
```

## 主机范围

主机关联接口统一按当前用户的主机范围过滤。范围可配置主机组和主机标签，命中任一所选主机组或标签的主机即可访问；未选择任何组或标签的已配置范围不允许访问主机。管理员未配置范围时保留全部主机可见的既有行为。

## 基础接口

- `GET /devops/api/bootstrap/`
  - 当前用户、模块权限和关键计数。
  - `counts.hosts/groups/open_alerts/pending_approvals` 均按当前用户可见主机范围统计；不返回不可见主机的告警或审批数量。
- `GET /devops/api/hosts/`
  - 当前用户可见主机列表，不返回密码或私钥。
- `GET /devops/api/dashboard/`
  - DevOps 概览、最近命令、最近告警、主机最新指标。
  - `recent_commands`、`recent_alerts`、`host_metrics` 和相关统计均按当前用户可见主机范围过滤。

## 命令和任务

- `GET /devops/api/commands/?limit=50`
  - 命令执行记录，仅返回当前用户可见主机上的记录。
- `POST /devops/api/commands/`
  - JSON: `{"host_id": 1, "command": "uptime"}`
  - `host_id` 必须在当前用户可见主机范围内；越权或不存在返回 `403` 和 `code: "host_forbidden"`。
  - 请求体不是合法 JSON 时返回 `400` 和 `code: "invalid_json"`。
  - 普通命令返回 `201` 和 `record`。
  - 高危命令返回 `202`、`requires_approval: true` 和 `approval`。
- `GET /devops/api/commands/<id>/`
  - 命令详情，遵守主机组授权范围。
- `GET /devops/api/tasks/?limit=50`
  - 批量任务列表，仅返回包含当前用户可见主机的任务；`host_count` 只统计当前用户可见主机数量。
- `POST /devops/api/tasks/`
  - JSON: `{"name": "check uptime", "host_ids": [1, 2], "command": "uptime"}`
  - 请求体不是合法 JSON 时返回 `400` 和 `code: "invalid_json"`。

## 监控、告警、审批

- `GET /devops/api/metrics/?host=1&range=24h`
  - `range` 支持 `6h`、`24h`、`7d`、`30d`。
  - 返回 `labels` 和 `series.cpu/memory/disk`。
  - `host` 必须在当前用户可见主机范围内；未指定时默认选择第一个可见主机。
- `GET /devops/api/alerts/?limit=50`
  - 告警记录列表，仅返回当前用户可见主机上的告警和无主机关联的全局告警。
- `GET /devops/api/approvals/?limit=100`
  - 审批列表，遵守主机组授权范围；命令审批按审批主机过滤，发布审批按发布目标主机过滤，无主机和无发布关联的全局审批仍可见。
- `POST /devops/api/approvals/<id>/decide/`
  - 审批决策。
  - 认证：需要 session 登录；未登录返回 `401` 和 `code: "unauthorized"`。
  - 权限：需要审批模块管理员权限，即 `DevOpsRole.ROLE_ADMIN` + `DevOpsModulePermission.MODULE_APPROVAL`；权限不足返回 `403` 和 `code: "forbidden"`。
  - JSON: `{"action": "approve", "comment": "同意"}`，`action` 仅支持 `approve` 或 `reject`，`comment` 可选并按模型最长 500 字符保存。
  - 请求体不是合法 JSON 时返回 `400` 和 `code: "invalid_json"`；动作无效、审批非待审批或申请人自审返回 `400` 和 `code: "validation_error"`。
  - 主机范围：只能处理 `GET /devops/api/approvals/` 中当前用户可见范围内的审批；不可见或不存在返回 `404` 和 `code: "not_found"`。
  - 拒绝成功返回 `ok: true` 和 `approval`，状态为 `rejected`，并记录审批人、意见和审计日志。
  - 批准成功会先记录审批人、意见和批准状态，再执行关联请求；返回的 `approval.status` 可能是 `executed` 或 `failed`。
  - 安全：返回字段沿用审批列表序列化，不包含主机密码、私钥、通知 webhook 或密钥。

## 发布、文件和通知

- `GET /devops/api/deployments/?limit=50`
  - 发布记录列表，仅返回包含当前用户可见主机的发布；`host_count` 只统计当前用户可见主机数量。
- `GET /devops/api/files/?limit=50`
  - 文件分发记录列表，仅返回包含当前用户可见主机的分发；`host_count` 只统计当前用户可见主机数量。
- `GET /devops/api/notifications/?channel=1&event_type=alert&status=failed&limit=50`
  - 通知渠道列表和发送日志。
  - 认证：需要 session 登录；未登录返回 `401` 和 `code: "unauthorized"`。
  - 权限：需要安全模块只读权限；权限不足返回 `403` 和 `code: "forbidden"`。通知管理数据不按主机范围过滤。
  - 查询参数：
    - `channel`：按通知渠道 ID 筛选日志。
    - `event_type`：按事件类型筛选，支持 `alert`、`approval`、`deployment`、`test`。
    - `status`：按发送状态筛选，支持 `success`、`failed`。
    - `limit`：返回日志数量，默认 `50`，最大 `200`。
  - 成功返回：
    - `channels[]`：`id`、`name`、`channel_type`、`channel_type_label`、通知开关和 `enabled`。
    - `logs[]`：`id`、`channel`、`channel_id`、`event_type`、`event_type_label`、`title`、`status`、`status_label`、`response`、`created_at`。
  - 安全：不返回 `webhook_url`、`secret` 或加密后的密文字段；`response` 仅返回截断后的预览，避免失败响应过长。
  - 无效 `channel`、`event_type` 或 `status` 返回 `400` 和 `code: "validation_error"`。

## 审计日志

- `GET /devops/api/audit-logs/?q=deploy&user=alice&action=创建&target_type=DeploymentRelease&limit=50`
  - 审计日志列表。
  - 认证：需要 session 登录；未登录返回 `401` 和 `code: "unauthorized"`。
  - 权限：需要审计日志模块只读权限，即 `DevOpsRole.ROLE_VIEWER` + `DevOpsModulePermission.MODULE_AUDIT`；权限不足返回 `403` 和 `code: "forbidden"`。
  - 主机范围：审计日志不是主机关联模型，不按主机范围过滤；调用方必须具备审计模块权限。
  - 查询参数：
    - `q`：模糊匹配 `action`、`detail`、`target_type`、`target_id`。
    - `user`：按 `user` 模糊匹配。
    - `action`：按 `action` 模糊匹配。
    - `target_type`：按 `target_type` 模糊匹配。
    - `limit`：返回数量，默认 `50`，最大 `200`。
  - 成功返回 `results[]`：`id`、`user`、`action`、`target_type`、`target_id`、`detail`、`ip_address`、`created_at`。
  - 安全：不返回主机凭据、通知密钥或 webhook 配置字段；`detail` 输出前会遮蔽 `http(s)` URL、`enc:` 密文片段，以及包含 `secret`、`password`、`token`、`key` 等关键词的键值片段。

## Vue 接入建议

1. 先用 `bootstrap` 初始化当前用户、权限和菜单可见性。
2. 页面列表优先使用 `GET` 接口替换模板数据。
3. 高风险操作继续走后端策略：命令接口可能返回审批申请而不是直接执行记录。
4. 文件上传、发布创建、审批处理可以在第二批 API 中补齐。
