# P0 平台可靠性与事件行动项实施计划

## 任务 1：调度与通知可靠性评估

所有权：`devops/reliability.py`、`devops/api.py` 可靠性端点、`devops/urls.py`、相关测试、`docs/devops_json_api.md`；不得修改 Incident 模型、事件 API 或前端组件。

实现安全的聚合服务，读取 `ScheduledTaskRun` 与通知日志，计算最后成功、失败连续次数和新鲜度状态；增加管理员保护的 GET API。补充边界测试：无记录、过期、失败、敏感字段不输出和非管理员拒绝。

验证：`.venv/bin/python manage.py test devops.test_platform_reliability devops.test_scheduler devops.test_notification_governance`、`.venv/bin/python manage.py check`。

## 任务 2：事件复盘行动项

所有权：`devops/models.py`、新迁移、`devops/incident_actions.py`、事件 API/URL、相关测试、事件 API 文档；不得修改调度可靠性服务或通知发送实现。

新增本地用户可选负责人、状态、优先级、截止时间和完成时间；通过现有事件可见性和告警模块权限保护 CRUD/状态更新，写入审计。保留 `Incident.follow_up` 兼容旧数据，逾期只读计算。

验证：`.venv/bin/python manage.py test devops.test_incident_action_items devops.test_incident_command_center devops.test_postmortem_draft`、迁移检查、`.venv/bin/python manage.py check`。

## 集成门

主代理审查两个轨道的模型迁移、API 字段和权限边界；运行完整 `devops` 测试、`git diff --check` 和 `manage.py makemigrations --check --dry-run`。不调用真实 SSH、企业微信、Prometheus、Alertmanager 或外部工单系统。
