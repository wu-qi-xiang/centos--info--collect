# 告警质量治理审核实施计划

## 任务 1：治理审核模型与确定性服务

所有权：`devops/models.py`、新迁移、`aiops/alert_quality.py` 或新治理服务、专项测试；不得修改告警生命周期和 Prometheus 写入逻辑。

扩展建议稳定键并新增审核记录的创建/读取/状态转换服务，校验状态、备注长度和可选 revision ID。建议只使用反馈计数与安全标识，保留现有阈值/去重建议算法。

## 任务 2：API 与 AIOps 页面

所有权：`aiops/views.py`、`aiops/urls.py`、`devops/api.py`、`devops/urls.py`、`static/js/aiops-vue.js`、相关 CSS、API 文档和测试；不得修改 SSH、通知发送和 Kubernetes 客户端。

增加建议查询和审核状态更新 API；在现有告警质量页面显示审核状态、审核备注和 operator 可用的审核按钮。保留 CSRF、权限和主机范围约束。

## 集成验证

运行 AIOps/DevOps 专项测试、完整 `aiops` 与 `devops` 测试、`manage.py check`、迁移检查、JS 语法检查和 `git diff --check`。不访问真实 Prometheus、Alertmanager、企业微信、SSH 或 LLM。
