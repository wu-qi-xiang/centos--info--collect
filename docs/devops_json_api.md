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
- `GET /devops/api/prometheus-rules/<cluster_id>/`
  - 返回所选已配置 Kubernetes 集群中全部命名空间的 PrometheusRule 安全摘要，需 session 登录和 K8s 集群模块只读权限。
  - `results[]` 仅包含 `namespace`、`name`、`resource_version`、`created_at`；不返回完整 YAML、kubeconfig、集群凭据、任意 GVK/API 路径或 Kubernetes 原始错误。
  - 路径中的 `cluster_id` 必须指向已配置集群；不存在返回 `404` 和 `code: "not_found"`。
- `GET /devops/api/prometheus-rules/<cluster_id>/<namespace>/<name>/`
  - 返回所选集群中该固定 `monitoring.coreos.com/v1` `PrometheusRule` 的完整 YAML，需 K8s 集群模块只读权限。
  - 集群、命名空间和规则名称只由路由确定；调用方不能提交 group、version、plural 或 Kubernetes API 路径。
- `POST /devops/api/prometheus-rules/<cluster_id>/<namespace>/<name>/update/`
  - JSON：`{"yaml": "..."}`。需 K8s 集群模块管理员权限。
  - YAML 必须且只能包含一个 `monitoring.coreos.com/v1` `PrometheusRule`，并且 `metadata.name`、`metadata.namespace` 和非空 `metadata.resourceVersion` 必须与路由完全一致。
  - 成功返回 `202` 和修订安全摘要；该操作只创建数据库草稿，不会连接 Kubernetes。修订摘要不回显 YAML、kubeconfig 或 Kubernetes 原始对象。
- `POST /devops/api/prometheus-rules/<cluster_id>/<namespace>/<name>/delete/`
  - JSON：`{"confirmation": "DELETE", "resource_version": "..."}`。需 K8s 集群模块管理员权限；确认词必须精确为 `DELETE`，缺少或错误的确认词/资源版本返回 `400` 和 `code: "validation_error"`。
  - 成功返回 `202` 和删除修订草稿；不会连接 Kubernetes。
- `GET /devops/api/prometheus-rules/<cluster_id>/revisions/`
  - 返回该集群的 PrometheusRule 修订安全摘要。需要 K8s 集群模块管理员权限；普通只读用户不能读取治理数据。
  - `results[]` 仅包含 ID、集群 ID、命名空间、规则名、操作、状态、SHA-256 摘要、资源版本、创建/提交/批准/发布时间、创建人和安全失败分类；不返回 YAML、复核意见、kubeconfig、令牌或 Kubernetes 原始错误。
- `POST /devops/api/prometheus-rule-revisions/<id>/submit/`
  - 仅草稿创建人可以提交待复核。需要 K8s 集群模块管理员权限。
- `POST /devops/api/prometheus-rule-revisions/<id>/review/`
  - JSON：`{"decision":"approve|reject","comment":"可选"}`。创建人不能复核自己的修订；复核仅更新数据库状态，不会连接 Kubernetes。复核记录为追加式，不能被 API 修改。
- `POST /devops/api/prometheus-rule-revisions/<id>/publish/`
  - 仅已批准修订可发布，且创建人不能发布自己的修订。发布前重新读取目标资源并比较基准 `resourceVersion`；发现漂移或 Kubernetes 409 时将修订标记为 `failed`，返回 `409/conflict`，不会自动重试或覆盖。
  - 成功后状态为 `published`。审计仅记录安全身份、动作、结果和资源版本，不记录 YAML、kubeconfig、令牌或 Kubernetes 原始错误。
- `POST /devops/api/prometheus-rule-revisions/<id>/restore/`
  - 仅已发布且带期望 YAML 的历史修订可恢复。恢复会以当前集群资源版本生成新的更新草稿（`202`），绝不修改旧修订，并再次经过提交、双人复核和独立发布流程。
- `GET /devops/api/service-topology/`
  - 返回服务、负责人、环境、描述、当前用户可见的关联主机及上游依赖。
  - 认证：需要 session 登录和服务管理模块只读权限；未登录返回 `401`，权限不足返回 `403`。
  - 主机范围：仅返回无关联主机的服务，或关联至少一台当前用户可见主机的服务；主机字段不会返回密码、私钥或其他凭据。上游依赖仅在依赖服务同样可见时返回。
- `GET /devops/api/service-slos/`
  - 返回当前用户主机范围内服务的 SLO 配置和安全评估摘要。
  - 认证：需要 session 登录和服务管理模块只读权限；未登录返回 `401`，权限不足返回 `403`。
  - 返回 `service`、`metric_kind`（仅 `availability`、`latency`、`error_rate`）、目标、窗口、启用状态、`last_state`（`healthy`、`exhausted`、`unavailable`）及安全摘要。
  - 安全：不返回 Prometheus 地址、查询语句、原始响应、标签、样本或凭据。
- `POST /devops/api/service-slos/`
  - JSON：`service`、`metric_kind`、`target`、`window_minutes`、`enabled`。指标类型仅支持 `availability`、`latency`、`error_rate`；目标与窗口由服务端范围校验。
  - 权限：需要安全策略模块管理员权限；服务必须在当前主机授权范围内。成功返回 `201` 和安全 SLO 摘要，创建操作记录摘要审计。
- `POST /devops/api/service-slos/<id>/update/`
  - 更新同一授权范围内的 SLO 配置；需要安全策略模块管理员权限。只接受受限的服务、指标类型、目标、窗口和启用状态，不接受 PromQL 或指标标签表达式。
- `POST /devops/api/service-slos/<id>/evaluate/`
  - 手动刷新同一授权范围内 SLO 的安全状态摘要；需要安全策略模块管理员权限。仅记录状态审计，不返回查询语句或原始 Prometheus 数据。
- `GET /devops/api/service-slos/<id>/burn-summary/`
  - 返回当前主机范围内服务 SLO 的本地错误预算燃尽摘要，需要服务管理模块只读权限。仅可用性和错误率 SLO 在有新式历史快照时返回预算剩余比例与固定短/长窗口燃尽率；延迟 SLO 和旧历史记录统一返回 `unavailable`。
  - 不返回 PromQL、原始指标值、样本、标签、历史摘要、主机、凭据或外部地址。接口只读取本地 SLO 评估历史，不调用 Prometheus，不写入数据库。
- `GET /devops/api/deployments/<id>/impact-preview/?batch_size=<n>`
  - 返回已授权发布的服务级影响模拟，需要发布部署和服务管理模块只读权限，且发布全部主机必须在当前用户范围内。`batch_size` 可选，`0` 或缺省表示全量一批。
  - 成功仅返回风险等级、授权服务/主机数量、候选批次数、活动严重告警/开放事件/耗尽 SLO/不健康发布/失败 CI 的固定计数和固定建议；不创建发布、审批、任务或远程操作，也不返回脚本、主机、CI 仓库、版本、日志或凭据。
- `GET /devops/api/gitops-service-impacts/`
  - 需要 K8s 集群和服务管理模块只读权限。仅将已漂移且已绑定到当前用户可见服务的 Deployment、StatefulSet、DaemonSet 工作负载汇总为服务级风险；未映射资源不会出现在结果中。
  - 返回服务 ID/名称、公开关键等级、漂移工作负载数量、依赖数量、风险与固定建议；不返回集群地址、清单、命名空间、资源名、哈希、kubeconfig 或凭据。接口只读取本地记录，不连接 Kubernetes 或执行修复。
- `GET /devops/api/runbooks/`
  - 返回当前用户主机范围内、已明确绑定主机的运行手册安全摘要。需要命令模块只读权限。
  - 返回 ID、名称、版本、触发类型、关联服务、启用和审批标记；不返回固定命令、命令输出、主机凭据或审批命令正文。
- `POST /devops/api/runbooks/` 和 `POST /devops/api/runbooks/<id>/update/`
  - 创建或更新版本化运行手册。需要安全策略模块管理员权限，关联服务和允许主机必须在当前主机范围内。
  - 命令只接受固定单行文本，拒绝花括号插值、Shell 替换、反引号、换行和调用方参数；运行手册始终要求审批。创建和更新写入摘要审计。
- `POST /devops/api/runbooks/<id>/initiate/`
  - JSON：`{"host_id": 1}`。需要命令模块运维操作权限，目标主机必须同时位于当前主机范围、运行手册允许主机和关联服务范围内。
  - 成功返回 `202`，创建待执行 `CommandExecution` 和 `ApprovalRequest.TYPE_COMMAND`；审批前不连接 SSH。批准后仅复用既有命令 Worker，不创建新的作业类型。AIOps 只提供运行手册 ID 和管理页链接，不能调用此接口或排队执行。
- `GET /devops/api/runbook-executions/<id>/effectiveness-feedback/`
  - 读取已批准运行手册执行记录的效果反馈。需要命令模块只读权限，执行记录主机必须在当前用户授权范围内。
  - 仅返回反馈 ID、运行手册 ID/名称/版本、分类（`effective`、`partial`、`ineffective`）、安全备注、提交人和时间；不返回命令模板、执行命令、输出或错误。
- `POST /devops/api/runbook-executions/<id>/effectiveness-feedback/`
  - JSON：`{"classification":"effective|partial|ineffective","note":"可选，最多 300 字符"}`。需要命令模块运维操作权限，且记录必须是已批准的受控运行手册执行记录并在当前主机范围内。
  - 该接口只追加效果反馈与审计记录，不会执行命令、重新运行手册或改变审批状态；备注中的 URL、密文和敏感键值会被脱敏后保存。
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

## AIOps 诊断证据

- `GET /aiops/api/diagnostic-evidence/?host_id=<id>&window=6h|24h`
  - 只读主机诊断证据包。需要 session 登录；`host_id` 必须是当前用户通过主机范围授权可见的主机。主机不存在或越权统一返回 `404`；无效主机 ID 或时间窗口返回 `400`。
  - 调用方至少需要以下任一个模块的只读权限：告警治理、监控历史、命令执行、发布部署。缺少某个模块权限时，该模块拥有的类别会被省略，而不是返回未授权数据。
  - 权限映射：告警与事件使用告警治理权限，指标状态使用监控历史权限，失败命令使用命令执行权限，发布健康与 CI 投递使用发布部署权限。
  - 成功仅返回选择的 `host_id`、窗口边界和受限 `evidence[]` 元数据：固定类别、记录 ID、等级/状态、受限摘要、时间及安全关联 ID。不会返回告警正文、事件描述、命令/输出/错误、原始指标值、发布脚本、主机凭据、CI 原始载荷或外部地址。
- `GET /aiops/api/alert-groups/?window=6h|24h`
  - 需要 session 登录和告警治理模块只读权限；仅按当前用户可见主机聚合 `open`、`processing`、`silenced` 告警。
  - 返回受限公开指标类别（未知类别统一为 `other`）和标准等级（非标准等级统一为 `unknown`）组成的组键、受影响主机数、活动与静默数量、累计重复次数、关联事件状态和固定建议；不返回告警正文、备注、指纹、原始指标或等级、主机 IP、事件标题或任何凭据。
  - 该接口只读：不会创建事件、更新告警、发送通知或调用外部系统。
  - 该接口只查询本地持久化证据；不会写入数据库、调用 SSH、命令、LLM、Prometheus、CI、云服务或其他网络服务。
- `GET /aiops/api/signal-freshness/?window=6h|24h`
  - 需要 session 登录和监控历史模块只读权限，仅检查当前用户主机范围内 CPU、内存和磁盘信号的本地最新观测。
  - `results[]` 最多返回 50 项，按 `absent`、`stale`、`partial`、`healthy` 的运维紧急度及主机 ID 稳定排序。每项仅含主机显示名称、状态、三个固定指标的 `fresh`、`stale`、`missing` 状态及对应计数；不返回指标值、单位、采样时间、IP 或凭据。
  - 一小时内的观测为新鲜；没有任何观测为 `absent`，全部已知观测过期为 `stale`，部分缺失或过期为 `partial`，三个类别都新鲜为 `healthy`。
  - 不返回指标值、原始采样、主机 IP、凭据、采集源或原始时间戳。接口只查询本地数据库，不采集指标、不写入数据库，也不调用 SSH、LLM、Prometheus 或其他网络服务。
- `GET /aiops/api/service-impacts/?window=6h|24h`
  - 只读服务影响摘要。需要 session 登录和服务管理模块只读权限；服务与关联主机均按当前用户主机范围过滤，仅保留至少关联一台可见主机的服务以及无关联主机的目录服务。
  - `results[]` 最多返回 32 项，包含安全服务 ID/名称、公开关键等级、可见主机数、受影响主机数、可见上游依赖数、活动告警/开放事件/耗尽 SLO/不健康发布/失败 CI 的固定计数、受限状态和固定建议。
  - 发布与 CI 证据只在服务关联且至少部署到可见服务主机时计入；发布健康还必须匹配可见主机批次。接口不返回主机 IP、告警正文、事件描述、SLO 查询、部署脚本或摘要、CI 仓库/版本/摘要、凭据或外部地址。
  - 接口只查询本地数据库，不会创建或更新告警、事件、发布、SLO、审批或通知，也不会调用 SSH、CI、LLM、Prometheus 或其他网络服务。
- `GET /aiops/api/service-workbench/<service_id>/?window=6h|24h`
  - 只读服务事件工作区。需要 session 登录和服务管理模块只读权限；`service_id` 必须同时位于当前可见服务目录和主机授权范围，服务不存在或越权统一返回 `404`。
  - 返回服务 ID/名称、固定证据计数和状态，以及最多 8 条开放/处理中事件的 ID、状态、负责人、SLA 时间，和最多 8 条关联发布的 ID、发布状态、受限健康状态和观测时间。关联发布必须至少部署到一台可见服务主机；发布健康还必须属于可见主机批次。
  - 不返回事件标题、描述、时间线备注、主机 IP、告警正文、发布脚本或摘要、CI 仓库/版本/摘要、命令、凭据、外部地址或原始载荷。接口无写入、无自动轮询、无 SSH/CI/LLM/Prometheus 或其他外部调用。

## 监控、告警、审批

- `GET /devops/api/metrics/?host=1&range=24h`
  - `range` 支持 `6h`、`24h`、`7d`、`30d`。
  - 返回 `labels` 和 `series.cpu/memory/disk`。
  - `host` 必须在当前用户可见主机范围内；未指定时默认选择第一个可见主机。
- `GET /devops/api/capacity-forecast/`
  - 需要 session 登录和监控历史模块只读权限，仅计算当前用户可见主机的 CPU、内存、磁盘历史采样。
  - 未登录返回 `401` 和 `{"ok": false, "code": "unauthorized", "message": "..."}`；权限不足返回 `403` 和 `{"ok": false, "code": "forbidden", "message": "..."}`。
  - 每项仅返回 `host.id`、`host.name`、`metric`、`state`、`sample_count`，以及风险状态下正整数 `days_to_threshold`。状态为 `risk`、`stable` 或 `insufficient_data`。
  - `days_to_threshold` 是风险日桶：`1` 表示当前最后观测值或当前趋势估计已经达到阈值，或预计在未来 24 小时内达到，并不表示还需等待一天；大于 `1` 表示预测将在对应天数内达到。
  - 使用最近 30 天去重后的有效采样进行最小二乘每日趋势估算；原始比例先归一化为百分比，归一化后不在 `0..100`（含）范围内的值无效。少于 3 个不同时间点、无效值或不可计算趋势均为 `insufficient_data`。预测最多展示 50 台主机，每项最多预测 365 天。
  - 不返回采样值、时间戳、原始监控响应、标签、来源 URL、主机 IP、凭据或其他敏感字段。
- `POST /devops/api/capacity-cost-simulation/`
  - 只读变更仿真。JSON 必须包含 `cpu_delta_percent`、`memory_delta_percent`（均为 `-50..100` 的整数或整数字符串）和 `instance_delta`（`-10..20` 的整数或整数字符串）。
  - 认证：需要 session 登录，并同时具备监控历史模块和服务管理模块的运维操作权限；未登录返回 `401`，任一模块权限不足返回 `403`。
  - 主机范围：只读取当前用户可见主机的最新 CPU/内存采样，以及关联到当前可见服务的本地云成本摘要。
  - 成功仅返回 `capacity.baseline_risk`、`capacity.projected_risk`、聚合 `sampled_host_count`，以及按 `currency` 分隔的 `baseline_daily`、`projected_daily`、`delta_daily` 成本汇总。风险为 `unknown`、`low`、`medium` 或 `high`。
  - 安全：不返回主机、服务、资源、云账号、标签、成本明细、采样值、IP、凭据或资源标识；接口不保存仿真、不调用云厂商/网络、不执行 SSH 或命令。
- `GET /devops/api/alerts/?limit=50`
  - 告警记录列表，仅返回当前用户可见主机上的告警和无主机关联的全局告警。
- `GET /devops/api/incidents/?limit=50`
  - 事件工单列表。需要告警模块只读权限；仅返回事件本身及其告警、命令、发布引用全部处于当前主机授权范围内的记录。
  - 返回引用的安全摘要和复盘字段，不返回命令输出、错误文本、主机凭据或密钥。
- `POST /devops/api/incidents/`
  - 创建事件。需要告警模块运维操作权限。
  - JSON：`title`、`severity`（`low`/`medium`/`high`/`critical`）、可选 `description`、`host_id`、`alert_id`、`deployment_release_id`、`command_execution_id`。
  - 所有主机关联引用必须在当前授权范围内；越权返回 `403` 和 `code: "host_forbidden"`。
- `GET /devops/api/incidents/<id>/`
  - 事件详情和时间线。不可见或不存在统一返回 `404`。
- `GET /devops/api/incidents/<id>/postmortem-draft/`
  - 仅已解决或已关闭的、当前用户可见的事件可生成复盘草稿，需要告警治理模块只读权限。返回安全事件 ID/严重度/状态、关联证据计数，以及固定的影响、根因、处置和跟进行动填写提示。
  - 草稿不写入数据库，也不回显事件标题、描述、时间线正文、根因、处置、命令、输出、发布脚本、主机或凭据；保存正式复盘仍必须使用既有受控接口。
- `POST /devops/api/incidents/<id>/timeline/`
  - 追加时间线备注。需要告警模块运维操作权限，JSON：`{"note": "..."}`。
- `POST /devops/api/incidents/<id>/status/`
  - 更新状态，JSON：`{"status": "open|processing|resolved|closed"}`。解决时记录解决时间。
- `POST /devops/api/incidents/<id>/postmortem/`
  - 为已解决或已关闭事件记录复盘，JSON：`root_cause`、`resolution`、`follow_up`。创建、时间线、状态和复盘变更均写入审计日志。
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

### CI 发布门禁

- `POST /devops/api/ci-deliveries/<provider>/`
  - 仅支持 `jenkins` 与 `gitlab`。请求头必须包含 `X-CI-Signature: sha256=<hex>`，其中 `<hex>` 是使用 provider 对应 `*_CI_WEBHOOK_SECRET` 对原始请求体计算的 HMAC-SHA256。
  - 请求只接受 `repository`、`status`、`delivery_id`、可选 `revision`；状态仅允许 `pending`、`running`、`success`、`failed`、`canceled`、`skipped`。包含 token、URL、日志或命令等字段的请求会被拒绝。
  - 重复投递按 provider、仓库和投递 ID 的摘要幂等处理。安全摘要可驱动已关联发布的质量门禁，但回调本身不会执行 SSH、不会绕过审批，也不会直接运行部署。
  - 安全：不保存原始请求体、签名、webhook URL、令牌、构建日志、命令、制品凭据或 CI 页面 URL。
- `GET /devops/api/ci-deliveries/`
  - 已启用时只返回 CI provider、仓库、状态、修订摘要、关联发布 ID、接收时间和安全摘要。前端在端点未部署或无权限时不显示门禁标签页。

- `GET /devops/api/deployments/?limit=50`
  - 发布记录列表，仅返回包含当前用户可见主机的发布；`host_count` 只统计当前用户可见主机数量。
  - 创建发布时，关联服务的已启用 SLO 若为 `exhausted`，平台会创建或复用待处理的发布审批而不入 Worker 队列；`unavailable` 不改变既有发布路径，也不会自动回滚或执行 SSH。
- `GET /devops/api/maintenance-windows/`
  - 维护窗口日历。需要安全策略模块管理员权限；返回名称、时间、启用状态及当前用户授权范围内的主机和服务摘要。
  - 不返回主机凭据、服务配置、发布脚本或通知密钥。发布命中启用中的维护窗口时，平台会创建或复用待处理的发布审批，不能直接执行。
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
- `GET /devops/api/integrations/health/`
  - GitHub 入站投递与通知渠道的只读健康汇总。
  - 认证：需要 session 登录；未登录返回 `401` 和 `code: "unauthorized"`。
  - 权限：当前没有独立的集成模块，使用安全策略模块管理员权限，即 `DevOpsRole.ROLE_ADMIN` + `DevOpsModulePermission.MODULE_SECURITY`；权限不足返回 `403` 和 `code: "forbidden"`。
  - 成功返回 `github_inbound`（当前状态、最近检查、连续失败和近期计数）、`prometheus[]`、`alertmanager[]`（配置 ID、名称、启用状态和安全健康摘要）及 `notifications[]`（渠道 ID、名称、类型、成功/失败计数、最近时间和失败分类）。
  - 安全：不返回 GitHub payload、签名、投递 ID、仓库或提交信息；不返回 Prometheus/Alertmanager URL；通知汇总不返回 webhook URL、密钥、内容或响应文本。
- `GET /devops/api/worker/`
  - Worker 队列的只读观测汇总。需要 session 登录和安全策略模块管理员权限；未登录返回 `401`，权限不足返回 `403`。
  - 成功返回 `worker.summary`（等待、执行中、累计成功/失败、超时、近一小时完成/失败及失败率）和 `worker.thresholds`（待处理、失败率、超时三个阈值的当前值、启用阈值与触发状态）。
  - 安全：不返回任务 ID、目标对象、输入、角色、异常文本、任务错误、配置原始值、主机信息或任何凭据；接口不领取、重试、取消任务，也不写入告警状态。

## 漏洞与 GitOps 发现

- `GET /devops/api/vulnerabilities/`
  - 需要 session 登录、安全策略模块只读权限，并按当前用户可见主机范围过滤。
  - 返回 `id`、`host_id`、`package_name`、`advisory_id`、`severity`、`status`、`last_seen_at`；不返回软件包版本清单、命令输出、扫描请求或凭据。
  - 该接口只读，不能触发漏洞扫描、软件下载、补丁或远程命令。
- `GET /devops/api/gitops-drift/`
  - 需要 session 登录和 K8s 集群模块只读权限。
  - 返回固定资源身份、期望与观测 SHA-256 摘要、状态和最近发现时间；不返回 YAML、Git 仓库地址、kubeconfig、令牌或 Kubernetes 原始响应。
  - 该接口只读，不能拉取 Git、连接 Kubernetes 或应用修复。PrometheusRule 的修复仍必须使用已有草稿、双人复核和发布流程。

## 服务 CMDB 与云成本中心

- `GET /devops/api/service-catalog/`
  - 需要 session 登录和服务管理模块只读权限；仅返回当前主机范围内的服务及未绑定主机的全局服务。
  - 返回服务负责人、环境、生命周期、关键等级、可见主机和已授权的上下游依赖；不返回主机凭据。
- `GET /devops/api/cloud-resources/` 和 `GET /devops/api/cloud-costs/`
  - 需要 session 登录和安全策略模块只读权限，并按关联服务的主机范围过滤。
  - 仅返回云服务商、资源类型/标识、区域、标签 SHA-256 摘要与每日费用汇总。不会返回标签值、账单明细、账号、Token、密钥或 provider URL。
  - 这两个接口只读，不能轮询云服务商、创建/删除资源或执行成本回收。受控导入程序必须先调用服务层输入校验并只写入摘要。

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
