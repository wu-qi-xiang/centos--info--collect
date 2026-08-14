# AIOps 统一调查工作台设计

## 目标

为现有 AIOps 增加一个 host-scoped 的调查工作台，将告警、指标、事件、发布、CI、SLO 和服务拓扑证据组织成可追溯的调查结果，输出根因候选、置信度和建议动作；第一阶段只做本地规则分析和只读聚合，不自动执行远程操作。

## 范围

### 包含

- 创建和查询调查任务，调查任务关联可见主机、可选服务和时间窗口。
- 统一调查时间线，按来源、时间、严重程度和关联资源展示安全摘要。
- 聚合现有告警、MetricSample、Incident、DeploymentRelease、CIDelivery、ServiceSlo、DeploymentHealthEvaluation 和 ServiceDependency 数据。
- 输出确定性的根因候选、证据引用、置信度、影响范围和建议下一步。
- 新增只读 JSON API 和 AIOps 工作台调查页签。
- 沿用 `visible_hosts_for_request`、模块权限和现有 DevOps 审批边界。

### 不包含

- 不执行 SSH、kubectl、发布、回滚、运行手册或其他远程命令。
- 不直接调用外部 LLM、Kubernetes、Loki、Tracing、Jenkins 或 GitLab。
- 不复制告警原文、命令输出、凭据、Webhook、LLM 原始响应或外部请求体。
- 不改变现有告警生命周期、发布状态机和审批流程。

## 核心模型

新增 `AiopsInvestigation` 持久化调查记录，字段包括：创建人、状态、标题、时间窗口、主机范围、可选服务、风险等级、根因候选摘要、置信度、创建/更新时间。主机和服务使用现有关系，调查记录不保存原始证据正文。

调查结果由服务层实时生成，包含：

- `summary`：安全摘要和影响范围。
- `timeline`：有界证据项，每项只有 `kind`、`occurred_at`、`severity`、`resource`、`summary` 和稳定引用 ID。
- `root_causes`：候选原因、置信度、证据引用列表和建议。
- `scope`：可见主机数、服务数和时间窗口。
- `partial` / `errors`：单个数据源失败时保留部分结果，只返回固定错误分类。

## 分析规则

1. 按主机和时间窗口收集活动告警、指标异常、开放事件、发布/CI 失败和 SLO 耗尽状态。
2. 使用现有服务拓扑将同一时间窗口内的上游证据传播到下游服务，但不扩大用户主机权限范围。
3. 近期发布与异常时间重叠时，提高发布相关根因候选的置信度；没有充分证据时标记为低置信度，而不是断言确定根因。
4. 排序稳定、结果有界，保证相同输入得到相同结果，便于测试和审计。

## 权限与安全

- 调查列表、详情和证据 API 至少需要 AIOps 查看权限。
- 目标主机必须来自 `visible_hosts_for_request(request)`；服务必须来自现有可见服务查询。
- 不允许通过调查 ID、主机 ID 或服务 ID 枚举越权对象；无权对象统一返回安全的 not found 响应。
- 调查创建和刷新为只读分析操作，不创建审批、任务、审计或通知记录。
- 序列化层只允许白名单字段，禁止输出 `raw_payload`、`llm_response`、命令、密码、密钥、Webhook 和 URL。

## API 与页面

- `GET /aiops/api/investigations/`：列出当前用户可见调查摘要。
- `POST /aiops/api/investigations/`：创建只读调查记录并返回初次分析摘要。
- `GET /aiops/api/investigations/<id>/`：返回调查范围、时间线、根因候选和错误分类。
- AIOps 工作台新增“调查”页签，保留现有异常、关联、根因、容量和运行手册页签。
- 页面必须提供加载、空数据、部分失败和权限错误状态；不引入远程 CDN。

## 验收标准

- 可见用户只能创建和读取授权主机范围内的调查。
- 调查结果包含告警、事件、发布、CI、SLO 和指标证据的安全摘要及稳定引用。
- 至少覆盖“发布后异常”“严重告警聚集”“SLO 耗尽”三类根因候选规则。
- 隐藏主机证据、原始告警正文和敏感字段不会进入 API、页面、日志或调查记录。
- 单个数据源查询失败不会导致整份调查失败，并返回固定错误分类。
- AIOps 专项测试、迁移检查、Django check、JavaScript 语法检查和 `git diff --check` 全部通过。

## 后续扩展

调查服务层预留只读 toolset 接口，后续可按权限接入 Kubernetes Analyzer、Loki/ES、Tracing、Jenkins/GitLab 和主动巡检 Operator；所有修复动作继续复用现有 DevOps 审批与执行服务。
