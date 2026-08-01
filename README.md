# CentOS Info Collect / 运维管理平台

这是一个基于 Django 4.2.16 和 Python 3.11 的服务器资产、监控告警和 DevOps 自动化管理项目。项目保留了原有业务结构和兼容逻辑，当前版本已扩展为面向小团队运维场景的综合控制台。

## 当前功能

- 用户登录、注册、退出，兼容旧明文密码并在登录后升级为哈希密码。
- 服务器资产管理：新增、编辑、删除、搜索、分页、连接测试、WebSSH。
- SSH 认证：支持密码和 SSH Key，敏感凭据加密存储。
- 本机和远程主机基础信息采集。
- 监控告警：CPU、内存、磁盘阈值配置，定时采集，邮件告警，告警恢复记录和周期性 SLO 评估。
- 密码管理：按当前登录用户隔离账号密码记录，支持加密存储和按需查看。
- DevOps 控制台：主机分组、标签、命令执行、批量任务、服务管理、文件分发、发布部署、发布前风险预览、回滚、审批流、通知渠道、审计日志、监控历史和容量预测。
- 权限控制：全局角色、模块权限、主机范围授权。
- 部署基础：环境变量配置、Dockerfile、Compose、Gunicorn 配置、审计日志清理命令。

## 本地运行

开发、CI 和容器运行时统一使用 Python 3.11，依赖固定为 Django 4.2.16。请不要以 Django 2.1 或其他 Python 主版本运行本项目；`python manage.py check --deploy` 会验证生产环境的运行基线。

```bash
python3.11 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
python manage.py migrate
python manage.py runserver 0.0.0.0:8000
```

访问 `http://127.0.0.1:8000/`，先注册用户再登录。

## 配置项

生产环境不要使用默认密钥。可以参考 `.env.example` 配置：

- `DJANGO_SECRET_KEY`
- `DATA_ENCRYPTION_KEY`
- `DJANGO_DEBUG`
- `DJANGO_ALLOWED_HOSTS`
- `DB_ENGINE` / `DB_NAME` / `DB_USER` / `DB_PASSWORD` / `DB_HOST` / `DB_PORT`
- `EMAIL_HOST` / `EMAIL_PORT` / `EMAIL_HOST_USER` / `EMAIL_HOST_PASSWORD`
- `DEVOPS_TASK_RETRY_COUNT`
- `DEVOPS_WORKER_POLL_SECONDS`
- `DEVOPS_WORKER_MAX_ATTEMPTS`
- `DEVOPS_WORKER_JOB_TIMEOUT_SECONDS`
- `DEVOPS_SCHEDULER_POLL_SECONDS`
- `DEVOPS_SCHEDULER_LEASE_SECONDS`
- `DEVOPS_SCHEDULER_MONITOR_INTERVAL_SECONDS` / `DEVOPS_SCHEDULER_ALERTMANAGER_INTERVAL_SECONDS` / `DEVOPS_SCHEDULER_ONCALL_INTERVAL_SECONDS` / `DEVOPS_SCHEDULER_SERVICE_SLO_INTERVAL_SECONDS` / `DEVOPS_SCHEDULER_COMPLIANCE_INTERVAL_SECONDS`
- `DEVOPS_SSH_CONNECT_TIMEOUT_SECONDS`
- `DEVOPS_COMMAND_TIMEOUT_SECONDS`
- `DEVOPS_COMMAND_OUTPUT_MAX_BYTES`
- `WEBSSH_SESSION_TIMEOUT_SECONDS`
- `AUDIT_LOG_RETENTION_DAYS`
- `METRIC_SAMPLE_RETENTION_DAYS`
- `AIOPS_ANALYSIS_RETENTION_DAYS`
- `K8S_CACHE_DIR`
- `K8S_DETAIL_CACHE_TIMEOUT_SECONDS`
- `BACKUP_S3_BUCKET` / `BACKUP_S3_PREFIX` / `BACKUP_S3_ENDPOINT_URL` / `BACKUP_S3_REGION`
- `BACKUP_S3_ACCESS_KEY_ID` / `BACKUP_S3_SECRET_ACCESS_KEY` / `BACKUP_S3_SESSION_TOKEN` / `BACKUP_S3_VERIFY_SSL`
- `EXTERNAL_AUTH_ROLE_MAP`
- `OIDC_DISCOVERY_URL` / `OIDC_CLIENT_ID` / `OIDC_CLIENT_SECRET` / `OIDC_REDIRECT_URI`
- `LDAP_SERVER_URI` / `LDAP_BIND_DN` / `LDAP_BIND_PASSWORD` / `LDAP_BASE_DN` / `LDAP_USER_FILTER` / `LDAP_GROUP_ATTRIBUTE` / `LDAP_STARTTLS`

生产模式由 `DJANGO_ENV=production` / `prod` 或 `DJANGO_DEBUG=False` 触发。运行 `python manage.py check --deploy` 会检查生产关键配置：

- `DJANGO_DEBUG` 必须关闭。
- `DJANGO_SECRET_KEY`、`DATA_ENCRYPTION_KEY` 不能使用默认或空值。
- `DJANGO_ALLOWED_HOSTS` 不能使用 `*`。
- 生产环境不应使用 SQLite，应配置 MySQL 或 PostgreSQL。
- `DEVOPS_WORKER_POLL_SECONDS`、`DEVOPS_WORKER_MAX_ATTEMPTS`、`DEVOPS_WORKER_JOB_TIMEOUT_SECONDS`、所有 `DEVOPS_SCHEDULER_*_SECONDS`、`DEVOPS_SSH_CONNECT_TIMEOUT_SECONDS`、`DEVOPS_COMMAND_TIMEOUT_SECONDS`、`DEVOPS_COMMAND_OUTPUT_MAX_BYTES`、`WEBSSH_SESSION_TIMEOUT_SECONDS`、`NOTIFICATION_TIMEOUT_SECONDS` 必须为正整数。
- `AUDIT_LOG_RETENTION_DAYS`、`METRIC_SAMPLE_RETENTION_DAYS`、`AIOPS_ANALYSIS_RETENTION_DAYS` 不能为负数；设置为 `0` 表示不按保留天数清理，生产环境会给出警告。
- 外部 OIDC/LDAP 认证可独立启用；启用来源必须完整配置，组到 `viewer`、`operator`、`admin` 的映射必须有效。OIDC discovery 和回调地址必须使用 HTTPS，回调主机必须在 `DJANGO_ALLOWED_HOSTS` 中；LDAP 必须使用 LDAPS 或 StartTLS。
- 启用 S3 兼容异地备份时，桶、对象前缀和 TLS 验证必须有效；自定义端点必须使用 HTTPS。备份加密复用 `DATA_ENCRYPTION_KEY`，不配置独立备份密钥。

外部认证配置、角色映射和上线检查见 [外部认证说明](docs/external_auth.md)。本地账号密码登录始终保留为回退方式。

## K8s 查询缓存

K8s 集群详情查询结果使用本地文件缓存，默认目录为 `<BASE_DIR>/.cache/k8s`，默认有效期为 `86400` 秒。首次查询会访问集群，后续查询优先读取缓存；页面主动刷新时会重新访问 K8s API 并覆盖缓存。

- `K8S_CACHE_DIR`：缓存目录，可使用绝对路径；相对路径按项目根目录解析。运行用户必须具有目录写权限。
- `K8S_DETAIL_CACHE_TIMEOUT_SECONDS`：缓存有效期，必须为正整数。

缓存只保存页面展示所需的安全资源摘要，不应包含 kubeconfig、访问令牌、客户端证书或 Secret 原文。容器内默认目录会随容器销毁而丢失；如需跨进程重启或容器重建保留缓存，应将 `K8S_CACHE_DIR` 指向持久化挂载目录。

## K8s 服务发现

K8s 服务发现仅只读扫描所选集群和命名空间中的 Deployment、StatefulSet、DaemonSet，需同时具备集群模块和服务模块管理员权限。发现结果必须由管理员显式关联到已有 `ServiceCatalog`；功能不会自动创建或覆盖服务目录记录。部署前执行 `python manage.py migrate`，以应用工作负载服务映射迁移 `devops.0030_k8sworkloadservicemapping`。

## DevOps 后台任务

命令执行、批量任务、文件分发、发布部署和回滚会写入数据库队列，由独立的 `python manage.py devops_worker` Worker 执行；测试环境仍由 `DEVOPS_SYNC_TASKS` 同步执行。Worker 使用持久化任务和原子领取语义，Web 服务重启不会丢失已入队工作；重复触发已领取或已有结果的任务不会再次产生远程执行记录。

- `DEVOPS_WORKER_POLL_SECONDS`：Worker 轮询新任务的间隔，默认 `1` 秒。
- `DEVOPS_WORKER_MAX_ATTEMPTS`：失败任务的最大尝试次数，默认 `1`；对 SSH、文件分发和发布等可能已部分执行的远程操作，默认不自动重放。
- `DEVOPS_WORKER_JOB_TIMEOUT_SECONDS`：单个任务的执行时限，默认 `300` 秒。

SQLite 部署只需启动一个 Worker；多个 Worker 需要使用支持并发的数据库，并依赖队列的持久化原子领取机制防止同一工作被重复执行。

## 平台健康与恢复

- `GET /health/live/`：公开存活探针，不访问数据库，仅返回固定存活状态。
- `GET /health/ready/`：公开就绪探针，仅检查数据库可用性；故障时只返回通用未就绪状态。
- `GET /runtime/status/`：仅已登录的 DevOps 管理员可访问，返回数据库状态和主机、活动告警、待审批、排队工作的聚合数量，以及 Worker 队列的状态总数、超时数量、近期完成/失败指标；不返回配置、路径、任务 ID、输入、异常、密钥或其他敏感数据。
- `GET /metrics/`：仅已登录的 DevOps 管理员可访问的 Prometheus 文本端点，仅输出后台队列、外部集成健康事件和（调度模型已部署时）调度任务的状态聚合计数；不输出主机、任务 ID、路径、命令、请求内容、异常、配置、URL 或凭据。请使用具备该会话权限的受控抓取方式，不要将端点公开给匿名 Prometheus 实例。

数据库和 `uploads/` 的备份、仅限本地的恢复演练步骤见 [运行恢复手册](docs/runtime_recovery.md)。恢复演练只验证明确指定的本地归档并写入空隔离目录；它不会下载 S3 归档或访问生产服务。

## 监控数据保留

远程监控采集会写入 `MetricSample` 指标样本，用于 DevOps 监控历史和 AIOps 容量分析。`METRIC_SAMPLE_RETENTION_DAYS` 控制样本保留天数，默认 `30` 天；设置为 `0` 表示不自动清理。定时监控任务每次运行后会清理超过保留期的指标样本，不删除告警事件、告警历史或审计日志。服务 SLO 每五分钟保存一次仅含状态和摘要的评估历史；`SERVICE_SLO_EVALUATION_RETENTION_DAYS` 控制其保留期，默认 `90` 天，必须为正整数，定时评估后会自动清理超期记录。

Alertmanager 接入只保留告警名称、级别、实例、允许的服务标签和经过净化的摘要，不保存原始 webhook 请求或大模型原始响应。P0 迁移会不可逆地清除已有原始告警、提供方响应和历史分析文本；生产操作员必须在迁移前按既有恢复流程完成受控备份。`AIOPS_ANALYSIS_RETENTION_DAYS` 控制分析记录保留天数，默认 `90` 天；设置为 `0` 表示不自动清理。可通过 `python manage.py cleanup_aiops_analyses` 清理超期记录，命令仅输出删除数量。

## 监控对接

监控对接支持配置多个带名称的 Prometheus 实例、Alertmanager 基础 URL 和连接测试，监控管理与监控对接页面按类型提供两个连接选择框。仅运维员可以创建、更新、删除或测试对接；“指标查询”页面可通过连接名称下拉框选择已启用且可用的 Prometheus 对接，默认仍选择首个可用连接以兼容旧行为。即时 PromQL 查询会将向量、矩阵、标量或字符串结果统一展示为表格，单次响应最多展示 500 行，同时保留完整结果行数用于提示。页面也可只读查看所选连接的活动 Targets 和 Rules，结果经过字段规范化与敏感标签过滤，并采用相同的 500 行展示上限和完整总数提示。飞书或企业微信告警通知保存成功后会进入“告警列表”；列表仅展示名称、类型、启用与配置状态和更新时间，不展示 Webhook。

## 定时监控

完成 `python manage.py migrate` 后，推荐启动持久化调度器：

```bash
python manage.py devops_scheduler
python manage.py devops_scheduler --once
```

调度器为监控采集、Alertmanager 轮询、值班升级、SLO 评估和合规扫描维护数据库租约及无敏感的状态摘要。默认轮询间隔为 `5` 秒；各任务默认间隔分别为 `60`、`60`、`60`、`300` 和 `86400` 秒。`DEVOPS_SCHEDULER_LEASE_SECONDS` 默认 `600` 秒，生产值应大于最长一次任务的预期持续时间；租约超时后任务可能重新执行，因此现有任务必须保持幂等。状态摘要不保存告警正文、请求载荷、命令文本、Webhook 地址或密钥。

`django-crontab` 在一个发布周期内保留为兼容回退。仅在停用 `scheduler` 服务后才执行以下命令，避免两个调度入口并行运行：

```bash
python manage.py crontab add
python manage.py crontab show
python manage.py crontab remove
```

值班升级扫描默认由持久化调度器每分钟运行：命中服务级值班策略的告警先通知主值班人，15 分钟仍未确认时仅向备值班人升级一次。告警确认、关闭、静默或恢复后不会继续升级；未配置服务策略的告警保持原有全局通知路由。回退到 cron 时，再执行 `python manage.py crontab add` 和 `python manage.py crontab show` 确认注册。通知渠道配置和密钥不会写入调度状态或 cron 输出。

服务值班策略可选配置每周主值班轮换成员，按顺序在 `Asia/Shanghai` 时区每周一 `00:00` 选择当前主值班人；固定备值班人保持不变。轮换名单为空时继续使用静态主值班人。部署前执行 `python manage.py migrate`，以应用轮换成员迁移 `devops.0031_serviceoncallrotationmember`。

“服务值班”中的覆盖巡检仅向安全管理员展示当前服务配置风险，例如缺少或停用的值班策略、停用的主备通知渠道、无可用成员的轮换名单和轮换顺序断档。巡检实时只读计算，不创建定时任务、不发送通知、不修改值班策略；它检查数据库配置，不能证明外部通知渠道当前可达。

DevOps“安全策略”页面支持服务运行状态和文件 SHA-256 合规基线。管理员可手动扫描、编辑或删除基线；系统每天 `03:30` 扫描已绑定主机，仅记录漂移或扫描失败，不自动修复。漂移会生成告警，恢复后自动关闭对应告警。

## 企业微信机器人处置入口

企业微信群机器人仅用于出站告警和审批通知，不接收回调、不授予权限、不执行命令。设置 HTTPS `PLATFORM_PUBLIC_BASE_URL` 后，审批通知会附带默认有效期 900 秒的签名跳转链接；访问者仍必须登录，并通过现有审批角色与主机范围校验。`WECOM_APPROVAL_LINK_TTL_SECONDS` 控制链接有效期；未配置公开基址时保持既有纯文本通知。

## 漏洞与 GitOps 发现

漏洞发现 API 和 GitOps 漂移 API 只保存受限资源身份、状态和摘要。漏洞记录仅包含主机、软件包名、公告编号、严重度和状态；GitOps 记录仅包含集群资源身份及期望/观测 SHA-256 摘要。两者不下载 CVE 数据、不保存软件包输出或 YAML、不执行补丁、不访问 Git，也不对 Kubernetes 执行写操作；任何实际导入或修复必须走后续受控适配器、审批和审计流程。

## 目录结构

- `PyLinux/`：Django 项目配置、路由和 WSGI 入口。
- `RemoteLinux/`、`linux/`、`monitor/`、`password/`、`userprofile/`、`devops/`：业务应用。
- `templates/`、`static/`：页面模板和静态资源。
- `deploy/`：Dockerfile、Compose、Gunicorn 和生产依赖文件。
- `docs/`：接口说明、优化记录和页面审计截图。
- `uploads/`、`logs/`：运行期文件目录，不应作为代码依赖。

## Docker / Compose

```bash
docker compose -f deploy/docker-compose.yml run --rm web python manage.py migrate
docker compose -f deploy/docker-compose.yml up --build
```

必须先完成迁移，再启动 Worker 和 scheduler。Compose 会同时启动 `web`、`worker` 和 `scheduler`，三者使用同一数据库、`uploads/` 和 `logs/` 挂载；后台任务命令为 `python manage.py devops_worker`，调度器命令为 `python manage.py devops_scheduler`。本地 SQLite 仅运行一个 Worker 和一个 scheduler。需要回退到 cron 时，先停止 `scheduler` 服务，再执行 `python manage.py crontab add`；恢复持久化调度器时执行 `python manage.py crontab remove` 后重新启动 `scheduler`。

可选的 PostgreSQL + Nginx 生产参考使用 `deploy/docker-compose.production.yml` 作为叠加文件，不会替换以上本地 SQLite 流程，也不会自动启动任何服务。它通过未跟踪的环境文件提供数据库凭据、只由 Nginx 发布 80 端口，并用命名卷共享静态文件；该拓扑刻意不对外提供上传文件，`/uploads/` 没有生产路由。迁移、静态文件收集、`check --deploy`、健康探针、备份预检、Docker Compose 版本要求和回退步骤见 [生产部署参考](docs/production_deployment.md)。

如使用 Kubernetes，参考 `k8s/` 目录内的镜像构建和部署 YAML，并按实际镜像仓库修改镜像地址。

## 开发验证

每次修改后建议执行：

```bash
.venv/bin/python manage.py check
.venv/bin/python manage.py test
```

GitHub Actions 会在 push 和 pull request 时使用 Python 3.11 自动执行 `manage.py check`、迁移一致性检查和完整测试。另有依赖审计与仓库密钥扫描报告作业；它们不会阻断现有测试门禁，且扫描器未预装时只记录跳过结果，不会安装新依赖。

## 运维工作流控制台

`/devops/vue/` 的控制台按当前 session 权限和主机范围加载事件与巡检、服务目录与云成本、CI 发布门禁摘要。没有对应权限、后端未启用或没有记录时，该入口不会展示对应标签页。云资源仅显示资源身份、区域、标签摘要和每日成本；不会显示云账号、标签明文、账单明细或凭据。

Jenkins 与 GitLab 可向 CI 状态入口发送受 HMAC 保护的回调。分别在部署环境中配置 `JENKINS_CI_WEBHOOK_SECRET`、`GITLAB_CI_WEBHOOK_SECRET`，并使用 `X-CI-Signature: sha256=<hex-hmac>` 对原始 HTTP 请求体计算 HMAC-SHA256。平台只接受固定的仓库、修订和状态摘要，拒绝包含令牌、URL、日志或命令字段的请求；不会保存原始请求、签名、日志、凭据或制品信息。回调不会绕过审批，只有已关联且通过质量门禁的发布才可能进入既有发布队列。

发布创建时可设置分批大小。`0` 保持一次性发布；大于 `0` 时每批执行后会根据发布后严重告警、失败命令和当前批次服务的已耗尽 SLO 写入健康摘要。判定不健康会停止后续批次、记录审计并创建或复用回滚审批；平台不会自动执行回滚。AIOps 变更影响页只显示健康状态、分数和固定计数摘要，不显示告警正文、命令、输出或批次中的其他主机信息。

当前测试覆盖包括登录注册、主机权限、SSH 凭据处理、密码管理、监控采集、告警、DevOps API、审批、文件分发、发布部署、通知和审计清理等核心路径。

## 注意事项

- 远程采集、命令执行、文件分发、发布部署依赖目标主机 SSH 连通性。
- 邮件告警依赖 SMTP 配置。
- 后台任务依赖独立数据库 Worker；部署时必须在 Worker 启动前完成迁移，并持续观察其容器日志和健康状态。
- 管理员默认可见全部主机；普通用户需要配置主机范围后才能看到对应主机。
