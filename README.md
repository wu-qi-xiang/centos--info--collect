# CentOS Info Collect / 运维管理平台

这是一个基于 Django 2.1 的服务器资产、监控告警和 DevOps 自动化管理项目。原始功能以服务器信息采集和邮件告警为主，当前版本已经扩展为面向小团队运维场景的综合控制台。

## 当前功能

- 用户登录、注册、退出，兼容旧明文密码并在登录后升级为哈希密码。
- 服务器资产管理：新增、编辑、删除、搜索、分页、连接测试、WebSSH。
- SSH 认证：支持密码和 SSH Key，敏感凭据加密存储。
- 本机和远程主机基础信息采集。
- 监控告警：CPU、内存、磁盘阈值配置，定时采集，邮件告警，告警恢复记录。
- 密码管理：按当前登录用户隔离账号密码记录，支持加密存储和按需查看。
- DevOps 控制台：主机分组、标签、命令执行、批量任务、服务管理、文件分发、发布部署、回滚、审批流、通知渠道、审计日志、监控历史。
- 权限控制：全局角色、模块权限、主机范围授权。
- 部署基础：环境变量配置、Dockerfile、Compose、Gunicorn 配置、审计日志清理命令。

## 本地运行

项目依赖较旧，建议使用仓库内现有 `.venv` 或 Python 3.6 兼容环境。

```bash
python3 -m venv .venv
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
- `DEVOPS_SSH_CONNECT_TIMEOUT_SECONDS`
- `DEVOPS_COMMAND_TIMEOUT_SECONDS`
- `DEVOPS_COMMAND_OUTPUT_MAX_BYTES`
- `WEBSSH_SESSION_TIMEOUT_SECONDS`
- `AUDIT_LOG_RETENTION_DAYS`
- `METRIC_SAMPLE_RETENTION_DAYS`

生产模式由 `DJANGO_ENV=production` / `prod` 或 `DJANGO_DEBUG=False` 触发。运行 `python manage.py check --deploy` 会检查生产关键配置：

- `DJANGO_DEBUG` 必须关闭。
- `DJANGO_SECRET_KEY`、`DATA_ENCRYPTION_KEY` 不能使用默认或空值。
- `DJANGO_ALLOWED_HOSTS` 不能使用 `*`。
- 生产环境不应使用 SQLite，应配置 MySQL 或 PostgreSQL。
- `DEVOPS_SSH_CONNECT_TIMEOUT_SECONDS`、`DEVOPS_COMMAND_TIMEOUT_SECONDS`、`DEVOPS_COMMAND_OUTPUT_MAX_BYTES`、`WEBSSH_SESSION_TIMEOUT_SECONDS`、`NOTIFICATION_TIMEOUT_SECONDS` 必须为正整数。
- `AUDIT_LOG_RETENTION_DAYS`、`METRIC_SAMPLE_RETENTION_DAYS` 不能为负数；设置为 `0` 表示不按保留天数清理，生产环境会给出警告。

## DevOps 后台任务

命令执行、批量任务、文件分发、发布部署和回滚通过后台线程执行，测试环境由 `DEVOPS_SYNC_TASKS` 同步执行。执行入口具备幂等保护：只有待执行任务会被领取；已经运行或已有结果的任务重复触发时不会再次创建远程执行记录，避免重复 SSH、重复分发或重复发布结果。

当前后台线程仍依附 Web 进程，适合小团队和单实例部署。生产关键发布建议后续接入独立 worker、Celery 或 RQ，并复用现有 pending/running/terminal 状态模型。

## 监控数据保留

远程监控采集会写入 `MetricSample` 指标样本，用于 DevOps 监控历史和 AIOps 容量分析。`METRIC_SAMPLE_RETENTION_DAYS` 控制样本保留天数，默认 `30` 天；设置为 `0` 表示不自动清理。定时监控任务每次运行后会清理超过保留期的指标样本，不删除告警事件、告警历史或审计日志。

## 定时监控

配置邮件和监控阈值后，添加定时任务：

```bash
python manage.py crontab add
python manage.py crontab show
python manage.py crontab remove
```

## 目录结构

- `PyLinux/`：Django 项目配置、路由和 WSGI 入口。
- `RemoteLinux/`、`linux/`、`monitor/`、`password/`、`userprofile/`、`devops/`：业务应用。
- `templates/`、`static/`：页面模板和静态资源。
- `deploy/`：Dockerfile、Compose、Gunicorn 和生产依赖文件。
- `docs/`：接口说明、优化记录和页面审计截图。
- `uploads/`、`logs/`：运行期文件目录，不应作为代码依赖。

## Docker / Compose

```bash
docker compose -f deploy/docker-compose.yml up --build
```

如使用 Kubernetes，参考 `k8s/` 目录内的镜像构建和部署 YAML，并按实际镜像仓库修改镜像地址。

## 开发验证

每次修改后建议执行：

```bash
.venv/bin/python manage.py check
.venv/bin/python manage.py test
```

当前测试覆盖包括登录注册、主机权限、SSH 凭据处理、密码管理、监控采集、告警、DevOps API、审批、文件分发、发布部署、通知和审计清理等核心路径。

## 注意事项

- 远程采集、命令执行、文件分发、发布部署依赖目标主机 SSH 连通性。
- 邮件告警依赖 SMTP 配置。
- 后台任务当前由 Web 进程内线程执行，失败会写入审计日志；更高可靠性的生产环境建议接入 Celery、RQ 或独立 worker。
- 管理员默认可见全部主机；普通用户需要配置主机范围后才能看到对应主机。
