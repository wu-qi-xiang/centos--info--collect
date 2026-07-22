# 平台备份与恢复演练

本手册提供本地 SQLite 数据库和 `uploads/` 的备份与隔离恢复预检。归档用于恢复演练和受控存储，不会包含 `.env` 或上传目录中的私钥、证书和密钥文件。不要将归档、环境变量文件或凭据提交到仓库。

## 范围和限制

- `scripts/backup_local.py` 仅支持 SQLite；MySQL 和 PostgreSQL 必须使用各自受控的逻辑备份和恢复程序。
- 归档包含一致性 SQLite 副本、`uploads/` 中的常规文件、`manifest.json` 和 `checksums.sha256`。数据库中已有的加密业务数据仍按正常数据库恢复流程处理。
- 脚本拒绝上传目录中的符号链接、特殊文件、`.env`、私钥、证书和常见密钥文件，避免把运行时配置或敏感文件意外纳入归档。
- `restore_runtime` 只接受明确指定的本地加密 `.tar.gz.enc` 归档和已存在且为空的隔离目录。它绝不替换源数据库、源 `uploads/` 或应用运行目录。

将生成的归档存入受控、加密的备份存储，限制访问并按组织保留策略清理。记录备份时间、归档校验结果、保管位置、恢复耗时和执行人；不要在记录中写入密码、令牌或连接字符串。

## S3 兼容异地存储

异地备份可使用 AWS S3、MinIO、阿里云 OSS 的 S3 兼容接口。设置 `BACKUP_S3_BUCKET` 后启用；`BACKUP_S3_PREFIX` 默认为 `pylinux`。AWS 可省略 `BACKUP_S3_ENDPOINT_URL`，MinIO 或其他兼容服务应填写其 HTTPS API 端点。生产环境必须设置 `BACKUP_S3_VERIFY_SSL=True`。

归档加密复用现有 `DATA_ENCRYPTION_KEY`，不要创建第二个备份加密密钥，也不要把任何密钥写入归档、命令行、日志或版本库。可使用 `BACKUP_S3_ACCESS_KEY_ID` 与 `BACKUP_S3_SECRET_ACCESS_KEY`，两者必须同时设置；在 AWS IAM 角色、EKS IRSA 等环境中应省略这两个变量，交由标准凭据链获取短期凭据。临时会话凭据使用 `BACKUP_S3_SESSION_TOKEN`，且必须与访问密钥对一起提供。

对象存储账户只应被授予目标桶及指定前缀的写入、读取和列举权限，禁止删除其他业务前缀。配置完成后执行 `python manage.py check --deploy`；此检查不会连接对象存储，仍应通过受控的上传和隔离恢复演练验证实际凭据、网络策略、桶版本控制和保留策略。

## 创建 SQLite 备份

在维护窗口执行，或先确认应用的写入策略。脚本使用 SQLite 在线备份 API 创建一致性副本；输出文件的父目录必须预先存在，且输出归档不能位于 `uploads/` 中。

```bash
mkdir -p /var/backups/pylinux
python3 scripts/backup_local.py \
  --database /srv/pylinux/db.sqlite3 \
  --uploads /srv/pylinux/uploads \
  --output /var/backups/pylinux/pylinux-20260720.tar.gz.enc \
  --encrypt
```

如果指定的归档已存在，脚本默认失败。只有在已确认目标文件正确时才追加 `--force`。备份失败时不要使用不完整归档；先修复目录权限、敏感上传文件或存储空间问题，再重新运行。

## 隔离恢复演练

先创建专用、已存在且为空的隔离目录。这个目录不应是项目目录、生产数据目录或归档所在目录。恢复演练会先拒绝不安全或损坏的归档，验证所有数据成员的 SHA-256 校验和，再把数据库和上传文件写入该隔离目录，并对恢复后的 SQLite 文件执行只读 `PRAGMA integrity_check`。

```bash
mkdir -p /var/tmp/pylinux-restore-drill
python manage.py restore_runtime \
  --archive /var/backups/pylinux/pylinux-20260720.tar.gz.enc \
  --target-dir /var/tmp/pylinux-restore-drill
```

该命令只接受明确指定的本地加密 `.tar.gz.enc` 归档和已存在且为空的隔离目录；不会从 S3 下载归档，也不会访问生产服务。成功时会输出 JSON 报告，并在隔离目录中生成：

```text
database.sqlite3
uploads/
```

恢复结果会保留在隔离目录中供人工检查。恢复演练不会运行 Django 迁移、启动服务、登录应用或连接 SSH、SMTP、Webhook 等外部系统。需要进一步演练时，基于这份已验证副本创建单独的测试应用环境，使用无生产凭据的配置运行 `manage.py check` 和受控的业务验证。

预检失败可能留下部分隔离副本，供调查归档问题使用；确认不再需要后由操作者删除该明确指定的隔离目录。生产恢复必须遵循组织的变更、审批和服务停写流程，不得把本预检脚本作为生产覆盖工具。
