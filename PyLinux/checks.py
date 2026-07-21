import sys
from urllib.parse import urlparse

import django
from django.conf import settings
from django.core.checks import Critical, Warning, Tags, register


DEFAULT_SECRET_KEY = 'django-insecure-change-me'
SQLITE_ENGINE = 'django.db.backends.sqlite3'
SUPPORTED_DJANGO_VERSION = (4, 2, 16)
SUPPORTED_PYTHON_VERSION = (3, 11)
EXTERNAL_AUTH_ROLES = ('viewer', 'operator', 'admin')


POSITIVE_PRODUCTION_SETTINGS = (
	('DEVOPS_WORKER_POLL_SECONDS', 'pylinux.E013', 'DevOps Worker 轮询间隔必须大于 0 秒。'),
	('DEVOPS_WORKER_MAX_ATTEMPTS', 'pylinux.E014', 'DevOps Worker 最大尝试次数必须大于 0。'),
	('DEVOPS_WORKER_JOB_TIMEOUT_SECONDS', 'pylinux.E015', 'DevOps Worker 任务超时时间必须大于 0 秒。'),
	('DEVOPS_SSH_CONNECT_TIMEOUT_SECONDS', 'pylinux.E006', 'SSH 连接超时时间必须大于 0 秒。'),
	('DEVOPS_COMMAND_TIMEOUT_SECONDS', 'pylinux.E007', '远程命令执行超时时间必须大于 0 秒。'),
	('DEVOPS_COMMAND_OUTPUT_MAX_BYTES', 'pylinux.E008', '远程命令输出上限必须大于 0 字节。'),
	('WEBSSH_SESSION_TIMEOUT_SECONDS', 'pylinux.E009', 'WebSSH 会话超时时间必须大于 0 秒。'),
	('NOTIFICATION_TIMEOUT_SECONDS', 'pylinux.E010', '通知请求超时时间必须大于 0 秒。'),
)

WORKER_ALERT_THRESHOLD_SETTINGS = (
	('DEVOPS_WORKER_ALERT_PENDING_THRESHOLD', 'pylinux.E029', 'Worker 待处理任务告警阈值必须是非负整数。'),
	('DEVOPS_WORKER_ALERT_TIMED_OUT_THRESHOLD', 'pylinux.E030', 'Worker 超时任务告警阈值必须是非负整数。'),
)


def production_mode():
	return getattr(settings, 'DJANGO_ENV', '').lower() in ('prod', 'production') or not settings.DEBUG


def runtime_baseline_check(app_configs=None, **kwargs):
	messages = []
	if django.VERSION[:3] != SUPPORTED_DJANGO_VERSION:
		messages.append(Critical(
			'当前 Django 版本不符合受支持运行基线。',
			hint='安装 requirements.txt 中固定的 Django==4.2.16。',
			id='pylinux.E016',
		))
	if sys.version_info[:2] != SUPPORTED_PYTHON_VERSION:
		messages.append(Critical(
			'当前 Python 版本不符合受支持运行基线。',
			hint='使用 Python 3.11 创建并运行虚拟环境或容器镜像。',
			id='pylinux.E017',
		))
	return messages


def retention_days_messages(setting_name, label, error_id, warning_id):
	messages = []
	try:
		days = int(getattr(settings, setting_name, 0))
	except (TypeError, ValueError):
		days = -1
	if days < 0:
		messages.append(Critical(
			'%s保留天数不能小于 0。' % label,
			hint='将 %s 设置为 0 或正整数。' % setting_name,
			id=error_id,
		))
	elif days == 0:
		messages.append(Warning(
			'生产环境未启用%s保留清理。' % label,
			hint='设置 %s 为符合容量和合规要求的正整数；0 表示不按保留天数清理。' % setting_name,
			id=warning_id,
		))
	return messages


def _external_auth_config(setting_name):
	config = getattr(settings, setting_name, {})
	return config if isinstance(config, dict) else {}


def _safe_https_uri(value):
	if not isinstance(value, str):
		return None
	parsed = urlparse(value)
	if (
		parsed.scheme != 'https' or not parsed.hostname or parsed.username or
		parsed.password or parsed.params or parsed.query or parsed.fragment
	):
		return None
	return parsed


def external_auth_production_messages():
	"""Check external identity configuration without ever including secret values."""
	messages = []
	oidc = _external_auth_config('OIDC_CONFIG')
	ldap = _external_auth_config('LDAP_CONFIG')
	oidc_enabled = oidc.get('enabled') is True
	ldap_enabled = ldap.get('enabled') is True

	role_map = getattr(settings, 'EXTERNAL_AUTH_ROLE_MAP', {})
	if not isinstance(role_map, dict) or any(
		not isinstance(group, str) or not group.strip() or role not in EXTERNAL_AUTH_ROLES
		for group, role in role_map.items()
	):
		messages.append(Critical(
			'外部认证角色映射无效。',
			hint='将 EXTERNAL_AUTH_ROLE_MAP 设置为组名到 viewer、operator 或 admin 的 JSON 对象。',
			id='pylinux.E018',
		))
	elif (oidc_enabled or ldap_enabled) and not role_map:
		messages.append(Critical(
			'启用外部认证时必须配置角色映射。',
			hint='为 EXTERNAL_AUTH_ROLE_MAP 配置至少一个外部组到现有 DevOps 角色的映射。',
			id='pylinux.E018',
		))

	if oidc_enabled:
		required = ('discovery_url', 'client_id', 'client_secret', 'redirect_uri')
		if any(not isinstance(oidc.get(key), str) or not oidc[key].strip() for key in required):
			messages.append(Critical(
				'OIDC 配置不完整。',
				hint='配置 discovery URL、client ID、client secret 和 redirect URI。',
				id='pylinux.E019',
			))
		else:
			discovery = _safe_https_uri(oidc['discovery_url'])
			redirect = _safe_https_uri(oidc['redirect_uri'])
			allowed_hosts = set(host.split(':', 1)[0].lower() for host in settings.ALLOWED_HOSTS)
			if not discovery:
				messages.append(Critical(
					'生产环境 OIDC discovery URL 必须使用 HTTPS。',
					hint='使用不含查询参数、片段或嵌入凭据的 HTTPS discovery URL。',
					id='pylinux.E020',
				))
			if not redirect or redirect.hostname.lower() not in allowed_hosts:
				messages.append(Critical(
					'生产环境 OIDC redirect URI 不安全或未登记到允许主机。',
					hint='使用 HTTPS 回调地址，并将其主机名加入 DJANGO_ALLOWED_HOSTS。',
					id='pylinux.E021',
				))

	if ldap_enabled:
		required = (
			'server_uri', 'bind_dn', 'bind_password', 'base_dn', 'user_filter',
			'group_attribute', 'starttls',
		)
		if any(key not in ldap or ldap[key] in (None, '') for key in required):
			messages.append(Critical(
				'LDAP 配置不完整。',
				hint='配置 LDAP 服务器、绑定凭据、搜索基准、用户过滤器、组属性和 StartTLS。',
				id='pylinux.E022',
			))
		else:
			parsed = urlparse(ldap['server_uri']) if isinstance(ldap['server_uri'], str) else None
			if (
				not parsed or parsed.scheme not in ('ldap', 'ldaps') or not parsed.hostname or
				parsed.username or parsed.password or parsed.params or parsed.query or parsed.fragment
			):
				messages.append(Critical(
					'LDAP 服务器 URI 无效。',
					hint='使用 ldap:// 或 ldaps:// 绝对 URI，且不要嵌入凭据。',
					id='pylinux.E023',
				))
			elif parsed.scheme != 'ldaps' and ldap.get('starttls') is not True:
				messages.append(Critical(
					'生产环境 LDAP 必须使用 LDAPS 或 StartTLS。',
					hint='使用 ldaps:// URI，或将 LDAP_STARTTLS 设置为 True。',
					id='pylinux.E024',
				))
	return messages


def backup_s3_production_messages():
	"""Validate an enabled remote backup target without exposing credentials."""
	config = getattr(settings, 'BACKUP_S3_CONFIG', {})
	if not isinstance(config, dict) or config.get('enabled') is not True:
		return []
	messages = []
	required = ('bucket', 'prefix', 'verify_ssl')
	if any(key not in config or config[key] in (None, '') for key in required):
		messages.append(Critical(
			'S3 备份配置不完整。',
			hint='配置 BACKUP_S3_BUCKET、BACKUP_S3_PREFIX 和 BACKUP_S3_VERIFY_SSL。',
			id='pylinux.E025',
		))
	endpoint_url = config.get('endpoint_url', '')
	if endpoint_url and not _safe_https_uri(endpoint_url):
		messages.append(Critical(
			'生产环境 S3 备份端点必须使用 HTTPS。',
			hint='将 BACKUP_S3_ENDPOINT_URL 配置为不含凭据的 HTTPS URL。',
			id='pylinux.E026',
		))
	if config.get('verify_ssl') is not True:
		messages.append(Critical(
			'生产环境 S3 备份必须验证 TLS 证书。',
			hint='设置 BACKUP_S3_VERIFY_SSL=True。',
			id='pylinux.E027',
		))
	if not getattr(settings, 'DATA_ENCRYPTION_KEY', ''):
		messages.append(Critical(
			'启用 S3 备份时必须配置 DATA_ENCRYPTION_KEY。',
			hint='备份归档使用现有 DATA_ENCRYPTION_KEY 加密；请在部署环境中配置该密钥。',
			id='pylinux.E028',
		))
	return messages


def worker_alert_threshold_messages():
	"""Validate optional Worker health thresholds; zero explicitly disables an alert."""
	messages = []
	for setting_name, check_id, message in WORKER_ALERT_THRESHOLD_SETTINGS:
		try:
			value = int(getattr(settings, setting_name, 0))
		except (TypeError, ValueError):
			value = -1
		if value < 0:
			messages.append(Critical(
				message,
				hint='为 %s 设置 0 或正整数；0 表示禁用该告警。' % setting_name,
				id=check_id,
			))
	try:
		failure_rate = int(getattr(settings, 'DEVOPS_WORKER_ALERT_FAILURE_RATE_PERCENT', 0))
	except (TypeError, ValueError):
		failure_rate = -1
	if not 0 <= failure_rate <= 100:
		messages.append(Critical(
			'Worker 失败率告警阈值必须在 0 到 100 之间。',
			hint='为 DEVOPS_WORKER_ALERT_FAILURE_RATE_PERCENT 设置 0 到 100 的整数；0 表示禁用该告警。',
			id='pylinux.E031',
		))
	return messages


@register(Tags.security, deploy=True)
def production_security_check(app_configs, **kwargs):
	if not production_mode():
		return []
	messages = runtime_baseline_check()
	if settings.DEBUG:
		messages.append(Critical(
			'生产环境不能启用 DEBUG。',
			hint='设置 DJANGO_DEBUG=False。',
			id='pylinux.E004',
		))
	if settings.SECRET_KEY == DEFAULT_SECRET_KEY:
		messages.append(Critical(
			'生产环境必须配置 DJANGO_SECRET_KEY。',
			hint='设置一个足够长的随机 DJANGO_SECRET_KEY。',
			id='pylinux.E001',
		))
	if not getattr(settings, 'DATA_ENCRYPTION_KEY', ''):
		messages.append(Critical(
			'生产环境必须配置 DATA_ENCRYPTION_KEY。',
			hint='DATA_ENCRYPTION_KEY 需要独立于 DJANGO_SECRET_KEY，避免密钥轮换导致敏感数据不可解密。',
			id='pylinux.E002',
		))
	if '*' in settings.ALLOWED_HOSTS:
		messages.append(Critical(
			'生产环境不能使用 DJANGO_ALLOWED_HOSTS=*。',
			hint='设置明确的域名或 IP 列表，例如 example.com,127.0.0.1。',
			id='pylinux.E003',
		))
	database_engine = settings.DATABASES.get('default', {}).get('ENGINE', '')
	if database_engine == SQLITE_ENGINE:
		messages.append(Critical(
			'生产环境不应使用 SQLite 数据库。',
			hint='通过 DB_ENGINE、DB_NAME、DB_USER、DB_PASSWORD、DB_HOST 和 DB_PORT 配置 MySQL 或 PostgreSQL。',
			id='pylinux.E005',
		))
	for setting_name, check_id, message in POSITIVE_PRODUCTION_SETTINGS:
		try:
			value = int(getattr(settings, setting_name, 0))
		except (TypeError, ValueError):
			value = 0
		if value <= 0:
			messages.append(Critical(
				message,
				hint='为 %s 设置正整数。' % setting_name,
				id=check_id,
			))
	messages.extend(retention_days_messages(
		'AUDIT_LOG_RETENTION_DAYS',
		'审计日志',
		'pylinux.E011',
		'pylinux.W002',
	))
	messages.extend(retention_days_messages(
		'METRIC_SAMPLE_RETENTION_DAYS',
		'指标样本',
		'pylinux.E012',
		'pylinux.W003',
	))
	messages.extend(retention_days_messages(
		'AIOPS_ANALYSIS_RETENTION_DAYS',
		'AIOps 分析记录',
		'pylinux.E031',
		'pylinux.W008',
	))
	messages.extend(external_auth_production_messages())
	messages.extend(backup_s3_production_messages())
	messages.extend(worker_alert_threshold_messages())
	return messages


@register(Tags.security, deploy=True)
def development_security_warning(app_configs, **kwargs):
	if production_mode():
		return []
	messages = []
	if not getattr(settings, 'DATA_ENCRYPTION_KEY', ''):
		messages.append(Warning(
			'当前未配置 DATA_ENCRYPTION_KEY，将使用 SECRET_KEY 派生加密密钥。',
			hint='开发环境可暂时使用；生产环境必须配置独立 DATA_ENCRYPTION_KEY。',
			id='pylinux.W001',
		))
	return messages
