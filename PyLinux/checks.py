from django.conf import settings
from django.core.checks import Critical, Warning, Tags, register


DEFAULT_SECRET_KEY = 'django-insecure-change-me'
SQLITE_ENGINE = 'django.db.backends.sqlite3'


POSITIVE_PRODUCTION_SETTINGS = (
	('DEVOPS_SSH_CONNECT_TIMEOUT_SECONDS', 'pylinux.E006', 'SSH 连接超时时间必须大于 0 秒。'),
	('DEVOPS_COMMAND_TIMEOUT_SECONDS', 'pylinux.E007', '远程命令执行超时时间必须大于 0 秒。'),
	('DEVOPS_COMMAND_OUTPUT_MAX_BYTES', 'pylinux.E008', '远程命令输出上限必须大于 0 字节。'),
	('WEBSSH_SESSION_TIMEOUT_SECONDS', 'pylinux.E009', 'WebSSH 会话超时时间必须大于 0 秒。'),
	('NOTIFICATION_TIMEOUT_SECONDS', 'pylinux.E010', '通知请求超时时间必须大于 0 秒。'),
)


def production_mode():
	return getattr(settings, 'DJANGO_ENV', '').lower() in ('prod', 'production') or not settings.DEBUG


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


@register(Tags.security, deploy=True)
def production_security_check(app_configs, **kwargs):
	if not production_mode():
		return []
	messages = []
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
