from django.core.exceptions import ImproperlyConfigured
from django.core.management import call_command
from unittest import mock
from io import StringIO
from pathlib import Path

from django.test import SimpleTestCase, TestCase, override_settings

from .checks import (
	development_security_warning,
	production_security_check,
	runtime_baseline_check,
	worker_alert_threshold_messages,
)
from .settings import (
	backup_s3_config_from_env,
	database_config_from_env,
	external_auth_config_from_env,
	k8s_cache_config_from_env,
)
from RemoteLinux.models import NewLinux, User
from devops.models import AlertEvent, ApprovalRequest, DevOpsRole


class DatabaseConfigTests(SimpleTestCase):
	def test_default_database_is_sqlite(self):
		config = database_config_from_env({}, '/app')

		self.assertEqual(config['default']['ENGINE'], 'django.db.backends.sqlite3')
		self.assertEqual(config['default']['NAME'], '/app/db.sqlite3')

	def test_mysql_database_uses_environment(self):
		config = database_config_from_env({
			'DB_ENGINE': 'mysql',
			'DB_NAME': 'pylinux',
			'DB_USER': 'app',
			'DB_PASSWORD': 'secret',
			'DB_HOST': 'mysql',
			'DB_PORT': '3306',
			'DB_CONN_MAX_AGE': '120',
			'DB_CHARSET': 'utf8mb4',
		}, '/app')

		self.assertEqual(config['default']['ENGINE'], 'django.db.backends.mysql')
		self.assertEqual(config['default']['NAME'], 'pylinux')
		self.assertEqual(config['default']['USER'], 'app')
		self.assertEqual(config['default']['PASSWORD'], 'secret')
		self.assertEqual(config['default']['HOST'], 'mysql')
		self.assertEqual(config['default']['PORT'], '3306')
		self.assertEqual(config['default']['CONN_MAX_AGE'], 120)
		self.assertEqual(config['default']['OPTIONS']['charset'], 'utf8mb4')

	def test_non_sqlite_requires_database_name(self):
		with self.assertRaises(ImproperlyConfigured):
			database_config_from_env({'DB_ENGINE': 'postgres'}, '/app')


class ProductionComposeReferenceTests(SimpleTestCase):
	"""Guard the opt-in PostgreSQL/Nginx reference without starting Docker."""

	def setUp(self):
		self.project_root = Path(__file__).resolve().parent.parent
		self.compose_path = self.project_root / 'deploy' / 'docker-compose.production.yml'
		self.nginx_path = self.project_root / 'deploy' / 'nginx' / 'default.conf'
		self.requirements_path = self.project_root / 'deploy' / 'requirements-prod.txt'
		self.production_doc_path = self.project_root / 'docs' / 'production_deployment.md'

	def test_production_override_has_private_postgres_and_existing_runtime_services(self):
		self.assertTrue(self.compose_path.exists())
		compose = self.compose_path.read_text(encoding='utf-8')

		for service in ('postgres:', 'web:', 'worker:', 'nginx:'):
			with self.subTest(service=service):
				self.assertIn(service, compose)
		self.assertIn('DB_ENGINE: postgresql', compose)
		self.assertIn('DB_CHARSET: ""', compose)
		self.assertIn('POSTGRES_PASSWORD: ${DB_PASSWORD', compose)
		self.assertIn('volumes: !override', compose)
		self.assertIn('static_data:/app/staticfiles', compose)
		self.assertIn('uploads_data:/app/uploads', compose)
		self.assertNotIn('uploads_data:/var/www/uploads', compose)
		self.assertNotIn('ports:', compose.split('postgres:', 1)[1].split('web:', 1)[0])
		self.assertNotIn('change-me', compose)
		web_section = compose.split('web:', 1)[1].split('worker:', 1)[0]
		worker_section = compose.split('worker:', 1)[1].split('nginx:', 1)[0]
		nginx_section = compose.split('nginx:', 1)[1]
		self.assertIn('ports: !reset []', web_section)
		self.assertNotIn('ports:', worker_section)
		self.assertIn('"80:80"', nginx_section)

	def test_nginx_serves_shared_files_and_proxies_health_endpoints(self):
		self.assertTrue(self.nginx_path.exists())
		nginx = self.nginx_path.read_text(encoding='utf-8')

		for path in ('/static/', '/health/live/', '/health/ready/'):
			with self.subTest(path=path):
				self.assertIn(path, nginx)
		self.assertNotIn('location /uploads/', nginx)
		self.assertNotIn('/var/www/uploads', nginx)
		self.assertIn('proxy_pass http://web:8000', nginx)
		self.assertIn('proxy_set_header X-Forwarded-For', nginx)

	def test_postgresql_reference_uses_database_environment_mapping(self):
		config = database_config_from_env({
			'DB_ENGINE': 'postgresql',
			'DB_NAME': 'pylinux',
			'DB_USER': 'pylinux',
			'DB_PASSWORD': 'test-only-password',
			'DB_HOST': 'postgres',
			'DB_PORT': '5432',
		}, '/app')

		self.assertEqual(config['default']['ENGINE'], 'django.db.backends.postgresql')
		self.assertEqual(config['default']['HOST'], 'postgres')

	def test_production_image_includes_a_pinned_postgresql_driver(self):
		requirements = self.requirements_path.read_text(encoding='utf-8')

		self.assertIn('psycopg2-binary==2.9.10', requirements)

	def test_production_reference_leaves_uploads_without_an_external_route(self):
		documentation = self.production_doc_path.read_text(encoding='utf-8')

		self.assertIn('`/uploads/` 没有生产路由', documentation)
		self.assertIn('刻意不对外提供上传文件', documentation)


class K8sCacheConfigTests(SimpleTestCase):
	def test_default_cache_is_persistent_file_cache(self):
		timeout, caches = k8s_cache_config_from_env({}, '/app')
		default_cache = caches['default']

		self.assertEqual(timeout, 86400)
		self.assertEqual(
			default_cache['BACKEND'],
			'django.core.cache.backends.filebased.FileBasedCache',
		)
		self.assertEqual(default_cache['LOCATION'], '/app/.cache/k8s')
		self.assertEqual(default_cache['TIMEOUT'], 86400)
		self.assertEqual(default_cache['OPTIONS']['MAX_ENTRIES'], 1000)

	def test_cache_environment_overrides_path_and_timeout(self):
		timeout, caches = k8s_cache_config_from_env({
			'K8S_CACHE_DIR': '/var/cache/pylinux/k8s',
			'K8S_DETAIL_CACHE_TIMEOUT_SECONDS': '7200',
		}, '/app')

		self.assertEqual(timeout, 7200)
		self.assertEqual(caches['default']['LOCATION'], '/var/cache/pylinux/k8s')
		self.assertEqual(caches['default']['TIMEOUT'], 7200)

	def test_relative_cache_path_is_resolved_from_base_dir(self):
		_, caches = k8s_cache_config_from_env({'K8S_CACHE_DIR': 'runtime/k8s'}, '/app')

		self.assertEqual(caches['default']['LOCATION'], '/app/runtime/k8s')

	def test_cache_timeout_must_be_positive_integer(self):
		for value in ('0', '-1', 'invalid'):
			with self.subTest(value=value):
				with self.assertRaises(ImproperlyConfigured):
					k8s_cache_config_from_env({
						'K8S_DETAIL_CACHE_TIMEOUT_SECONDS': value,
					}, '/app')


class BackupS3ConfigTests(SimpleTestCase):
	def test_backup_s3_is_disabled_without_bucket(self):
		self.assertEqual(backup_s3_config_from_env({}), {'enabled': False})

	def test_backup_s3_accepts_compatible_endpoint_and_provider_credentials(self):
		config = backup_s3_config_from_env({
			'BACKUP_S3_BUCKET': 'pylinux-backups',
			'BACKUP_S3_PREFIX': 'production/daily',
			'BACKUP_S3_ENDPOINT_URL': 'https://minio.example.invalid',
			'BACKUP_S3_REGION': 'us-east-1',
			'BACKUP_S3_ACCESS_KEY_ID': 'access-key',
			'BACKUP_S3_SECRET_ACCESS_KEY': 'secret-key',
		})

		self.assertTrue(config['enabled'])
		self.assertEqual(config['prefix'], 'production/daily')
		self.assertTrue(config['verify_ssl'])

	def test_backup_s3_rejects_unsafe_partial_configuration(self):
		for environment in (
			{'BACKUP_S3_BUCKET': 'Invalid_Bucket'},
			{'BACKUP_S3_BUCKET': 'pylinux-backups', 'BACKUP_S3_PREFIX': '../outside'},
			{'BACKUP_S3_BUCKET': 'pylinux-backups', 'BACKUP_S3_ENDPOINT_URL': 'https://key:secret@example.invalid'},
			{'BACKUP_S3_BUCKET': 'pylinux-backups', 'BACKUP_S3_ACCESS_KEY_ID': 'access-key'},
			{'BACKUP_S3_BUCKET': 'pylinux-backups', 'BACKUP_S3_SESSION_TOKEN': 'token'},
		):
			with self.subTest(environment=environment):
				with self.assertRaises(ImproperlyConfigured):
					backup_s3_config_from_env(environment)


class ExternalAuthConfigTests(SimpleTestCase):
	def role_map(self):
		return '{"directory-viewers":"viewer","directory-admins":"admin"}'

	def oidc_environment(self):
		return {
			'EXTERNAL_AUTH_ROLE_MAP': self.role_map(),
			'OIDC_DISCOVERY_URL': 'https://identity.invalid/.well-known/openid-configuration',
			'OIDC_CLIENT_ID': 'client-id',
			'OIDC_CLIENT_SECRET': 'client-secret',
			'OIDC_REDIRECT_URI': 'https://platform.invalid/userprofile/external/oidc/callback/',
		}

	def ldap_environment(self):
		return {
			'EXTERNAL_AUTH_ROLE_MAP': self.role_map(),
			'LDAP_SERVER_URI': 'ldaps://directory.invalid:636',
			'LDAP_BIND_DN': 'CN=service,DC=example,DC=invalid',
			'LDAP_BIND_PASSWORD': 'bind-secret',
			'LDAP_BASE_DN': 'DC=example,DC=invalid',
			'LDAP_USER_FILTER': '(&(objectClass=person)(uid={username}))',
			'LDAP_GROUP_ATTRIBUTE': 'memberOf',
			'LDAP_STARTTLS': 'True',
		}

	def test_default_external_auth_sources_are_disabled(self):
		role_map, oidc, ldap = external_auth_config_from_env({})

		self.assertEqual(role_map, {})
		self.assertEqual(oidc, {'enabled': False})
		self.assertEqual(ldap, {'enabled': False})

	def test_complete_oidc_and_ldap_sources_parse(self):
		environment = self.oidc_environment()
		environment.update(self.ldap_environment())

		role_map, oidc, ldap = external_auth_config_from_env(environment)

		self.assertEqual(role_map['directory-admins'], 'admin')
		self.assertTrue(oidc['enabled'])
		self.assertEqual(oidc['client_id'], 'client-id')
		self.assertTrue(ldap['enabled'])
		self.assertTrue(ldap['starttls'])

	def test_partial_source_invalid_role_and_unsafe_filter_are_rejected(self):
		with self.assertRaises(ImproperlyConfigured):
			external_auth_config_from_env({'OIDC_CLIENT_ID': 'client-id'})
		with self.assertRaises(ImproperlyConfigured):
			external_auth_config_from_env({'EXTERNAL_AUTH_ROLE_MAP': '{"ops":"owner"}'})
		environment = self.ldap_environment()
		environment['LDAP_USER_FILTER'] = '(uid={username}{username})'
		with self.assertRaises(ImproperlyConfigured):
			external_auth_config_from_env(environment)
		environment = self.oidc_environment()
		environment['OIDC_REDIRECT_URI'] = 'http://platform.invalid/callback/'
		with self.assertRaises(ImproperlyConfigured):
			external_auth_config_from_env(environment)

	def test_enabled_source_requires_role_mapping(self):
		environment = self.oidc_environment()
		del environment['EXTERNAL_AUTH_ROLE_MAP']

		with self.assertRaises(ImproperlyConfigured):
			external_auth_config_from_env(environment)


class ProductionChecksTests(SimpleTestCase):
	def message_ids(self, messages):
		return set(message.id for message in messages)

	def test_runtime_baseline_accepts_pinned_versions(self):
		self.assertEqual(runtime_baseline_check(), [])

	@mock.patch('PyLinux.checks.sys.version_info', (3, 10, 0))
	@mock.patch('PyLinux.checks.django.VERSION', (4, 2, 15, 'final', 0))
	def test_runtime_baseline_rejects_unpinned_versions(self):
		ids = self.message_ids(runtime_baseline_check())

		self.assertEqual(ids, {'pylinux.E016', 'pylinux.E017'})

	@override_settings(
		DEVOPS_WORKER_ALERT_PENDING_THRESHOLD=-1,
		DEVOPS_WORKER_ALERT_FAILURE_RATE_PERCENT=101,
		DEVOPS_WORKER_ALERT_TIMED_OUT_THRESHOLD='invalid',
	)
	def test_worker_alert_threshold_check_rejects_invalid_values(self):
		self.assertEqual(
			self.message_ids(worker_alert_threshold_messages()),
			{'pylinux.E029', 'pylinux.E030', 'pylinux.E031'},
		)

	@override_settings(
		DEVOPS_WORKER_ALERT_PENDING_THRESHOLD=0,
		DEVOPS_WORKER_ALERT_FAILURE_RATE_PERCENT=0,
		DEVOPS_WORKER_ALERT_TIMED_OUT_THRESHOLD=0,
	)
	def test_worker_alert_threshold_check_accepts_disabled_alerts(self):
		self.assertEqual(worker_alert_threshold_messages(), [])

	@override_settings(
		DJANGO_ENV='production',
		DEBUG=True,
		SECRET_KEY='django-insecure-change-me',
		DATA_ENCRYPTION_KEY='',
		ALLOWED_HOSTS=['*'],
		DATABASES={'default': {'ENGINE': 'django.db.backends.sqlite3', 'NAME': '/app/db.sqlite3'}},
		DEVOPS_WORKER_POLL_SECONDS=0,
		DEVOPS_WORKER_MAX_ATTEMPTS='invalid',
		DEVOPS_WORKER_JOB_TIMEOUT_SECONDS=-1,
		DEVOPS_SSH_CONNECT_TIMEOUT_SECONDS=0,
		DEVOPS_COMMAND_TIMEOUT_SECONDS='invalid',
		DEVOPS_COMMAND_OUTPUT_MAX_BYTES=0,
		WEBSSH_SESSION_TIMEOUT_SECONDS=-1,
		NOTIFICATION_TIMEOUT_SECONDS=0,
		AUDIT_LOG_RETENTION_DAYS=0,
		METRIC_SAMPLE_RETENTION_DAYS=0,
	)
	def test_production_check_reports_unsafe_runtime_settings(self):
		ids = self.message_ids(production_security_check(None))

		self.assertTrue({
			'pylinux.E001',
			'pylinux.E002',
			'pylinux.E003',
			'pylinux.E004',
			'pylinux.E005',
			'pylinux.E013',
			'pylinux.E014',
			'pylinux.E015',
			'pylinux.E006',
			'pylinux.E007',
			'pylinux.E008',
			'pylinux.E009',
			'pylinux.E010',
			'pylinux.W002',
			'pylinux.W003',
		}.issubset(ids))

	@override_settings(
		DJANGO_ENV='production',
		DEBUG=False,
		SECRET_KEY='prod-secret',
		DATA_ENCRYPTION_KEY='prod-data-key',
		ALLOWED_HOSTS=['example.com', '127.0.0.1'],
		DATABASES={'default': {'ENGINE': 'django.db.backends.mysql', 'NAME': 'pylinux'}},
		DEVOPS_WORKER_POLL_SECONDS=1,
		DEVOPS_WORKER_MAX_ATTEMPTS=1,
		DEVOPS_WORKER_JOB_TIMEOUT_SECONDS=300,
		DEVOPS_SSH_CONNECT_TIMEOUT_SECONDS=10,
		DEVOPS_COMMAND_TIMEOUT_SECONDS=60,
		DEVOPS_COMMAND_OUTPUT_MAX_BYTES=204800,
		WEBSSH_SESSION_TIMEOUT_SECONDS=1800,
		NOTIFICATION_TIMEOUT_SECONDS=5,
		AUDIT_LOG_RETENTION_DAYS=90,
		METRIC_SAMPLE_RETENTION_DAYS=30,
	)
	def test_production_check_accepts_safe_runtime_settings(self):
		self.assertEqual(production_security_check(None), [])

	@override_settings(
		DJANGO_ENV='production',
		DEBUG=False,
		SECRET_KEY='prod-secret',
		DATA_ENCRYPTION_KEY='',
		ALLOWED_HOSTS=['example.com'],
		DATABASES={'default': {'ENGINE': 'django.db.backends.mysql', 'NAME': 'pylinux'}},
		DEVOPS_WORKER_POLL_SECONDS=1,
		DEVOPS_WORKER_MAX_ATTEMPTS=1,
		DEVOPS_WORKER_JOB_TIMEOUT_SECONDS=300,
		DEVOPS_SSH_CONNECT_TIMEOUT_SECONDS=10,
		DEVOPS_COMMAND_TIMEOUT_SECONDS=60,
		DEVOPS_COMMAND_OUTPUT_MAX_BYTES=204800,
		WEBSSH_SESSION_TIMEOUT_SECONDS=1800,
		NOTIFICATION_TIMEOUT_SECONDS=5,
		AUDIT_LOG_RETENTION_DAYS=90,
		METRIC_SAMPLE_RETENTION_DAYS=30,
		BACKUP_S3_CONFIG={
			'enabled': True,
			'bucket': 'pylinux-backups',
			'prefix': 'production',
			'endpoint_url': 'http://minio.example.invalid',
			'verify_ssl': False,
		},
	)
	def test_production_check_rejects_insecure_s3_backup_settings(self):
		ids = self.message_ids(production_security_check(None))

		self.assertTrue({'pylinux.E002', 'pylinux.E026', 'pylinux.E027', 'pylinux.E028'}.issubset(ids))

	@override_settings(
		DJANGO_ENV='production',
		DEBUG=False,
		SECRET_KEY='prod-secret',
		DATA_ENCRYPTION_KEY='prod-data-key',
		ALLOWED_HOSTS=['example.com'],
		DATABASES={'default': {'ENGINE': 'django.db.backends.mysql', 'NAME': 'pylinux'}},
		DEVOPS_WORKER_POLL_SECONDS=1,
		DEVOPS_WORKER_MAX_ATTEMPTS=1,
		DEVOPS_WORKER_JOB_TIMEOUT_SECONDS=300,
		DEVOPS_SSH_CONNECT_TIMEOUT_SECONDS=10,
		DEVOPS_COMMAND_TIMEOUT_SECONDS=60,
		DEVOPS_COMMAND_OUTPUT_MAX_BYTES=204800,
		WEBSSH_SESSION_TIMEOUT_SECONDS=1800,
		NOTIFICATION_TIMEOUT_SECONDS=5,
		AUDIT_LOG_RETENTION_DAYS=90,
		METRIC_SAMPLE_RETENTION_DAYS=30,
		BACKUP_S3_CONFIG={
			'enabled': True,
			'bucket': 'pylinux-backups',
			'prefix': 'production',
			'endpoint_url': 'https://minio.example.invalid',
			'verify_ssl': True,
		},
	)
	def test_production_check_accepts_safe_s3_backup_settings(self):
		self.assertEqual(production_security_check(None), [])

	@override_settings(
		DJANGO_ENV='production',
		DEBUG=False,
		SECRET_KEY='prod-secret',
		DATA_ENCRYPTION_KEY='prod-data-key',
		ALLOWED_HOSTS=['platform.invalid'],
		DATABASES={'default': {'ENGINE': 'django.db.backends.mysql', 'NAME': 'pylinux'}},
		DEVOPS_WORKER_POLL_SECONDS=1,
		DEVOPS_WORKER_MAX_ATTEMPTS=1,
		DEVOPS_WORKER_JOB_TIMEOUT_SECONDS=300,
		DEVOPS_SSH_CONNECT_TIMEOUT_SECONDS=10,
		DEVOPS_COMMAND_TIMEOUT_SECONDS=60,
		DEVOPS_COMMAND_OUTPUT_MAX_BYTES=204800,
		WEBSSH_SESSION_TIMEOUT_SECONDS=1800,
		NOTIFICATION_TIMEOUT_SECONDS=5,
		AUDIT_LOG_RETENTION_DAYS=90,
		METRIC_SAMPLE_RETENTION_DAYS=30,
		EXTERNAL_AUTH_ROLE_MAP={'directory-ops': 'operator'},
		OIDC_CONFIG={
			'enabled': True,
			'discovery_url': 'https://identity.invalid/.well-known/openid-configuration',
			'client_id': 'client-id',
			'client_secret': 'client-secret',
			'redirect_uri': 'http://platform.invalid/callback/',
		},
		LDAP_CONFIG={
			'enabled': True,
			'server_uri': 'ldap://directory.invalid:389',
			'bind_dn': 'CN=service,DC=example,DC=invalid',
			'bind_password': 'bind-secret',
			'base_dn': 'DC=example,DC=invalid',
			'user_filter': '(uid={username})',
			'group_attribute': 'memberOf',
			'starttls': False,
		},
	)
	def test_production_check_rejects_insecure_external_auth(self):
		ids = self.message_ids(production_security_check(None))

		self.assertIn('pylinux.E021', ids)
		self.assertIn('pylinux.E024', ids)

	@override_settings(
		DJANGO_ENV='production',
		DEBUG=False,
		SECRET_KEY='prod-secret',
		DATA_ENCRYPTION_KEY='prod-data-key',
		ALLOWED_HOSTS=['platform.invalid'],
		DATABASES={'default': {'ENGINE': 'django.db.backends.mysql', 'NAME': 'pylinux'}},
		DEVOPS_WORKER_POLL_SECONDS=1,
		DEVOPS_WORKER_MAX_ATTEMPTS=1,
		DEVOPS_WORKER_JOB_TIMEOUT_SECONDS=300,
		DEVOPS_SSH_CONNECT_TIMEOUT_SECONDS=10,
		DEVOPS_COMMAND_TIMEOUT_SECONDS=60,
		DEVOPS_COMMAND_OUTPUT_MAX_BYTES=204800,
		WEBSSH_SESSION_TIMEOUT_SECONDS=1800,
		NOTIFICATION_TIMEOUT_SECONDS=5,
		AUDIT_LOG_RETENTION_DAYS=90,
		METRIC_SAMPLE_RETENTION_DAYS=30,
		EXTERNAL_AUTH_ROLE_MAP={'directory-ops': 'operator'},
		OIDC_CONFIG={
			'enabled': True,
			'discovery_url': 'https://identity.invalid/.well-known/openid-configuration',
			'client_id': 'client-id',
			'client_secret': 'client-secret',
			'redirect_uri': 'https://platform.invalid/callback/',
		},
		LDAP_CONFIG={
			'enabled': True,
			'server_uri': 'ldaps://directory.invalid:636',
			'bind_dn': 'CN=service,DC=example,DC=invalid',
			'bind_password': 'bind-secret',
			'base_dn': 'DC=example,DC=invalid',
			'user_filter': '(uid={username})',
			'group_attribute': 'memberOf',
			'starttls': False,
		},
	)
	def test_production_check_accepts_safe_external_auth(self):
		self.assertEqual(production_security_check(None), [])

	@override_settings(
		DJANGO_ENV='development',
		DEBUG=True,
		DATA_ENCRYPTION_KEY='',
	)
	def test_development_mode_only_warns_about_missing_data_key(self):
		production_ids = self.message_ids(production_security_check(None))
		development_ids = self.message_ids(development_security_warning(None))

		self.assertEqual(production_ids, set())
		self.assertEqual(development_ids, {'pylinux.W001'})

	@override_settings(
		DJANGO_ENV='production',
		DEBUG=False,
		SECRET_KEY='prod-secret',
		DATA_ENCRYPTION_KEY='prod-data-key',
		ALLOWED_HOSTS=['example.com'],
		DATABASES={'default': {'ENGINE': 'django.db.backends.mysql', 'NAME': 'pylinux'}},
		DEVOPS_SSH_CONNECT_TIMEOUT_SECONDS=10,
		DEVOPS_COMMAND_TIMEOUT_SECONDS=60,
		DEVOPS_COMMAND_OUTPUT_MAX_BYTES=204800,
		WEBSSH_SESSION_TIMEOUT_SECONDS=1800,
		NOTIFICATION_TIMEOUT_SECONDS=5,
		AUDIT_LOG_RETENTION_DAYS=-1,
		METRIC_SAMPLE_RETENTION_DAYS=-1,
	)
	def test_production_check_rejects_negative_audit_retention(self):
		ids = self.message_ids(production_security_check(None))

		self.assertIn('pylinux.E011', ids)
		self.assertIn('pylinux.E012', ids)


class WorkerAlertCommandTests(SimpleTestCase):
	@override_settings(
		DEVOPS_WORKER_ALERT_PENDING_THRESHOLD=5,
		DEVOPS_WORKER_ALERT_FAILURE_RATE_PERCENT=25,
		DEVOPS_WORKER_ALERT_TIMED_OUT_THRESHOLD=1,
	)
	@mock.patch('devops.management.commands.evaluate_worker_alerts.resolve_alert')
	@mock.patch('devops.management.commands.evaluate_worker_alerts.record_alert')
	@mock.patch('devops.management.commands.evaluate_worker_alerts.summarize_background_jobs')
	def test_command_records_each_threshold_breach(
		self, summarize_background_jobs, record_alert, resolve_alert,
	):
		summarize_background_jobs.return_value = {
			'pending': 5,
			'timed_out': 1,
			'recent_failure_rate': 0.25,
		}
		output = StringIO()

		call_command('evaluate_worker_alerts', stdout=output)

		summarize_background_jobs.assert_called_once_with()
		self.assertEqual(record_alert.call_count, 3)
		self.assertFalse(resolve_alert.called)
		self.assertIn('3 threshold breach(es)', output.getvalue())
		for call in record_alert.call_args_list:
			self.assertIsNone(call.args[0])
			self.assertNotIn('error', call.args[2].lower())

	@override_settings(
		DEVOPS_WORKER_ALERT_PENDING_THRESHOLD=5,
		DEVOPS_WORKER_ALERT_FAILURE_RATE_PERCENT=10,
		DEVOPS_WORKER_ALERT_TIMED_OUT_THRESHOLD=1,
	)
	@mock.patch('devops.management.commands.evaluate_worker_alerts.resolve_alert', return_value=object())
	@mock.patch('devops.management.commands.evaluate_worker_alerts.record_alert')
	@mock.patch('devops.management.commands.evaluate_worker_alerts.summarize_background_jobs')
	def test_command_resolves_recovered_alerts(
		self, summarize_background_jobs, record_alert, resolve_alert,
	):
		summarize_background_jobs.return_value = {
			'pending': 4,
			'timed_out': 0,
			'recent_failure_rate': 0.09,
		}
		output = StringIO()

		call_command('evaluate_worker_alerts', stdout=output)

		self.assertFalse(record_alert.called)
		self.assertEqual(resolve_alert.call_count, 3)
		self.assertIn('3 resolved', output.getvalue())

	@override_settings(
		DEVOPS_WORKER_ALERT_PENDING_THRESHOLD=0,
		DEVOPS_WORKER_ALERT_FAILURE_RATE_PERCENT=0,
		DEVOPS_WORKER_ALERT_TIMED_OUT_THRESHOLD=0,
	)
	@mock.patch('devops.management.commands.evaluate_worker_alerts.resolve_alert')
	@mock.patch('devops.management.commands.evaluate_worker_alerts.record_alert')
	@mock.patch('devops.management.commands.evaluate_worker_alerts.summarize_background_jobs')
	def test_command_keeps_new_alerts_disabled_by_default(
		self, summarize_background_jobs, record_alert, resolve_alert,
	):
		summarize_background_jobs.return_value = {
			'pending': 100,
			'timed_out': 100,
			'recent_failure_rate': 1.0,
		}

		call_command('evaluate_worker_alerts', stdout=StringIO())

		self.assertFalse(record_alert.called)
		self.assertEqual(resolve_alert.call_count, 3)


class HealthEndpointTests(TestCase):
	def login(self, user):
		session = self.client.session
		session['is_login'] = True
		session['user_id'] = user.id
		session['user_name'] = user.user
		session.save()

	def test_liveness_is_public_and_has_no_runtime_details(self):
		response = self.client.get('/health/live/')

		self.assertEqual(response.status_code, 200)
		self.assertEqual(response.json(), {'ok': True, 'status': 'alive'})

	def test_readiness_reports_safe_database_failure(self):
		with mock.patch('PyLinux.health.database_is_ready', return_value=False):
			response = self.client.get('/health/ready/')

		self.assertEqual(response.status_code, 503)
		self.assertEqual(response.json(), {'ok': False, 'status': 'not_ready'})

	def test_runtime_status_requires_session_login(self):
		response = self.client.get('/runtime/status/')

		self.assertEqual(response.status_code, 401)
		self.assertEqual(response.json(), {'ok': False, 'code': 'unauthorized'})

	def test_runtime_status_requires_explicit_devops_admin_role(self):
		user = User.objects.create(user='runtime-viewer', email='viewer@example.com', password='x', confirm_pwd='x')
		DevOpsRole.objects.create(user=user, role=DevOpsRole.ROLE_VIEWER)
		self.login(user)

		response = self.client.get('/runtime/status/')

		self.assertEqual(response.status_code, 403)
		self.assertEqual(response.json(), {'ok': False, 'code': 'forbidden'})

	def test_runtime_status_returns_safe_aggregate_counts_for_admin(self):
		user = User.objects.create(user='runtime-admin', email='admin@example.com', password='x', confirm_pwd='x')
		DevOpsRole.objects.create(user=user, role=DevOpsRole.ROLE_ADMIN)
		host = NewLinux.objects.create(
			linux_ip='192.0.2.10', linux_port='22', linux_user='root',
		)
		AlertEvent.objects.create(host=host, status=AlertEvent.STATUS_OPEN, message='test')
		ApprovalRequest.objects.create(
			request_type=ApprovalRequest.TYPE_COMMAND,
			title='test',
			status=ApprovalRequest.STATUS_PENDING,
		)
		self.login(user)
		worker_summary = {
			'pending': 2,
			'running': 1,
			'success': 5,
			'failed': 1,
			'timed_out': 1,
			'recent_completed': 4,
			'recent_failed': 1,
			'recent_failure_rate': 25,
		}

		with mock.patch(
			'devops.services.summarize_background_jobs',
			return_value=worker_summary,
		) as summarize_background_jobs:
			response = self.client.get('/runtime/status/')

		self.assertEqual(response.status_code, 200)
		summarize_background_jobs.assert_called_once_with()
		self.assertEqual(response.json(), {
			'ok': True,
			'status': 'ready',
			'database': 'ready',
			'counts': {
				'hosts': 1,
				'active_alerts': 1,
				'pending_approvals': 1,
				'queued_work': 0,
			},
			'worker': worker_summary,
		})
		response_body = response.content.decode('utf-8')
		for forbidden_value in (
			'192.0.2.10', 'error', 'task_id', 'role', 'target_id', 'input',
		):
			with self.subTest(forbidden_value=forbidden_value):
				self.assertNotIn(forbidden_value, response_body)

	def test_runtime_status_reports_safe_database_failure(self):
		user = User.objects.create(
			user='runtime-admin-unavailable', email='unavailable@example.com',
			password='x', confirm_pwd='x',
		)
		DevOpsRole.objects.create(user=user, role=DevOpsRole.ROLE_ADMIN)
		self.login(user)

		with mock.patch('PyLinux.health.database_is_ready', return_value=False):
			response = self.client.get('/runtime/status/')

		self.assertEqual(response.status_code, 503)
		self.assertEqual(response.json(), {'ok': False, 'status': 'not_ready'})
