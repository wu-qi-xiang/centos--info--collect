from django.core.exceptions import ImproperlyConfigured
from django.test import SimpleTestCase, override_settings

from .checks import development_security_warning, production_security_check
from .settings import database_config_from_env


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


class ProductionChecksTests(SimpleTestCase):
	def message_ids(self, messages):
		return set(message.id for message in messages)

	@override_settings(
		DJANGO_ENV='production',
		DEBUG=True,
		SECRET_KEY='django-insecure-change-me',
		DATA_ENCRYPTION_KEY='',
		ALLOWED_HOSTS=['*'],
		DATABASES={'default': {'ENGINE': 'django.db.backends.sqlite3', 'NAME': '/app/db.sqlite3'}},
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
