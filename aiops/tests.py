from django.test import TestCase
from django.urls import reverse
from django.utils import timezone
from unittest import mock

from RemoteLinux.models import NewLinux, User
from devops.models import AlertEvent, CommandExecution, DevOpsHostScope, HostGroup, MetricSample
from .models import AiopsAlertAnalysis, AiopsIntegration


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
			raw_payload='{}',
			summary='visible analysis',
			suggestion='visible suggestion',
		)
		AiopsAlertAnalysis.objects.create(
			alert_name='HiddenAlert',
			instance='db-01:9100',
			raw_payload='{}',
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
		self.assertEqual(config.llm_api_key, 'secret')
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
		self.assertIn('nginx', analysis.suggestion)
		post.assert_called_once()
