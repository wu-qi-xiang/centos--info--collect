from django.test import TestCase
from django.urls import reverse
from unittest import mock

from devops.models import AlertEvent, AlertHistory, AuditLog, DevOpsRole
from devops.models import MetricSample
from PyLinux.crypto import decrypt_text
from RemoteLinux.models import User
from RemoteLinux.models import NewLinux
from .crontab import monitor_send_email, parse_percent, record_collection_failure, send_threshold_alert
from .models import AlertNotificationConfig, Monitor, PrometheusConfig


class MonitorSecurityTests(TestCase):
	def setUp(self):
		self.user = User.objects.create(
			user='tester',
			email='tester@example.com',
			password='plain-password',
			confirm_pwd='plain-password',
		)
		session = self.client.session
		session['is_login'] = True
		session['user_id'] = self.user.id
		session['user_name'] = self.user.user
		session.save()

	def set_role(self, role):
		DevOpsRole.objects.update_or_create(user=self.user, defaults={'role': role})

	def test_viewer_cannot_create_monitor_config_when_roles_are_configured(self):
		self.set_role(DevOpsRole.ROLE_VIEWER)

		response = self.client.post(reverse('monitor:monitor_index'), {
			'monitor_email': 'ops@example.com',
			'monitor_cpu': '80',
			'monitor_men': '85',
			'monitor_disk': '90',
		})

		self.assertEqual(response.status_code, 403)
		self.assertEqual(Monitor.objects.count(), 0)

	def test_operator_can_create_monitor_config(self):
		self.set_role(DevOpsRole.ROLE_OPERATOR)

		response = self.client.post(reverse('monitor:monitor_index'), {
			'monitor_email': 'ops@example.com',
			'monitor_cpu': '80',
			'monitor_men': '85',
			'monitor_disk': '90',
		})

		self.assertEqual(response.status_code, 302)
		self.assertEqual(Monitor.objects.count(), 1)
		monitor = Monitor.objects.get()
		self.assertTrue(AuditLog.objects.filter(action='创建监控阈值', target_id=str(monitor.id)).exists())

	def test_monitor_index_uses_real_alert_state_not_placeholder_values(self):
		host = NewLinux.objects.create(
			linux_name='alert-host',
			linux_ip='127.0.0.1',
			linux_hostname='alert-host',
			linux_port='22',
			linux_user='root',
			linux_passwd='',
		)
		AlertEvent.objects.create(
			host=host,
			metric='cpu',
			message='CPU usage high',
			status=AlertEvent.STATUS_OPEN,
			fingerprint='alert-host:cpu',
		)

		response = self.client.get(reverse('monitor:monitor_index'))

		self.assertEqual(response.status_code, 200)
		self.assertEqual(response.context['open_alert_count'], 1)
		self.assertContains(response, 'CPU usage high')
		self.assertNotContains(response, '服务器-01 CPU使用率达到85%')
		self.assertNotContains(response, '2分钟前')

	def test_operator_cannot_create_second_monitor_config(self):
		self.set_role(DevOpsRole.ROLE_OPERATOR)
		Monitor.objects.create(
			monitor_email='old@example.com',
			monitor_cpu='80',
			monitor_men='85',
			monitor_disk='90',
		)

		response = self.client.post(reverse('monitor:monitor_index'), {
			'monitor_email': 'ops@example.com',
			'monitor_cpu': '70',
			'monitor_men': '75',
			'monitor_disk': '80',
		})

		self.assertEqual(response.status_code, 400)
		self.assertContains(response, '已存有告警数据', status_code=400)
		self.assertEqual(Monitor.objects.count(), 1)

	def test_operator_cannot_create_monitor_config_with_invalid_threshold(self):
		self.set_role(DevOpsRole.ROLE_OPERATOR)

		response = self.client.post(reverse('monitor:monitor_index'), {
			'monitor_email': 'ops@example.com',
			'monitor_cpu': '150%',
			'monitor_men': '85',
			'monitor_disk': '90',
		})

		self.assertEqual(response.status_code, 400)
		self.assertContains(response, '提交失败，请检查以下内容', status_code=400)
		self.assertContains(response, '请输入 0 到 100 之间的百分比', status_code=400)
		self.assertEqual(Monitor.objects.count(), 0)

	def test_viewer_cannot_update_monitor_config_when_roles_are_configured(self):
		self.set_role(DevOpsRole.ROLE_VIEWER)
		monitor = Monitor.objects.create(
			monitor_email='old@example.com',
			monitor_cpu='80',
			monitor_men='85',
			monitor_disk='90',
		)

		response = self.client.post(reverse('monitor:monitor_update', args=[monitor.id]), {
			'monitor_email': 'new@example.com',
			'monitor_cpu': '70',
			'monitor_men': '75',
			'monitor_disk': '80',
		})

		monitor.refresh_from_db()
		self.assertEqual(response.status_code, 403)
		self.assertEqual(monitor.monitor_email, 'old@example.com')

	def test_operator_update_monitor_config_records_audit(self):
		self.set_role(DevOpsRole.ROLE_OPERATOR)
		monitor = Monitor.objects.create(
			monitor_email='old@example.com',
			monitor_cpu='80',
			monitor_men='85',
			monitor_disk='90',
		)

		response = self.client.post(reverse('monitor:monitor_update', args=[monitor.id]), {
			'monitor_email': 'new@example.com',
			'monitor_cpu': '70',
			'monitor_men': '75',
			'monitor_disk': '80',
		})

		self.assertEqual(response.status_code, 302)
		self.assertEqual(response.url, reverse('monitor:monitor_index'))
		self.assertTrue(AuditLog.objects.filter(action='更新监控阈值', target_id=str(monitor.id)).exists())

	def test_operator_update_monitor_config_invalid_submission_keeps_existing_values(self):
		self.set_role(DevOpsRole.ROLE_OPERATOR)
		monitor = Monitor.objects.create(
			monitor_email='old@example.com',
			monitor_cpu='80',
			monitor_men='85',
			monitor_disk='90',
		)

		response = self.client.post(reverse('monitor:monitor_update', args=[monitor.id]), {
			'monitor_email': 'new@example.com',
			'monitor_cpu': '101',
			'monitor_men': '75',
			'monitor_disk': '80',
		})

		monitor.refresh_from_db()
		self.assertEqual(response.status_code, 400)
		self.assertContains(response, '提交失败，请检查以下内容', status_code=400)
		self.assertEqual(monitor.monitor_email, 'old@example.com')
		self.assertEqual(monitor.monitor_cpu, '80')

	def test_monitor_home_renders_management_links(self):
		PrometheusConfig.objects.create(prometheus_url='http://prometheus.local:9090', enabled=True)
		Monitor.objects.create(
			monitor_email='ops@example.com',
			monitor_cpu='80',
			monitor_men='85',
			monitor_disk='90',
		)

		response = self.client.get(reverse('monitor:monitor_home'))

		self.assertEqual(response.status_code, 200)
		self.assertContains(response, '监控管理')
		self.assertContains(response, '监控对接')
		self.assertContains(response, '告警查询')
		self.assertContains(response, '告警设置')

	def test_viewer_cannot_save_prometheus_config_when_roles_are_configured(self):
		self.set_role(DevOpsRole.ROLE_VIEWER)

		response = self.client.post(reverse('monitor:prometheus_config'), {
			'prometheus_url': 'http://prometheus.local:9090',
			'enabled': 'on',
		})

		self.assertEqual(response.status_code, 403)
		self.assertEqual(PrometheusConfig.objects.count(), 0)

	def test_operator_can_save_prometheus_config(self):
		self.set_role(DevOpsRole.ROLE_OPERATOR)

		response = self.client.post(reverse('monitor:prometheus_config'), {
			'prometheus_url': 'http://prometheus.local:9090/',
			'enabled': 'on',
		})

		self.assertEqual(response.status_code, 302)
		self.assertEqual(response.url, reverse('monitor:monitor_home'))
		config = PrometheusConfig.objects.get()
		self.assertEqual(config.prometheus_url, 'http://prometheus.local:9090')
		self.assertTrue(config.enabled)
		self.assertTrue(AuditLog.objects.filter(action='保存Prometheus对接', target_id=str(config.id)).exists())

	def test_prometheus_config_rejects_secret_bearing_url(self):
		self.set_role(DevOpsRole.ROLE_OPERATOR)

		response = self.client.post(reverse('monitor:prometheus_config'), {
			'prometheus_url': 'http://user:pass@prometheus.local:9090?token=secret',
			'enabled': 'on',
		})

		self.assertEqual(response.status_code, 400)
		self.assertContains(response, '不要包含用户名、密码、Token 或查询参数', status_code=400)
		self.assertEqual(PrometheusConfig.objects.count(), 0)

	@mock.patch('monitor.views.test_prometheus_connection', return_value={'ok': True, 'message': 'Prometheus 连接正常'})
	def test_operator_can_test_prometheus_connection_without_saving(self, test_connection):
		self.set_role(DevOpsRole.ROLE_OPERATOR)

		response = self.client.post(reverse('monitor:prometheus_test'), {
			'prometheus_url': 'http://prometheus.local:9090',
			'enabled': 'on',
		})

		self.assertEqual(response.status_code, 200)
		self.assertContains(response, 'Prometheus 连接正常')
		self.assertEqual(PrometheusConfig.objects.count(), 0)
		self.assertEqual(test_connection.call_args[0][0].prometheus_url, 'http://prometheus.local:9090')

	def test_alert_query_requires_enabled_prometheus_config(self):
		response = self.client.get(reverse('monitor:alert_query'), {'query': 'up'})

		self.assertEqual(response.status_code, 400)
		self.assertContains(response, '请先配置并启用 Prometheus 对接', status_code=400)

	@mock.patch('monitor.views.query_prometheus')
	def test_alert_query_uses_prometheus_service(self, query_prometheus_mock):
		PrometheusConfig.objects.create(prometheus_url='http://prometheus.local:9090', enabled=True)
		query_prometheus_mock.return_value = {
			'ok': True,
			'body': {
				'status': 'success',
				'data': {
					'resultType': 'vector',
					'result': [{'metric': {'job': 'node'}, 'value': [1, '1']}],
				},
			},
		}

		response = self.client.get(reverse('monitor:alert_query'), {'query': 'up'})

		self.assertEqual(response.status_code, 200)
		self.assertContains(response, 'up')
		self.assertContains(response, 'node')
		query_prometheus_mock.assert_called_once()

	def test_alert_notifications_page_renders(self):
		response = self.client.get(reverse('monitor:alert_notifications'))

		self.assertEqual(response.status_code, 200)
		self.assertContains(response, '告警通知')
		self.assertContains(response, '飞书')
		self.assertContains(response, '企业微信')

	def test_viewer_cannot_save_alert_notifications_when_roles_are_configured(self):
		self.set_role(DevOpsRole.ROLE_VIEWER)

		response = self.client.post(reverse('monitor:alert_notifications'), {
			'feishu_enabled': 'on',
			'feishu_name': 'feishu',
			'feishu_webhook_url': 'https://open.feishu.cn/open-apis/bot/v2/hook/test',
		})

		self.assertEqual(response.status_code, 403)
		self.assertEqual(AlertNotificationConfig.objects.count(), 0)

	def test_operator_can_save_alert_notifications_encrypted(self):
		self.set_role(DevOpsRole.ROLE_OPERATOR)

		response = self.client.post(reverse('monitor:alert_notifications'), {
			'feishu_enabled': 'on',
			'feishu_name': 'feishu',
			'feishu_webhook_url': 'https://open.feishu.cn/open-apis/bot/v2/hook/test',
			'wecom_enabled': 'on',
			'wecom_name': 'wecom',
			'wecom_webhook_url': 'https://qyapi.weixin.qq.com/cgi-bin/webhook/send',
		})

		self.assertEqual(response.status_code, 302)
		feishu = AlertNotificationConfig.objects.get(provider=AlertNotificationConfig.PROVIDER_FEISHU)
		wecom = AlertNotificationConfig.objects.get(provider=AlertNotificationConfig.PROVIDER_WECOM)
		self.assertTrue(feishu.enabled)
		self.assertTrue(wecom.enabled)
		self.assertTrue(feishu.webhook_url.startswith('enc:'))
		self.assertEqual(decrypt_text(feishu.webhook_url), 'https://open.feishu.cn/open-apis/bot/v2/hook/test')
		self.assertTrue(AuditLog.objects.filter(action='保存告警通知').exists())

	def test_alert_notifications_blank_webhook_preserves_existing_value(self):
		self.set_role(DevOpsRole.ROLE_OPERATOR)
		config = AlertNotificationConfig.objects.create(
			provider=AlertNotificationConfig.PROVIDER_FEISHU,
			name='old',
			enabled=True,
			webhook_url='https://open.feishu.cn/open-apis/bot/v2/hook/original',
		)
		encrypted = config.webhook_url

		response = self.client.post(reverse('monitor:alert_notifications'), {
			'feishu_enabled': 'on',
			'feishu_name': 'new',
			'feishu_webhook_url': '',
		})

		self.assertEqual(response.status_code, 302)
		config.refresh_from_db()
		self.assertEqual(config.webhook_url, encrypted)
		self.assertEqual(config.decrypted_webhook_url, 'https://open.feishu.cn/open-apis/bot/v2/hook/original')
		self.assertEqual(config.name, 'new')

	def test_alert_notifications_rejects_invalid_webhook(self):
		self.set_role(DevOpsRole.ROLE_OPERATOR)

		response = self.client.post(reverse('monitor:alert_notifications'), {
			'feishu_enabled': 'on',
			'feishu_webhook_url': 'javascript:alert(1)',
		})

		self.assertEqual(response.status_code, 400)
		self.assertContains(response, 'Webhook 地址必须是 http:// 或 https://', status_code=400)
		self.assertEqual(AlertNotificationConfig.objects.count(), 0)

	@mock.patch('monitor.views.send_alert_notification', return_value={'ok': True, 'message': '测试通知发送成功'})
	def test_operator_can_test_alert_notification_without_saving(self, send_mock):
		self.set_role(DevOpsRole.ROLE_OPERATOR)

		response = self.client.post(reverse('monitor:alert_notifications_test'), {
			'provider': AlertNotificationConfig.PROVIDER_WECOM,
			'wecom_enabled': 'on',
			'wecom_name': 'wecom',
			'wecom_webhook_url': 'https://qyapi.weixin.qq.com/cgi-bin/webhook/send',
		})

		self.assertEqual(response.status_code, 200)
		self.assertContains(response, '测试通知发送成功')
		self.assertEqual(AlertNotificationConfig.objects.count(), 0)
		self.assertEqual(send_mock.call_args[0][0].provider, AlertNotificationConfig.PROVIDER_WECOM)


class MonitorCollectionTests(TestCase):
	def setUp(self):
		self.host = NewLinux.objects.create(
			linux_name='metric-host',
			linux_ip='127.0.0.1',
			linux_hostname='localhost',
			linux_port='22',
			linux_user='root',
			linux_passwd='bad-password',
		)

	def test_parse_percent_accepts_percent_and_fraction_values(self):
		self.assertEqual(parse_percent('80%'), 0.8)
		self.assertEqual(parse_percent('80'), 0.8)
		self.assertEqual(parse_percent('0.75'), 0.75)

	def test_parse_percent_rejects_invalid_or_out_of_range_values(self):
		self.assertIsNone(parse_percent('abc'))
		self.assertIsNone(parse_percent('-1'))
		self.assertIsNone(parse_percent('150%'))

	@mock.patch('monitor.crontab.print')
	def test_send_threshold_alert_skips_missing_metric_without_blocking_others(self, print_mock):
		send_threshold_alert(self.host, 'cpu', None, 0.8, '', 'subject')
		send_threshold_alert(self.host, 'memory', 0.5, 0.8, '', 'subject')

		self.assertEqual(MetricSample.objects.count(), 1)
		sample = MetricSample.objects.get()
		self.assertEqual(sample.metric, MetricSample.METRIC_MEMORY)
		self.assertEqual(sample.value, 0.5)

	@mock.patch('monitor.crontab.print')
	def test_send_threshold_alert_resolves_active_alert_when_metric_recovers(self, print_mock):
		alert = AlertEvent.objects.create(
			host=self.host,
			metric='cpu',
			message='cpu high',
			status=AlertEvent.STATUS_OPEN,
			fingerprint='%s:%s' % (self.host.id, 'cpu'),
		)

		send_threshold_alert(self.host, 'cpu', 0.2, 0.8, '', 'subject')

		alert.refresh_from_db()
		self.assertEqual(alert.status, AlertEvent.STATUS_RESOLVED)
		self.assertEqual(AlertHistory.objects.get(alert=alert).to_status, AlertEvent.STATUS_RESOLVED)

	def test_record_collection_failure_creates_critical_alert(self):
		alert, created = record_collection_failure(self.host, Exception('network down'))

		self.assertTrue(created)
		self.assertEqual(alert.metric, 'collector')
		self.assertEqual(alert.level, AlertEvent.LEVEL_CRITICAL)
		self.assertIn('监控采集失败', alert.message)

	@mock.patch('monitor.crontab.cleanup_metric_samples')
	@mock.patch('monitor.crontab.print')
	@mock.patch('monitor.crontab.collect_remote_usage', return_value={'cpu': 0.2, 'memory': 0.3, 'disk': 0.4})
	@mock.patch('monitor.crontab.create_host_ssh_client')
	def test_monitor_send_email_resolves_collection_failure_on_success(self, create_host_ssh_client, collect_remote_usage, print_mock, cleanup_metric_samples):
		Monitor.objects.create(
			monitor_email='',
			monitor_cpu='80',
			monitor_men='85',
			monitor_disk='90',
		)
		alert = AlertEvent.objects.create(
			host=self.host,
			metric='collector',
			message='collection failed',
			status=AlertEvent.STATUS_OPEN,
			fingerprint='%s:%s' % (self.host.id, 'collector'),
		)

		monitor_send_email()

		alert.refresh_from_db()
		self.assertEqual(alert.status, AlertEvent.STATUS_RESOLVED)
		cleanup_metric_samples.assert_called_once_with()
