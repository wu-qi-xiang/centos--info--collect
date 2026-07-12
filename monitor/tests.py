import json
import socket

from django.test import TestCase
from django.urls import reverse
from unittest import mock

from devops.models import AlertEvent, AlertHistory, AuditLog, DevOpsRole
from devops.models import MetricSample
from PyLinux.crypto import decrypt_text
from RemoteLinux.models import User
from RemoteLinux.models import NewLinux
from . import services
from .crontab import monitor_send_email, parse_percent, record_collection_failure, send_threshold_alert
from .models import AlertmanagerConfig, AlertNotificationConfig, Monitor, PrometheusConfig


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

	def vue_data(self, response):
		return json.loads(response.context['vue_page_payload'])['data']

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
		self.assertContains(response, '指标查询')
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
			'name': 'VictoriaMetrics 生产',
			'prometheus_url': 'http://v-metrics.odc.sunline.cn/',
			'enabled': 'on',
		})

		self.assertEqual(response.status_code, 302)
		self.assertEqual(response.url, reverse('monitor:monitor_home'))
		config = PrometheusConfig.objects.get()
		self.assertEqual(config.name, 'VictoriaMetrics 生产')
		self.assertEqual(config.prometheus_url, 'http://v-metrics.odc.sunline.cn')
		self.assertTrue(config.enabled)
		self.assertTrue(AuditLog.objects.filter(action='保存Prometheus对接', target_id=str(config.id)).exists())

	def test_prometheus_config_rejects_secret_bearing_url(self):
		self.set_role(DevOpsRole.ROLE_OPERATOR)

		response = self.client.post(reverse('monitor:prometheus_config'), {
			'name': 'Secret Prometheus',
			'prometheus_url': 'http://user:pass@prometheus.local:9090?token=secret',
			'enabled': 'on',
		})

		self.assertEqual(response.status_code, 400)
		self.assertContains(response, '不要包含用户名、密码、Token 或查询参数', status_code=400)
		self.assertNotContains(response, 'user:pass', status_code=400)
		self.assertNotContains(response, 'token=secret', status_code=400)
		self.assertEqual(PrometheusConfig.objects.count(), 0)

	@mock.patch('monitor.views.test_prometheus_connection', return_value={'ok': True, 'message': 'Prometheus 连接正常'})
	def test_operator_can_test_prometheus_connection_without_saving(self, test_connection):
		self.set_role(DevOpsRole.ROLE_OPERATOR)

		response = self.client.post(reverse('monitor:prometheus_test'), {
			'name': 'VictoriaMetrics 测试',
			'prometheus_url': 'http://v-metrics.odc.sunline.cn/',
			'enabled': 'on',
		})

		self.assertEqual(response.status_code, 200)
		self.assertContains(response, 'Prometheus 连接正常')
		self.assertEqual(PrometheusConfig.objects.count(), 0)
		self.assertEqual(test_connection.call_args[0][0].name, 'VictoriaMetrics 测试')
		self.assertEqual(test_connection.call_args[0][0].prometheus_url, 'http://v-metrics.odc.sunline.cn')

	def test_integration_page_exposes_safe_common_payload_and_forms(self):
		prometheus = PrometheusConfig.objects.create(
			name='生产 Prometheus',
			prometheus_url='http://prometheus.local:9090',
			enabled=True,
		)
		alertmanager = AlertmanagerConfig.objects.create(
			name='生产 Alertmanager',
			alertmanager_url='http://alertmanager.local:9093',
			enabled=False,
		)

		response = self.client.get(reverse('monitor:prometheus_config'))
		data = self.vue_data(response)

		self.assertEqual(response.status_code, 200)
		self.assertEqual(json.loads(response.context['vue_page_payload'])['kind'], 'monitor-integrations')
		self.assertTrue(data['can_manage_integrations'])
		self.assertTrue(data['csrf'])
		self.assertEqual(len(data['integrations']), 2)
		self.assertEqual(set(data['integrations'][0]), {
			'id', 'kind', 'kind_label', 'name', 'url', 'enabled', 'updated_at', 'edit_url', 'delete_url',
		})
		self.assertEqual(data['integrations'][0]['edit_url'], reverse('monitor:prometheus_update', args=[prometheus.id]))
		self.assertEqual(data['integrations'][1]['delete_url'], reverse('monitor:alertmanager_delete', args=[alertmanager.id]))
		self.assertEqual(data['prometheus_form']['action'], reverse('monitor:prometheus_config'))
		self.assertEqual(data['prometheus_form']['test_action'], reverse('monitor:prometheus_test'))
		self.assertEqual(data['alertmanager_form']['action'], reverse('monitor:alertmanager_create'))
		self.assertEqual(data['alertmanager_form']['test_action'], reverse('monitor:alertmanager_test'))

	def test_operator_can_create_multiple_named_prometheus_integrations(self):
		self.set_role(DevOpsRole.ROLE_OPERATOR)
		PrometheusConfig.objects.create(
			name='Prometheus A',
			prometheus_url='http://prometheus-a.local:9090',
			enabled=True,
		)

		response = self.client.post(reverse('monitor:prometheus_config'), {
			'name': 'Prometheus B',
			'prometheus_url': 'http://prometheus-b.local:9090',
			'enabled': 'on',
		})

		self.assertEqual(response.status_code, 302)
		self.assertEqual(PrometheusConfig.objects.count(), 2)
		created = PrometheusConfig.objects.get(name='Prometheus B')
		self.assertTrue(AuditLog.objects.filter(action='保存Prometheus对接', target_id=str(created.id)).exists())

	def test_operator_can_update_and_delete_prometheus_with_audits(self):
		self.set_role(DevOpsRole.ROLE_OPERATOR)
		config = PrometheusConfig.objects.create(
			name='旧 Prometheus',
			prometheus_url='http://old-prometheus.local:9090',
			enabled=True,
		)

		response = self.client.post(reverse('monitor:prometheus_update', args=[config.id]), {
			'name': '新 Prometheus',
			'prometheus_url': 'http://new-prometheus.local:9090/',
		})

		self.assertEqual(response.status_code, 302)
		config.refresh_from_db()
		self.assertEqual(config.name, '新 Prometheus')
		self.assertEqual(config.prometheus_url, 'http://new-prometheus.local:9090')
		self.assertFalse(config.enabled)
		self.assertTrue(AuditLog.objects.filter(action='更新Prometheus对接', target_id=str(config.id)).exists())
		self.assertEqual(self.client.get(reverse('monitor:prometheus_delete', args=[config.id])).status_code, 405)

		response = self.client.post(reverse('monitor:prometheus_delete', args=[config.id]))

		self.assertEqual(response.status_code, 302)
		self.assertEqual(response.url, reverse('monitor:monitor_home'))
		self.assertFalse(PrometheusConfig.objects.filter(id=config.id).exists())
		self.assertTrue(AuditLog.objects.filter(action='删除Prometheus对接', target_id=str(config.id)).exists())

	@mock.patch('monitor.views.test_prometheus_connection', return_value={'ok': True, 'message': 'Prometheus 连接正常'})
	def test_prometheus_connection_test_does_not_update_existing_record(self, test_connection):
		self.set_role(DevOpsRole.ROLE_OPERATOR)
		config = PrometheusConfig.objects.create(
			name='已保存 Prometheus',
			prometheus_url='http://saved-prometheus.local:9090',
			enabled=True,
		)

		response = self.client.post(reverse('monitor:prometheus_test'), {
			'id': config.id,
			'name': '仅测试 Prometheus',
			'prometheus_url': 'http://test-prometheus.local:9090',
			'enabled': 'on',
		})

		self.assertEqual(response.status_code, 200)
		config.refresh_from_db()
		self.assertEqual(config.name, '已保存 Prometheus')
		self.assertEqual(config.prometheus_url, 'http://saved-prometheus.local:9090')
		self.assertEqual(test_connection.call_args[0][0].name, '仅测试 Prometheus')

	def test_operator_can_create_update_and_delete_alertmanager_with_audits(self):
		self.set_role(DevOpsRole.ROLE_OPERATOR)

		response = self.client.post(reverse('monitor:alertmanager_create'), {
			'name': 'Alertmanager 生产',
			'alertmanager_url': 'http://alertmanager.local:9093/',
			'enabled': 'on',
		})

		self.assertEqual(response.status_code, 302)
		config = AlertmanagerConfig.objects.get()
		self.assertEqual(config.name, 'Alertmanager 生产')
		self.assertEqual(config.alertmanager_url, 'http://alertmanager.local:9093')
		self.assertTrue(AuditLog.objects.filter(action='保存Alertmanager对接', target_id=str(config.id)).exists())

		response = self.client.post(reverse('monitor:alertmanager_update', args=[config.id]), {
			'name': 'Alertmanager 灾备',
			'alertmanager_url': 'https://alertmanager-dr.local:9093',
		})

		self.assertEqual(response.status_code, 302)
		config.refresh_from_db()
		self.assertEqual(config.name, 'Alertmanager 灾备')
		self.assertFalse(config.enabled)
		self.assertTrue(AuditLog.objects.filter(action='更新Alertmanager对接', target_id=str(config.id)).exists())
		self.assertEqual(self.client.get(reverse('monitor:alertmanager_delete', args=[config.id])).status_code, 405)

		response = self.client.post(reverse('monitor:alertmanager_delete', args=[config.id]))

		self.assertEqual(response.status_code, 302)
		self.assertEqual(response.url, reverse('monitor:monitor_home'))
		self.assertFalse(AlertmanagerConfig.objects.filter(id=config.id).exists())
		self.assertTrue(AuditLog.objects.filter(action='删除Alertmanager对接', target_id=str(config.id)).exists())

	def test_alertmanager_rejects_secret_bearing_url_without_echoing_it(self):
		self.set_role(DevOpsRole.ROLE_OPERATOR)

		response = self.client.post(reverse('monitor:alertmanager_create'), {
			'name': 'Secret Alertmanager',
			'alertmanager_url': 'http://user:pass@alertmanager.local:9093?token=secret',
			'enabled': 'on',
		})

		self.assertEqual(response.status_code, 400)
		self.assertContains(response, '不要包含用户名、密码、Token 或查询参数', status_code=400)
		self.assertNotContains(response, 'user:pass', status_code=400)
		self.assertNotContains(response, 'token=secret', status_code=400)
		self.assertEqual(AlertmanagerConfig.objects.count(), 0)

	@mock.patch('monitor.views.test_alertmanager_connection', return_value={'ok': True, 'message': 'Alertmanager 连接正常'})
	def test_operator_can_test_alertmanager_connection_without_saving(self, test_connection):
		self.set_role(DevOpsRole.ROLE_OPERATOR)

		response = self.client.post(reverse('monitor:alertmanager_test'), {
			'name': 'Alertmanager 测试',
			'alertmanager_url': 'http://alertmanager.local:9093/',
			'enabled': 'on',
		})

		self.assertEqual(response.status_code, 200)
		self.assertContains(response, 'Alertmanager 连接正常')
		self.assertEqual(AlertmanagerConfig.objects.count(), 0)
		self.assertEqual(test_connection.call_args[0][0].alertmanager_url, 'http://alertmanager.local:9093')

	def test_viewer_cannot_write_or_test_alertmanager_integrations(self):
		self.set_role(DevOpsRole.ROLE_VIEWER)
		config = AlertmanagerConfig.objects.create(
			name='只读 Alertmanager',
			alertmanager_url='http://alertmanager.local:9093',
			enabled=True,
		)
		payload = {
			'name': '禁止变更',
			'alertmanager_url': 'http://denied.local:9093',
			'enabled': 'on',
		}

		responses = [
			self.client.post(reverse('monitor:alertmanager_create'), payload),
			self.client.post(reverse('monitor:alertmanager_test'), payload),
			self.client.post(reverse('monitor:alertmanager_update', args=[config.id]), payload),
			self.client.post(reverse('monitor:alertmanager_delete', args=[config.id])),
		]

		self.assertEqual([response.status_code for response in responses], [403, 403, 403, 403])
		config.refresh_from_db()
		self.assertEqual(config.name, '只读 Alertmanager')
		self.assertEqual(AlertmanagerConfig.objects.count(), 1)

	def test_monitor_home_lists_both_integration_types_for_viewer(self):
		self.set_role(DevOpsRole.ROLE_VIEWER)
		PrometheusConfig.objects.create(
			name='Dashboard Prometheus',
			prometheus_url='http://prometheus.local:9090',
			enabled=True,
		)
		AlertmanagerConfig.objects.create(
			name='Dashboard Alertmanager',
			alertmanager_url='http://alertmanager.local:9093',
			enabled=True,
		)

		response = self.client.get(reverse('monitor:monitor_home'))
		data = self.vue_data(response)

		self.assertEqual(response.status_code, 200)
		self.assertFalse(data['can_manage_integrations'])
		self.assertTrue(data['csrf'])
		self.assertEqual([item['kind'] for item in data['integrations']], ['prometheus', 'alertmanager'])
		self.assertEqual([item['name'] for item in data['integrations']], ['Dashboard Prometheus', 'Dashboard Alertmanager'])

	def test_alert_query_requires_enabled_prometheus_config(self):
		response = self.client.get(reverse('monitor:alert_query'), {'query': 'up'})
		data = self.vue_data(response)

		self.assertEqual(response.status_code, 400)
		self.assertEqual(data['query'], 'up')
		self.assertEqual(data['table'], services.empty_prometheus_table())
		self.assertEqual(data['error'], '请先配置并启用 Prometheus 对接')

	@mock.patch('monitor.views.query_prometheus')
	def test_alert_query_preserves_bookmarked_query_as_normalized_table(self, query_prometheus_mock):
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
		data = self.vue_data(response)

		self.assertEqual(response.status_code, 200)
		self.assertEqual(response.context['vue_page_title'], '指标查询')
		self.assertEqual(data['query'], 'up')
		self.assertEqual(data['execute_url'], reverse('monitor:metric_query_execute'))
		self.assertTrue(data['csrf'])
		self.assertEqual(data['error'], '')
		self.assertEqual(data['table']['label_columns'], ['job'])
		self.assertEqual(data['table']['rows'][0]['labels'], {'job': 'node'})
		query_prometheus_mock.assert_called_once()

	@mock.patch('monitor.views.query_prometheus')
	def test_metric_query_execute_uses_first_enabled_prometheus_deterministically(self, query_prometheus_mock):
		PrometheusConfig.objects.create(
			name='Disabled First',
			prometheus_url='http://disabled.local:9090',
			enabled=False,
		)
		first_enabled = PrometheusConfig.objects.create(
			name='Enabled First',
			prometheus_url='http://enabled-first.local:9090',
			enabled=True,
		)
		PrometheusConfig.objects.create(
			name='Enabled Second',
			prometheus_url='http://enabled-second.local:9090',
			enabled=True,
		)
		query_prometheus_mock.return_value = {
			'ok': True,
			'body': {
				'status': 'success',
				'data': {'resultType': 'scalar', 'result': [1, '2']},
			},
		}

		response = self.client.post(reverse('monitor:metric_query_execute'), {'query': '  up  '})

		self.assertEqual(response.status_code, 200)
		self.assertEqual(response.json()['query'], 'up')
		self.assertEqual(response.json()['table']['rows'][0]['value'], '2')
		self.assertEqual(query_prometheus_mock.call_args[0][0].id, first_enabled.id)
		self.assertEqual(query_prometheus_mock.call_args[0][1], 'up')

	def test_metric_query_page_payload_and_dashboard_use_renamed_text(self):
		query_response = self.client.get(reverse('monitor:alert_query'))
		query_data = self.vue_data(query_response)
		home_response = self.client.get(reverse('monitor:monitor_home'))
		home_data = self.vue_data(home_response)

		self.assertEqual(query_response.status_code, 200)
		self.assertEqual(query_response.context['vue_page_title'], '指标查询')
		self.assertEqual(query_data['query'], '')
		self.assertEqual(query_data['table'], services.empty_prometheus_table())
		self.assertEqual(query_data['execute_url'], reverse('monitor:metric_query_execute'))
		self.assertIn('指标查询', [item['label'] for item in query_data['actions']])
		self.assertIn('指标查询', home_data['subtitle'])

	def test_metric_query_execute_requires_login_and_post(self):
		self.client.get(reverse('monitor:alert_query'))
		self.assertEqual(self.client.get(reverse('monitor:metric_query_execute')).status_code, 405)

		session = self.client.session
		session.clear()
		session.save()
		response = self.client.post(reverse('monitor:metric_query_execute'), {'query': 'up'})

		self.assertEqual(response.status_code, 302)
		self.assertEqual(response.url, reverse('userprofile:login'))

	def test_metric_query_execute_validates_query(self):
		empty_response = self.client.post(reverse('monitor:metric_query_execute'), {'query': '   '})
		long_response = self.client.post(reverse('monitor:metric_query_execute'), {'query': 'x' * 2001})

		self.assertEqual(empty_response.status_code, 400)
		self.assertEqual(empty_response.json(), {'ok': False, 'message': '请输入 PromQL 查询语句'})
		self.assertEqual(long_response.status_code, 400)
		self.assertEqual(
			long_response.json(),
			{'ok': False, 'message': 'PromQL 查询语句不能超过 2000 个字符'},
		)

	def test_metric_query_execute_requires_enabled_prometheus(self):
		PrometheusConfig.objects.create(
			prometheus_url='http://disabled.local:9090',
			enabled=False,
		)

		response = self.client.post(reverse('monitor:metric_query_execute'), {'query': 'up'})

		self.assertEqual(response.status_code, 400)
		self.assertEqual(
			response.json(),
			{'ok': False, 'message': '请先配置并启用 Prometheus 对接'},
		)

	@mock.patch('monitor.views.query_prometheus', return_value={'ok': False, 'message': 'Prometheus 查询失败'})
	def test_metric_query_execute_returns_safe_upstream_failure(self, query_prometheus_mock):
		PrometheusConfig.objects.create(
			prometheus_url='http://prometheus.local:9090',
			enabled=True,
		)

		response = self.client.post(reverse('monitor:metric_query_execute'), {'query': 'up'})

		self.assertEqual(response.status_code, 502)
		self.assertEqual(response.json(), {'ok': False, 'message': 'Prometheus 查询失败'})
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


class PrometheusServiceTests(TestCase):
	@mock.patch('monitor.services.prometheus_get_json')
	def test_query_masks_upstream_error_details(self, prometheus_get_json):
		config = PrometheusConfig(
			prometheus_url='http://prometheus.local:9090',
			enabled=True,
		)
		prometheus_get_json.return_value = {
			'ok': True,
			'body': {
				'status': 'error',
				'errorType': 'execution',
				'error': 'upstream internal detail and original expression',
			},
		}

		result = services.query_prometheus(config, 'private_metric{scope="internal"}')

		self.assertEqual(result, {'ok': False, 'message': 'Prometheus 查询失败'})
		self.assertNotIn('upstream internal detail', result['message'])
		self.assertNotIn('private_metric', result['message'])

	@mock.patch('monitor.services.urlrequest.urlopen')
	def test_get_json_returns_safe_message_for_dns_failure(self, urlopen):
		urlopen.side_effect = socket.gaierror(-2, 'resolver internal detail')
		config = PrometheusConfig(
			prometheus_url='http://prometheus.local:9090',
			enabled=True,
		)

		result = services.prometheus_get_json(config, '/api/v1/query', {'query': 'vector(1)'})

		self.assertEqual(result, {'ok': False, 'message': 'Prometheus 请求失败，请检查地址和网络'})
		self.assertNotIn('resolver internal detail', result['message'])

	def test_normalize_vector_sorts_labels_and_preserves_samples(self):
		table = services.normalize_prometheus_result({
			'data': {
				'resultType': 'vector',
				'result': [{
					'metric': {'job': 'node', '__name__': 'up', 'instance': 'host-a'},
					'value': [1710000000.5, '1'],
				}],
			},
		})

		self.assertEqual(table['result_type'], 'vector')
		self.assertEqual(table['label_columns'], ['__name__', 'instance', 'job'])
		self.assertEqual(table['total_rows'], 1)
		self.assertFalse(table['truncated'])
		self.assertEqual(table['rows'][0], {
			'labels': {'__name__': 'up', 'instance': 'host-a', 'job': 'node'},
			'timestamp': 1710000000.5,
			'value': '1',
		})

	def test_normalize_matrix_creates_one_row_per_sample(self):
		table = services.normalize_prometheus_result({
			'data': {
				'resultType': 'matrix',
				'result': [{
					'metric': {'instance': 'host-a'},
					'values': [[1, '10'], [2, '20']],
				}],
			},
		})

		self.assertEqual(table['label_columns'], ['instance'])
		self.assertEqual(table['total_rows'], 2)
		self.assertEqual([row['timestamp'] for row in table['rows']], [1, 2])
		self.assertEqual([row['value'] for row in table['rows']], ['10', '20'])

	def test_normalize_scalar_and_string_results(self):
		for result_type, value in (('scalar', '3.14'), ('string', 'ready')):
			with self.subTest(result_type=result_type):
				table = services.normalize_prometheus_result({
					'data': {'resultType': result_type, 'result': [10, value]},
				})

				self.assertEqual(table['result_type'], result_type)
				self.assertEqual(table['label_columns'], [])
				self.assertEqual(table['rows'], [{'labels': {}, 'timestamp': 10, 'value': value}])

	def test_normalize_caps_rows_and_preserves_total_count(self):
		result = [
			{'metric': {'instance': 'host-%s' % index}, 'value': [index, str(index)]}
			for index in range(services.PROMETHEUS_TABLE_MAX_ROWS + 7)
		]

		table = services.normalize_prometheus_result({
			'data': {'resultType': 'vector', 'result': result},
		})

		self.assertEqual(len(table['rows']), services.PROMETHEUS_TABLE_MAX_ROWS)
		self.assertEqual(table['total_rows'], services.PROMETHEUS_TABLE_MAX_ROWS + 7)
		self.assertTrue(table['truncated'])

	@mock.patch('monitor.services.prometheus_get_json')
	def test_connection_uses_buildinfo_endpoint_for_victoriametrics(self, prometheus_get_json):
		config = PrometheusConfig(
			prometheus_url='http://v-metrics.odc.sunline.cn',
			enabled=True,
		)
		prometheus_get_json.return_value = {
			'ok': True,
			'body': {'status': 'success', 'data': {'version': 'victoria-metrics'}},
		}

		result = services.test_prometheus_connection(config)

		self.assertEqual(result, {'ok': True, 'message': 'Prometheus 连接正常'})
		prometheus_get_json.assert_called_once_with(
			config,
			'/api/v1/status/buildinfo',
			require_enabled=False,
		)

	@mock.patch('monitor.services.prometheus_get_json')
	def test_connection_rejects_unsuccessful_buildinfo_response(self, prometheus_get_json):
		config = PrometheusConfig(
			prometheus_url='http://v-metrics.odc.sunline.cn',
			enabled=True,
		)
		prometheus_get_json.return_value = {
			'ok': True,
			'body': {'status': 'error', 'error': 'unsupported'},
		}

		result = services.test_prometheus_connection(config)

		self.assertEqual(result, {'ok': False, 'message': 'Prometheus 返回状态异常'})
		prometheus_get_json.assert_called_once_with(
			config,
			'/api/v1/status/buildinfo',
			require_enabled=False,
		)

	@mock.patch('monitor.services.prometheus_get_json')
	def test_connection_preserves_request_failure(self, prometheus_get_json):
		config = PrometheusConfig(
			prometheus_url='http://v-metrics.odc.sunline.cn',
			enabled=True,
		)
		prometheus_get_json.return_value = {
			'ok': False,
			'message': 'Prometheus 请求失败，请检查地址和网络',
		}

		result = services.test_prometheus_connection(config)

		self.assertEqual(result, prometheus_get_json.return_value)
		prometheus_get_json.assert_called_once_with(
			config,
			'/api/v1/status/buildinfo',
			require_enabled=False,
		)

	@mock.patch('monitor.services.urlrequest.urlopen')
	def test_connection_can_test_disabled_config(self, urlopen):
		urlopen.return_value.read.return_value = b'{"status": "success"}'
		config = PrometheusConfig(
			prometheus_url='http://prometheus.local:9090',
			enabled=False,
		)

		result = services.test_prometheus_connection(config)

		self.assertEqual(result, {'ok': True, 'message': 'Prometheus 连接正常'})
		self.assertEqual(
			urlopen.call_args[0][0].full_url,
			'http://prometheus.local:9090/api/v1/status/buildinfo',
		)

	@mock.patch('monitor.services.urlrequest.urlopen')
	def test_get_json_rejects_non_object_json(self, urlopen):
		urlopen.return_value.read.return_value = b'[]'
		config = PrometheusConfig(
			prometheus_url='http://prometheus.local:9090',
			enabled=True,
		)

		result = services.prometheus_get_json(config, '/api/v1/query')

		self.assertEqual(result, {'ok': False, 'message': 'Prometheus 返回格式异常'})

	@mock.patch('monitor.services.urlrequest.urlopen')
	def test_get_json_requires_enabled_config_by_default(self, urlopen):
		config = PrometheusConfig(
			prometheus_url='http://prometheus.local:9090',
			enabled=False,
		)

		result = services.prometheus_get_json(config, '/api/v1/query')

		self.assertEqual(result, {'ok': False, 'message': 'Prometheus 未配置或未启用'})
		urlopen.assert_not_called()


class AlertmanagerServiceTests(TestCase):
	@mock.patch('monitor.services.urlrequest.urlopen')
	def test_connection_can_test_disabled_config(self, urlopen):
		urlopen.return_value.read.return_value = b'{"cluster": {"status": "ready"}}'
		config = AlertmanagerConfig(
			alertmanager_url='http://alertmanager.local:9093',
			enabled=False,
		)

		result = services.test_alertmanager_connection(config)

		self.assertEqual(result, {'ok': True, 'message': 'Alertmanager 连接正常'})
		self.assertEqual(
			urlopen.call_args[0][0].full_url,
			'http://alertmanager.local:9093/api/v2/status',
		)

	@mock.patch('monitor.services.urlrequest.urlopen')
	def test_connection_rejects_invalid_or_non_object_json(self, urlopen):
		config = AlertmanagerConfig(
			alertmanager_url='http://alertmanager.local:9093',
			enabled=True,
		)
		for response_body in (b'not-json', b'[]'):
			with self.subTest(response_body=response_body):
				urlopen.return_value.read.return_value = response_body

				result = services.test_alertmanager_connection(config)

				self.assertEqual(result, {'ok': False, 'message': 'Alertmanager 返回格式异常'})

	@mock.patch('monitor.services.urlrequest.urlopen', side_effect=IOError('network unavailable'))
	def test_connection_returns_safe_request_error(self, urlopen):
		config = AlertmanagerConfig(
			alertmanager_url='http://alertmanager.local:9093',
			enabled=True,
		)

		result = services.test_alertmanager_connection(config)

		self.assertEqual(
			result,
			{'ok': False, 'message': 'Alertmanager 请求失败，请检查地址和网络'},
		)
		urlopen.assert_called_once()


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
