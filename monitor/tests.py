import json
import io
import socket
import ssl
from datetime import timedelta

from django.conf import settings
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone
from unittest import mock

from devops.models import AlertEvent, AlertHistory, AuditLog, DevOpsModulePermission, DevOpsRole, IntegrationHealthEvent, K8sCluster, MaintenanceWindow
from devops.models import MetricSample
from PyLinux.crypto import decrypt_text
from RemoteLinux.models import User
from RemoteLinux.models import NewLinux
from devops.services import record_alert, resolve_alert
from . import services
from .crontab import evaluate_service_slos_periodically, monitor_send_email, parse_percent, poll_alertmanager_notifications, process_due_oncall_escalations_periodically, record_collection_failure, send_threshold_alert, scan_compliance_baselines_daily
from .models import AlertmanagerConfig, AlertNotificationConfig, Monitor, PrometheusConfig


class MockWebhookResponse(object):
	def __init__(self, body, status=200):
		self.body = body
		self.status = status
		self.code = status

	def read(self):
		return self.body.encode('utf-8')


class SloScheduleTests(TestCase):
	def test_slo_evaluation_is_registered_every_five_minutes(self):
		self.assertIn(
			('*/5 * * * *', 'monitor.crontab.evaluate_service_slos_periodically', '>>/tmp/service_slo_evaluation.log'),
			settings.CRONJOBS,
		)

	@mock.patch('monitor.crontab.cleanup_service_slo_evaluations', return_value=3)
	@mock.patch('monitor.crontab.evaluate_enabled_service_slos')
	def test_periodic_slo_evaluation_writes_only_bounded_aggregate_audit(self, evaluate, cleanup):
		evaluate.return_value = {'evaluated': 12, 'exhausted': 2, 'unavailable': 1, 'errors': 1}

		result = evaluate_service_slos_periodically()

		self.assertEqual(result, evaluate.return_value)
		evaluate.assert_called_once_with()
		cleanup.assert_called_once_with()
		audit_log = AuditLog.objects.get(action='定期评估服务SLO', user='system')
		self.assertEqual(audit_log.target_type, 'ServiceSlo')
		self.assertEqual(audit_log.detail, '评估=12, 耗尽=2, 不可用=1, 错误=1, 清理=3')
		self.assertLessEqual(len(audit_log.detail), 200)


class OnCallEscalationScheduleTests(TestCase):
	def test_oncall_escalation_is_registered_every_minute(self):
		self.assertIn(
			('*/1 * * * *', 'monitor.crontab.process_due_oncall_escalations_periodically', '>>/tmp/oncall_escalation.log'),
			settings.CRONJOBS,
		)

	@mock.patch('monitor.crontab.print')
	@mock.patch('devops.services.process_due_oncall_escalations')
	def test_due_oncall_escalation_reports_safe_counts(self, process, print_mock):
		process.return_value = {'scanned': 3, 'escalated': 1, 'cancelled': 1, 'errors': 0}

		result = process_due_oncall_escalations_periodically()

		self.assertEqual(result, process.return_value)
		process.assert_called_once_with()
		print_mock.assert_called_once_with('值班升级扫描完成：扫描3条，升级1条，取消1条，错误0条')

	@mock.patch('monitor.crontab.print')
	@mock.patch('devops.services.process_due_oncall_escalations', side_effect=RuntimeError('notification unavailable'))
	def test_due_oncall_escalation_isolates_core_exception(self, process, print_mock):
		self.assertEqual(process_due_oncall_escalations_periodically(), {'scanned': 0, 'escalated': 0, 'cancelled': 0, 'errors': 1})

		process.assert_called_once_with()
		print_mock.assert_called_once_with('值班升级扫描失败')


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

	@mock.patch('monitor.crontab.scan_compliance_baselines', return_value=3)
	def test_daily_compliance_scan_is_scheduled_and_audited(self, scan):
		self.assertEqual(scan_compliance_baselines_daily(), 3)
		scan.assert_called_once_with()
		self.assertTrue(AuditLog.objects.filter(action='定期扫描合规基线', user='system').exists())

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

	def test_monitor_index_keeps_real_alert_context_outside_rule_page_payload(self):
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
		data = self.vue_data(response)

		self.assertEqual(response.status_code, 200)
		self.assertEqual(response.context['open_alert_count'], 1)
		self.assertNotIn('open_alert_count', data)
		self.assertNotContains(response, 'CPU usage high')
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
		self.assertNotIn('monitor', self.vue_data(response))
		self.assertNotIn('errors', self.vue_data(response))
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
		self.assertNotIn('monitor', self.vue_data(response))
		self.assertNotIn('errors', self.vue_data(response))
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
		self.assertNotIn('monitor', self.vue_data(response))
		self.assertNotIn('errors', self.vue_data(response))
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

	@mock.patch('monitor.views.record_integration_health_event')
	@mock.patch('monitor.views.test_prometheus_connection', return_value={'ok': True, 'message': 'Prometheus 连接正常'})
	def test_operator_can_test_prometheus_connection_without_saving(self, test_connection, record_health):
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
		record_health.assert_not_called()

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
		self.assertEqual(data['prometheus_integrations'], [data['integrations'][0]])
		self.assertEqual(data['alertmanager_integrations'], [data['integrations'][1]])
		self.assertEqual(set(data['integrations'][0]), {
			'id', 'kind', 'kind_label', 'name', 'url', 'enabled', 'updated_at', 'edit_url', 'delete_url',
		})
		self.assertEqual(data['integrations'][0]['edit_url'], reverse('monitor:prometheus_update', args=[prometheus.id]))
		self.assertEqual(data['integrations'][1]['delete_url'], reverse('monitor:alertmanager_delete', args=[alertmanager.id]))
		self.assertEqual(data['prometheus_integrations'][0]['url'], 'http://prometheus.local:9090')
		self.assertEqual(data['alertmanager_integrations'][0]['url'], 'http://alertmanager.local:9093')
		self.assertEqual(data['prometheus_form']['action'], reverse('monitor:prometheus_config'))
		self.assertEqual(data['prometheus_form']['test_action'], reverse('monitor:prometheus_test'))
		self.assertEqual(data['alertmanager_form']['action'], reverse('monitor:alertmanager_create'))
		self.assertEqual(data['alertmanager_form']['test_action'], reverse('monitor:alertmanager_test'))
		self.assertNotIn('health', data['integrations'][0])
		with open('static/js/ops-vue-pages.js', 'r') as handle:
			vue_source = handle.read()
		self.assertNotIn('id="monitor-integrations-kind"', vue_source)
		self.assertNotIn('id="monitor-integrations-query"', vue_source)
		self.assertNotIn('monitor-integrations-\' + group.key + \'-selector', vue_source)

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

	@mock.patch('monitor.views.record_integration_health_event')
	@mock.patch('monitor.views.test_prometheus_connection', return_value={'ok': True, 'message': 'Prometheus 连接正常'})
	def test_prometheus_connection_test_does_not_update_existing_record(self, test_connection, record_health):
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
		record_health.assert_not_called()

	@mock.patch('monitor.views.record_integration_health_event')
	@mock.patch('monitor.views.test_prometheus_connection', return_value={'ok': False, 'message': 'Prometheus 请求失败，请检查地址和网络'})
	def test_persisted_prometheus_connection_test_records_safe_health_result(self, test_connection, record_health):
		self.set_role(DevOpsRole.ROLE_OPERATOR)
		config = PrometheusConfig.objects.create(
			name='已保存 Prometheus', prometheus_url='http://saved-prometheus.local:9090', enabled=True,
		)

		response = self.client.post(reverse('monitor:prometheus_test'), {
			'id': config.id, 'name': config.name, 'prometheus_url': config.prometheus_url, 'enabled': 'on',
		})

		self.assertEqual(response.status_code, 400)
		record_health.assert_called_once_with(
			IntegrationHealthEvent.TYPE_PROMETHEUS,
			source=config,
			status=IntegrationHealthEvent.STATUS_FAILED,
			category=IntegrationHealthEvent.CATEGORY_REQUEST_ERROR,
		)

	@mock.patch('monitor.views.summarize_integration_health')
	def test_integration_health_payload_is_admin_security_only(self, summarize_health):
		config = PrometheusConfig.objects.create(
			name='Health Prometheus', prometheus_url='http://prometheus.local:9090', enabled=True,
		)
		summarize_health.return_value = {
			'current_state': 'failed', 'latest_check': '2026-07-19T10:00:00Z',
			'latest_category': IntegrationHealthEvent.CATEGORY_TIMEOUT,
			'latest_summary': 'untrusted raw token=secret', 'consecutive_failures': 2,
			'recent_event_counts': {'failed': 3, 'success': 1},
		}
		self.set_role(DevOpsRole.ROLE_OPERATOR)

		operator_data = self.vue_data(self.client.get(reverse('monitor:prometheus_config')))

		self.assertFalse(operator_data['can_view_integration_health'])
		self.assertNotIn('health', operator_data['integrations'][0])
		summarize_health.assert_not_called()
		self.set_role(DevOpsRole.ROLE_ADMIN)
		DevOpsModulePermission.objects.update_or_create(
			user=self.user,
			module=DevOpsModulePermission.MODULE_SECURITY,
			defaults={'role': DevOpsRole.ROLE_ADMIN},
		)
		admin_data = self.vue_data(self.client.get(reverse('monitor:prometheus_config')))

		health = admin_data['integrations'][0]['health']
		self.assertTrue(admin_data['can_view_integration_health'])
		self.assertEqual(health, {
			'state': 'failed', 'last_checked_at': '2026-07-19T10:00:00Z',
			'category': IntegrationHealthEvent.CATEGORY_TIMEOUT,
			'summary': '请求超时', 'consecutive_failures': 2,
			'recent_failures': 3, 'recent_successes': 1,
		})
		summarize_health.assert_called_once_with(IntegrationHealthEvent.TYPE_PROMETHEUS, source=config)
		with open('static/js/ops-vue-pages.js', 'r') as handle:
			vue_source = handle.read()
		self.assertIn('normalizeMonitorIntegrationHealth', vue_source)
		self.assertIn('data.can_view_integration_health', vue_source)
		self.assertIn('对接健康状态', vue_source)

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

	@mock.patch('monitor.views.record_integration_health_event')
	@mock.patch('monitor.views.test_alertmanager_connection', return_value={'ok': True, 'message': 'Alertmanager 连接正常'})
	def test_operator_can_test_alertmanager_connection_without_saving(self, test_connection, record_health):
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
		record_health.assert_not_called()

	@mock.patch('monitor.views.record_integration_health_event')
	@mock.patch('monitor.views.test_alertmanager_connection', return_value={'ok': True, 'message': 'Alertmanager 连接正常'})
	def test_persisted_alertmanager_connection_test_records_safe_health_result(self, test_connection, record_health):
		self.set_role(DevOpsRole.ROLE_OPERATOR)
		config = AlertmanagerConfig.objects.create(
			name='已保存 Alertmanager', alertmanager_url='http://alerts.local:9093', enabled=True,
		)

		response = self.client.post(reverse('monitor:alertmanager_test'), {
			'id': config.id, 'name': config.name, 'alertmanager_url': config.alertmanager_url, 'enabled': 'on',
		})

		self.assertEqual(response.status_code, 200)
		record_health.assert_called_once_with(
			IntegrationHealthEvent.TYPE_ALERTMANAGER,
			source=config,
			status=IntegrationHealthEvent.STATUS_SUCCESS,
			category=IntegrationHealthEvent.CATEGORY_OK,
		)

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
		self.assertEqual([item['kind'] for item in data['prometheus_integrations']], ['prometheus'])
		self.assertEqual([item['kind'] for item in data['alertmanager_integrations']], ['alertmanager'])
		self.assertEqual(data['prometheus_integrations'][0]['url'], 'http://prometheus.local:9090')
		self.assertEqual(data['alertmanager_integrations'][0]['url'], 'http://alertmanager.local:9093')
		with open('static/js/ops-vue-pages.js', 'r') as handle:
			vue_source = handle.read()
		self.assertIn('监控对接列表', vue_source)
		self.assertIn('id="monitor-home-integration-kind"', vue_source)
		self.assertIn('id="monitor-home-integration-query"', vue_source)
		self.assertIn('aria-label="查询监控对接"', vue_source)
		self.assertIn('ops-integration-filter-query', vue_source)
		self.assertIn('filteredMonitorIntegrationItems', vue_source)
		self.assertIn('monitorIntegrationEnabledCount', vue_source)
		self.assertIn('ops-integration-list-summary', vue_source)
		self.assertIn('ops-integration-table', vue_source)
		self.assertIn('<th>名称</th>', vue_source)
		self.assertIn('<th>类型</th>', vue_source)
		self.assertIn('<th>地址</th>', vue_source)
		self.assertIn('<th>状态</th>', vue_source)
		self.assertIn('<th>更新时间</th>', vue_source)
		self.assertIn('integration.updatedAt ? formatDisplayDate(integration.updatedAt) : \'-\'', vue_source)
		self.assertIn('ops-integration-icon-action', vue_source)
		self.assertIn('integration.deleteUrl', vue_source)
		self.assertNotIn('monitor-home-\' + group.key + \'-selector', vue_source)

	def test_alert_query_requires_enabled_prometheus_config(self):
		response = self.client.get(reverse('monitor:alert_query'), {'query': 'up'})
		data = self.vue_data(response)

		self.assertEqual(response.status_code, 400)
		self.assertEqual(data['query'], 'up')
		self.assertEqual(data['table'], services.empty_prometheus_table())
		self.assertEqual(data['error'], '请先配置并启用 Prometheus 对接')
		self.assertFalse(data['prometheus_configured'])
		self.assertEqual(data['prometheus_configs'], [])
		self.assertIsNone(data['selected_prometheus_id'])

	def test_metric_query_page_lists_only_safe_available_prometheus_options(self):
		PrometheusConfig.objects.create(
			name='Disabled',
			prometheus_url='http://disabled.local:9090',
			enabled=False,
		)
		PrometheusConfig.objects.create(
			name='Blank URL',
			prometheus_url='',
			enabled=True,
		)
		first_enabled = PrometheusConfig.objects.create(
			name='  Primary Metrics  ',
			prometheus_url='http://primary.local:9090',
			enabled=True,
		)
		second_enabled = PrometheusConfig.objects.create(
			name='   ',
			prometheus_url='http://backup.local:9090',
			enabled=True,
		)

		response = self.client.get(reverse('monitor:alert_query'))
		data = self.vue_data(response)

		self.assertEqual(response.status_code, 200)
		self.assertTrue(data['prometheus_configured'])
		self.assertEqual(data['prometheus_configs'], [
			{'id': first_enabled.id, 'name': 'Primary Metrics'},
			{'id': second_enabled.id, 'name': 'Prometheus'},
		])
		self.assertEqual([set(item) for item in data['prometheus_configs']], [
			{'id', 'name'},
			{'id', 'name'},
		])
		self.assertEqual(data['selected_prometheus_id'], first_enabled.id)
		self.assertEqual(data['metadata_url'], reverse('monitor:metric_query_metadata'))

	def test_metric_query_page_disambiguates_duplicate_and_fallback_names(self):
		duplicate_a = PrometheusConfig.objects.create(
			name='Shared Metrics',
			prometheus_url='http://shared-a.local:9090',
			enabled=True,
		)
		duplicate_b = PrometheusConfig.objects.create(
			name='  Shared Metrics  ',
			prometheus_url='http://shared-b.local:9090',
			enabled=True,
		)
		fallback = PrometheusConfig.objects.create(
			name='',
			prometheus_url='http://fallback.local:9090',
			enabled=True,
		)
		actual_default = PrometheusConfig.objects.create(
			name=' Prometheus ',
			prometheus_url='http://named-default.local:9090',
			enabled=True,
		)

		response = self.client.get(reverse('monitor:alert_query'))
		data = self.vue_data(response)

		self.assertEqual(response.status_code, 200)
		self.assertEqual(data['prometheus_configs'], [
			{'id': duplicate_a.id, 'name': 'Shared Metrics (#%s)' % duplicate_a.id},
			{'id': duplicate_b.id, 'name': 'Shared Metrics (#%s)' % duplicate_b.id},
			{'id': fallback.id, 'name': 'Prometheus (#%s)' % fallback.id},
			{'id': actual_default.id, 'name': 'Prometheus (#%s)' % actual_default.id},
		])

	@mock.patch('monitor.views.query_prometheus')
	def test_metric_query_excludes_whitespace_only_prometheus_url(self, query_prometheus_mock):
		whitespace_url = PrometheusConfig.objects.create(
			name='Legacy Whitespace URL',
			prometheus_url=' \t ',
			enabled=True,
		)
		available = PrometheusConfig.objects.create(
			name='Available',
			prometheus_url='http://available.local:9090',
			enabled=True,
		)
		query_prometheus_mock.return_value = {
			'ok': True,
			'body': {
				'status': 'success',
				'data': {'resultType': 'scalar', 'result': [1, '2']},
			},
		}

		page_response = self.client.get(reverse('monitor:alert_query'))
		page_data = self.vue_data(page_response)
		default_response = self.client.post(reverse('monitor:metric_query_execute'), {'query': 'up'})

		self.assertEqual(page_response.status_code, 200)
		self.assertEqual(page_data['prometheus_configs'], [
			{'id': available.id, 'name': 'Available'},
		])
		self.assertEqual(page_data['selected_prometheus_id'], available.id)
		self.assertEqual(default_response.status_code, 200)
		self.assertEqual(default_response.json()['prometheus_id'], available.id)
		self.assertEqual(query_prometheus_mock.call_args[0][0].id, available.id)

		query_prometheus_mock.reset_mock()
		get_response = self.client.get(reverse('monitor:alert_query'), {
			'query': 'up',
			'prometheus_id': whitespace_url.id,
		})
		post_response = self.client.post(reverse('monitor:metric_query_execute'), {
			'query': 'up',
			'prometheus_id': whitespace_url.id,
		})

		self.assertEqual(get_response.status_code, 400)
		self.assertEqual(self.vue_data(get_response)['error'], '选择的 Prometheus 对接不可用')
		self.assertEqual(post_response.status_code, 400)
		self.assertEqual(post_response.json(), {
			'ok': False,
			'message': '选择的 Prometheus 对接不可用',
		})
		query_prometheus_mock.assert_not_called()

	@mock.patch('monitor.views.query_prometheus')
	def test_alert_query_preserves_bookmarked_query_as_normalized_table(self, query_prometheus_mock):
		config = PrometheusConfig.objects.create(prometheus_url='http://prometheus.local:9090', enabled=True)
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
		self.assertEqual(data['selected_prometheus_id'], config.id)
		self.assertEqual(data['table']['label_columns'], ['job'])
		self.assertEqual(data['table']['rows'][0]['labels'], {'job': 'node'})
		query_prometheus_mock.assert_called_once()

	@mock.patch('monitor.views.query_prometheus')
	def test_alert_query_bookmark_uses_selected_prometheus_config(self, query_prometheus_mock):
		PrometheusConfig.objects.create(
			name='Primary Metrics',
			prometheus_url='http://primary.local:9090',
			enabled=True,
		)
		selected = PrometheusConfig.objects.create(
			name='Backup Metrics',
			prometheus_url='http://backup.local:9090',
			enabled=True,
		)
		query_prometheus_mock.return_value = {
			'ok': True,
			'body': {
				'status': 'success',
				'data': {'resultType': 'scalar', 'result': [1, '2']},
			},
		}

		response = self.client.get(reverse('monitor:alert_query'), {
			'query': 'up',
			'prometheus_id': selected.id,
		})
		data = self.vue_data(response)

		self.assertEqual(response.status_code, 200)
		self.assertEqual(data['selected_prometheus_id'], selected.id)
		self.assertEqual(data['table']['rows'][0]['value'], '2')
		self.assertEqual(query_prometheus_mock.call_args[0][0].id, selected.id)
		self.assertEqual(query_prometheus_mock.call_args[0][1], 'up')

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
		self.assertEqual(response.json()['prometheus_id'], first_enabled.id)
		self.assertEqual(response.json()['table']['rows'][0]['value'], '2')
		self.assertEqual(query_prometheus_mock.call_args[0][0].id, first_enabled.id)
		self.assertEqual(query_prometheus_mock.call_args[0][1], 'up')

	@mock.patch('monitor.views.query_prometheus')
	def test_metric_query_execute_uses_selected_prometheus_config(self, query_prometheus_mock):
		PrometheusConfig.objects.create(
			name='Primary Metrics',
			prometheus_url='http://primary.local:9090',
			enabled=True,
		)
		selected = PrometheusConfig.objects.create(
			name='Backup Metrics',
			prometheus_url='http://backup.local:9090',
			enabled=True,
		)
		query_prometheus_mock.return_value = {
			'ok': True,
			'body': {
				'status': 'success',
				'data': {'resultType': 'scalar', 'result': [1, '2']},
			},
		}

		response = self.client.post(reverse('monitor:metric_query_execute'), {
			'query': 'up',
			'prometheus_id': selected.id,
		})

		self.assertEqual(response.status_code, 200)
		self.assertEqual(response.json()['prometheus_id'], selected.id)
		self.assertEqual(query_prometheus_mock.call_args[0][0].id, selected.id)
		self.assertEqual(query_prometheus_mock.call_args[0][1], 'up')

	@mock.patch('monitor.views.query_prometheus')
	def test_metric_query_execute_blank_prometheus_id_uses_default(self, query_prometheus_mock):
		default = PrometheusConfig.objects.create(
			name='Primary Metrics',
			prometheus_url='http://primary.local:9090',
			enabled=True,
		)
		query_prometheus_mock.return_value = {
			'ok': True,
			'body': {
				'status': 'success',
				'data': {'resultType': 'scalar', 'result': [1, '2']},
			},
		}

		response = self.client.post(reverse('monitor:metric_query_execute'), {
			'query': 'up',
			'prometheus_id': '',
		})

		self.assertEqual(response.status_code, 200)
		self.assertEqual(response.json()['prometheus_id'], default.id)
		self.assertEqual(query_prometheus_mock.call_args[0][0].id, default.id)

	@mock.patch('monitor.views.query_prometheus')
	def test_metric_query_rejects_unavailable_explicit_prometheus_ids(self, query_prometheus_mock):
		disabled = PrometheusConfig.objects.create(
			name='Disabled',
			prometheus_url='http://disabled.local:9090',
			enabled=False,
		)
		blank_url = PrometheusConfig.objects.create(
			name='Blank URL',
			prometheus_url='',
			enabled=True,
		)
		available = PrometheusConfig.objects.create(
			name='Available',
			prometheus_url='http://available.local:9090',
			enabled=True,
		)
		invalid_ids = (
			'not-a-number',
			disabled.id,
			blank_url.id,
			available.id + 1000,
		)

		for prometheus_id in invalid_ids:
			with self.subTest(prometheus_id=prometheus_id):
				get_response = self.client.get(reverse('monitor:alert_query'), {
					'query': 'up',
					'prometheus_id': prometheus_id,
				})
				post_response = self.client.post(reverse('monitor:metric_query_execute'), {
					'query': 'up',
					'prometheus_id': prometheus_id,
				})
				get_data = self.vue_data(get_response)

				self.assertEqual(get_response.status_code, 400)
				self.assertEqual(get_data['error'], '选择的 Prometheus 对接不可用')
				self.assertIsNone(get_data['selected_prometheus_id'])
				self.assertEqual(post_response.status_code, 400)
				self.assertEqual(post_response.json(), {
					'ok': False,
					'message': '选择的 Prometheus 对接不可用',
				})
				query_prometheus_mock.assert_not_called()

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
		self.assertEqual(query_data['targets_url'], reverse('monitor:metric_query_targets'))
		self.assertEqual(query_data['rules_url'], reverse('monitor:metric_query_rules'))
		self.assertEqual(query_data['prometheus_configs'], [])
		self.assertIsNone(query_data['selected_prometheus_id'])
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

	@mock.patch('monitor.views.query_prometheus')
	def test_metric_query_invalid_promql_returns_400_without_internal_classification(self, query_prometheus_mock):
		PrometheusConfig.objects.create(
			prometheus_url='http://prometheus.local:9090',
			enabled=True,
		)
		query_prometheus_mock.return_value = {
			'ok': False,
			'message': services.PROMETHEUS_INVALID_QUERY_MESSAGE,
			'error_kind': 'invalid_query',
		}

		post_response = self.client.post(reverse('monitor:metric_query_execute'), {'query': '('})
		get_response = self.client.get(reverse('monitor:alert_query'), {'query': '('})
		get_data = self.vue_data(get_response)

		self.assertEqual(post_response.status_code, 400)
		self.assertEqual(post_response.json(), {
			'ok': False,
			'message': services.PROMETHEUS_INVALID_QUERY_MESSAGE,
		})
		self.assertNotIn('error_kind', post_response.json())
		self.assertEqual(get_response.status_code, 400)
		self.assertEqual(get_data['error'], services.PROMETHEUS_INVALID_QUERY_MESSAGE)
		self.assertNotIn('error_kind', get_data)

	def test_metric_metadata_endpoints_require_post_and_login(self):
		endpoint_names = (
			'monitor:metric_query_metadata',
			'monitor:metric_query_targets',
			'monitor:metric_query_rules',
		)
		for endpoint_name in endpoint_names:
			with self.subTest(endpoint_name=endpoint_name, method='GET'):
				self.assertEqual(self.client.get(reverse(endpoint_name)).status_code, 405)

		session = self.client.session
		session.clear()
		session.save()
		for endpoint_name in endpoint_names:
			with self.subTest(endpoint_name=endpoint_name, authenticated=False):
				response = self.client.post(reverse(endpoint_name))
				self.assertEqual(response.status_code, 302)
				self.assertEqual(response.url, reverse('userprofile:login'))

	@mock.patch('monitor.views.query_prometheus_metadata')
	def test_metric_query_metadata_uses_selected_config_and_returns_safe_identifiers(
			self, metadata_mock):
		PrometheusConfig.objects.create(
			name='Primary Metrics',
			prometheus_url='http://primary.local:9090',
			enabled=True,
		)
		selected = PrometheusConfig.objects.create(
			name='Secondary Metrics',
			prometheus_url='http://secondary.local:9090',
			enabled=True,
		)
		metadata_mock.return_value = {
			'ok': True,
			'metrics': ['http_requests_total', 'up'],
			'labels': ['instance', 'job'],
		}

		response = self.client.post(reverse('monitor:metric_query_metadata'), {
			'prometheus_id': selected.id,
		})

		self.assertEqual(response.status_code, 200)
		self.assertEqual(response.json(), {
			'ok': True,
			'prometheus_id': selected.id,
			'metrics': ['http_requests_total', 'up'],
			'labels': ['instance', 'job'],
		})
		self.assertEqual(metadata_mock.call_args[0][0].id, selected.id)

	@mock.patch('monitor.views.query_prometheus_metadata')
	def test_metric_query_metadata_rejects_config_and_masks_upstream_failure(
			self, metadata_mock):
		missing_response = self.client.post(reverse('monitor:metric_query_metadata'))
		self.assertEqual(missing_response.status_code, 400)
		self.assertEqual(missing_response.json(), {
			'ok': False,
			'message': '请先配置并启用 Prometheus 对接',
		})

		config = PrometheusConfig.objects.create(
			prometheus_url='http://prometheus.local:9090',
			enabled=True,
		)
		invalid_response = self.client.post(reverse('monitor:metric_query_metadata'), {
			'prometheus_id': 'invalid',
		})
		self.assertEqual(invalid_response.status_code, 400)
		self.assertEqual(invalid_response.json(), {
			'ok': False,
			'message': '选择的 Prometheus 对接不可用',
		})

		metadata_mock.return_value = {
			'ok': False,
			'message': 'raw upstream token=private-value',
		}
		failure_response = self.client.post(reverse('monitor:metric_query_metadata'), {
			'prometheus_id': config.id,
		})
		self.assertEqual(failure_response.status_code, 502)
		self.assertEqual(failure_response.json(), {
			'ok': False,
			'message': services.PROMETHEUS_METADATA_FAILURE_MESSAGE,
		})
		self.assertNotIn('private-value', failure_response.content.decode('utf-8'))

	@mock.patch('monitor.views.query_prometheus_rules')
	@mock.patch('monitor.views.query_prometheus_targets')
	def test_metric_metadata_endpoints_use_selected_config_and_return_id(
			self, targets_mock, rules_mock):
		PrometheusConfig.objects.create(
			name='Primary Metrics',
			prometheus_url='http://primary.local:9090',
			enabled=True,
		)
		selected = PrometheusConfig.objects.create(
			name='Secondary Metrics',
			prometheus_url='http://secondary.local:9090',
			enabled=True,
		)
		targets_mock.return_value = {
			'ok': True,
			'body': {
				'status': 'success',
				'data': {'activeTargets': [{
					'labels': {'instance': 'host-a', 'job': 'node'},
					'scrapePool': 'node',
					'health': 'up',
					'lastScrapeDuration': 0.2,
				}]},
			},
		}
		rules_mock.return_value = {
			'ok': True,
			'body': {
				'status': 'success',
				'data': {'groups': [{
					'name': 'system',
					'rules': [{
						'name': 'HostDown',
						'type': 'alerting',
						'health': 'ok',
						'state': 'inactive',
						'query': 'up == 0',
					}],
				}]},
			},
		}

		targets_response = self.client.post(reverse('monitor:metric_query_targets'), {
			'prometheus_id': selected.id,
		})
		rules_response = self.client.post(reverse('monitor:metric_query_rules'), {
			'prometheus_id': selected.id,
		})

		self.assertEqual(targets_response.status_code, 200)
		self.assertEqual(targets_response.json()['prometheus_id'], selected.id)
		self.assertEqual(targets_response.json()['targets']['summary']['up'], 1)
		self.assertEqual(rules_response.status_code, 200)
		self.assertEqual(rules_response.json()['prometheus_id'], selected.id)
		self.assertEqual(rules_response.json()['rules']['summary']['alerting'], 1)
		self.assertEqual(targets_mock.call_args[0][0].id, selected.id)
		self.assertEqual(rules_mock.call_args[0][0].id, selected.id)

	@mock.patch('monitor.views.query_prometheus_rules')
	@mock.patch('monitor.views.query_prometheus_targets')
	def test_metric_metadata_endpoints_reject_missing_or_invalid_config(
			self, targets_mock, rules_mock):
		for endpoint_name in ('monitor:metric_query_targets', 'monitor:metric_query_rules'):
			with self.subTest(endpoint_name=endpoint_name, configured=False):
				response = self.client.post(reverse(endpoint_name))
				self.assertEqual(response.status_code, 400)
				self.assertEqual(response.json(), {
					'ok': False,
					'message': '请先配置并启用 Prometheus 对接',
				})

		PrometheusConfig.objects.create(
			name='Available',
			prometheus_url='http://available.local:9090',
			enabled=True,
		)
		for endpoint_name in ('monitor:metric_query_targets', 'monitor:metric_query_rules'):
			with self.subTest(endpoint_name=endpoint_name, invalid_id=True):
				response = self.client.post(reverse(endpoint_name), {'prometheus_id': 'invalid'})
				self.assertEqual(response.status_code, 400)
				self.assertEqual(response.json(), {
					'ok': False,
					'message': '选择的 Prometheus 对接不可用',
				})
		targets_mock.assert_not_called()
		rules_mock.assert_not_called()

	@mock.patch('monitor.views.query_prometheus_rules')
	@mock.patch('monitor.views.query_prometheus_targets')
	def test_metric_metadata_endpoints_return_safe_502_failures(
			self, targets_mock, rules_mock):
		config = PrometheusConfig.objects.create(
			prometheus_url='http://prometheus.local:9090',
			enabled=True,
		)
		targets_mock.return_value = {
			'ok': False,
			'message': 'raw upstream target detail',
		}
		rules_mock.return_value = {
			'ok': False,
			'message': services.PROMETHEUS_RULES_FORMAT_MESSAGE,
		}

		targets_response = self.client.post(reverse('monitor:metric_query_targets'), {
			'prometheus_id': config.id,
		})
		rules_response = self.client.post(reverse('monitor:metric_query_rules'), {
			'prometheus_id': config.id,
		})

		self.assertEqual(targets_response.status_code, 502)
		self.assertEqual(targets_response.json(), {
			'ok': False,
			'message': services.PROMETHEUS_TARGETS_FAILURE_MESSAGE,
		})
		self.assertNotIn('raw upstream', targets_response.content.decode('utf-8'))
		self.assertEqual(rules_response.status_code, 502)
		self.assertEqual(rules_response.json(), {
			'ok': False,
			'message': services.PROMETHEUS_RULES_FORMAT_MESSAGE,
		})

	@mock.patch('monitor.services.query_prometheus')
	@mock.patch('monitor.services.prometheus_get_json')
	def test_metric_targets_endpoint_returns_up_fallback_rows(
			self, prometheus_get_json, query_prometheus_mock):
		config = PrometheusConfig.objects.create(
			prometheus_url='http://prometheus.local:9090',
			enabled=True,
		)
		prometheus_get_json.return_value = {
			'ok': True,
			'body': {'status': 'success', 'data': {'activeTargets': []}},
		}
		query_prometheus_mock.return_value = {
			'ok': True,
			'body': {
				'status': 'success',
				'data': {
					'resultType': 'vector',
					'result': [{
						'metric': {'instance': 'host-a:9100', 'job': 'node'},
						'value': [1710000000, '1'],
					}],
				},
			},
		}

		response = self.client.post(reverse('monitor:metric_query_targets'), {
			'prometheus_id': config.id,
		})

		self.assertEqual(response.status_code, 200)
		self.assertEqual(response.json()['prometheus_id'], config.id)
		self.assertEqual(response.json()['targets']['total_rows'], 1)
		self.assertEqual(response.json()['targets']['rows'][0]['instance'], 'host-a:9100')
		self.assertEqual(
			response.json()['targets']['rows'][0]['last_scrape'],
			'2024-03-09T16:00:00Z',
		)
		query_prometheus_mock.assert_called_once_with(config, 'up')

	def test_metric_resource_frontend_keeps_security_query_context_and_keyboard_tabs(self):
		with open('static/js/ops-vue-pages.js', 'r') as handle:
			vue_source = handle.read()

		self.assertIn('sensitiveParts.some((sensitive) => compact.endsWith(sensitive))', vue_source)
		self.assertIn('isSensitiveMetricLabelValue(labels[key])', vue_source)
		self.assertIn("this.fetchMetricJson(this.data.execute_url, form, 'query')", vue_source)
		self.assertIn("this.fetchMetricJson(endpoint, form, 'resource')", vue_source)
		self.assertEqual(vue_source.count('@keydown="handleMetricTabKeydown'), 4)
		self.assertEqual(vue_source.count(':tabindex="metricView ==='), 4)

	def test_metric_query_frontend_metadata_suggestions_and_native_scroll_contract(self):
		with open('static/js/ops-vue-pages.js', 'r') as handle:
			vue_source = handle.read()
		with open('static/css/ops-vue-pages.css', 'r') as handle:
			css_source = handle.read()
		with open('templates/vue/page.html', 'r') as handle:
			page_template = handle.read()

		self.assertIn('metricMetadataCache: {}', vue_source)
		self.assertIn('metricMetadataState(prometheusId)', vue_source)
		self.assertIn('if (existing && (existing.loading || existing.loaded)) return;', vue_source)
		self.assertIn("form.set('prometheus_id', id);", vue_source)
		self.assertIn("this.fetchMetricJson(this.data.metadata_url, form, 'metadata')", vue_source)
		self.assertIn('state.metrics = uniqueNames(', vue_source)
		self.assertIn('state.labels = uniqueNames(', vue_source)
		self.assertIn("kind: 'metric', label: '指标'", vue_source)
		self.assertIn("kind: 'label', label: '标签'", vue_source)
		self.assertIn("kind: 'function', label: '函数'", vue_source)
		self.assertIn('.concat(promqlFunctionSuggestions)', vue_source)
		for function_name in ('rate', 'sum', 'count', 'avg', 'max', 'min', 'increase', 'irate', 'histogram_quantile'):
			self.assertIn("'%s'" % function_name, vue_source)

		self.assertIn('updateMetricQuerySuggestions(panel, event)', vue_source)
		self.assertIn(".toLowerCase().indexOf(token) !== -1", vue_source)
		self.assertIn('suggestionsVisible: false', vue_source)
		self.assertIn('suggestionIndex: -1', vue_source)
		self.assertIn('@focus="updateMetricQuerySuggestions(panel, $event)"', vue_source)
		self.assertIn('@input="resetMetricQueryResult(panel); updateMetricQuerySuggestions(panel, $event)"', vue_source)
		self.assertIn('@keydown="handleMetricQueryKeydown($event, panel)"', vue_source)
		self.assertIn("event.key === 'ArrowDown' || event.key === 'ArrowUp'", vue_source)
		self.assertIn("event.key === 'Enter'", vue_source)
		self.assertIn("event.key === 'Escape'", vue_source)
		self.assertIn("(event.ctrlKey || event.metaKey) && event.key === 'Enter'", vue_source)
		self.assertIn('@mousedown.prevent="selectMetricQuerySuggestion(panel, suggestion)"', vue_source)
		self.assertIn('role="listbox"', vue_source)
		self.assertIn(":class=\"'is-' + suggestion.kind\"", vue_source)

		self.assertIn('changeMetricPrometheus()', vue_source)
		self.assertIn('panel.suggestions = [];', vue_source)
		self.assertIn('panel.suggestionsVisible = false;', vue_source)
		self.assertIn('panel.suggestionIndex = -1;', vue_source)
		self.assertIn('this.metricMetadataState(this.selectedMetricPrometheusId)', vue_source)

		self.assertIn('class="ops-query-table-wrap"', vue_source)
		self.assertIn('class="ops-query-sticky-scroll"', vue_source)
		self.assertIn('measureQueryStickyBars()', vue_source)
		self.assertIn('syncQueryStickyScroll(panelId)', vue_source)
		self.assertIn('const wasVisible = panel.stickyScrollbarVisible;', vue_source)
		self.assertIn('this.$nextTick(() => this.syncQueryStickyScroll(panel.id));', vue_source)
		self.assertIn('mirrorQueryTableScroll(panelId, event)', vue_source)
		self.assertIn('mirrorQueryStickyScroll(panelId, event)', vue_source)
		self.assertIn('tableWrap.scrollWidth > tableWrap.clientWidth + 1', vue_source)
		self.assertIn('rect.bottom > viewportHeight', vue_source)
		self.assertIn("window.addEventListener('scroll', this.handleQueryViewportChange, { passive: true });", vue_source)
		self.assertIn("window.addEventListener('resize', this.handleQueryViewportChange, { passive: true });", vue_source)
		self.assertIn('.ops-query-table-wrap {', css_source)
		self.assertIn('.ops-query-panel > * {', css_source)
		self.assertIn('width: 100%;\n    max-width: 100%;\n    min-width: 0;\n    max-height:', css_source)
		self.assertIn('.ops-query-sticky-scroll {', css_source)
		self.assertIn('position: fixed;', css_source)
		self.assertIn('bottom: 0;', css_source)
		self.assertIn('overflow-x: auto;', css_source)
		self.assertIn('overflow-y: auto;', css_source)
		self.assertIn('width: max-content;', css_source)
		self.assertIn('.ops-query-table th,\n.ops-query-table td {', css_source)
		self.assertIn('white-space: nowrap;', css_source)
		self.assertIn('.ops-query-table code {', css_source)
		self.assertIn('.ops-query-suggestions {', css_source)
		self.assertIn('20260714-promql-scroll-width-sync', page_template)

		for obsolete in (
			'metricQueryPatterns', 'queryPattern', 'type="range"', 'horizontalScroll',
			'measureMetricQueryScroll', 'measureAllMetricQueryScroll',
			'syncMetricQueryScroll', 'setMetricQueryScroll', 'ops-query-scroll-control',
		):
			self.assertNotIn(obsolete, vue_source)
		self.assertNotIn('.ops-query-scroll-control', css_source)

	def test_metric_resource_frontend_filters_expandable_rules_and_reset_contract(self):
		with open('static/js/ops-vue-pages.js', 'r') as handle:
			vue_source = handle.read()
		with open('templates/vue/page.html', 'r') as handle:
			page_template = handle.read()

		self.assertIn("metricResourceFilters: { targets: '', rules: '' }", vue_source)
		self.assertIn('expandedTargetCells: { name: [], instance: [], job: [], scrapePool: [], labels: [] }', vue_source)
		self.assertIn('expandedRuleCells: { query: [], labels: [] }', vue_source)
		self.assertIn('filteredMetricTargets()', vue_source)
		self.assertIn('filteredMetricRules()', vue_source)
		self.assertIn('filterMetricResourceRows(kind, rows)', vue_source)
		self.assertIn('formatMetricLabelsSummary(labels)', vue_source)
		self.assertIn('v-model="metricResourceFilters.targets"', vue_source)
		self.assertIn('v-model="metricResourceFilters.rules"', vue_source)
		self.assertIn('v-for="(row, rowIndex) in filteredMetricTargets"', vue_source)
		self.assertIn('v-for="(row, rowIndex) in filteredMetricRules"', vue_source)

		self.assertIn('toggleRuleCell(row, cell)', vue_source)
		self.assertIn("event.key !== 'Enter' && event.key !== ' '", vue_source)
		self.assertIn('this.toggleRuleCell(row, cell)', vue_source)
		self.assertEqual(vue_source.count('@dblclick="toggleRuleCell(row,'), 2)
		self.assertEqual(vue_source.count('@keydown="handleRuleCellKeydown('), 2)
		self.assertEqual(vue_source.count(':aria-expanded="isRuleCellExpanded('), 2)
		self.assertIn('toggleTargetCell(row, cell)', vue_source)
		self.assertIn('this.toggleTargetCell(row, cell)', vue_source)
		self.assertEqual(vue_source.count('@dblclick="toggleTargetCell(row,'), 5)
		self.assertEqual(vue_source.count('@keydown="handleTargetCellKeydown('), 5)
		self.assertEqual(vue_source.count(':aria-expanded="isTargetCellExpanded('), 5)
		self.assertEqual(vue_source.count('class="ops-metric-label-summary"'), 2)
		self.assertEqual(vue_source.count("v-if=\"isTargetCellExpanded(row, 'labels') && row.labels.length\""), 1)
		self.assertEqual(vue_source.count("v-if=\"isRuleCellExpanded(row, 'labels') && row.labels.length\""), 1)
		self.assertEqual(vue_source.count('class="ops-metric-labels"'), 2)
		self.assertNotIn('v-if="row.labels.length" class="ops-metric-labels"', vue_source)

		self.assertIn('clearMetricResource(kind)', vue_source)
		self.assertIn('this.resetMetricResourceUi(kind);', vue_source)
		self.assertIn('if (force) this.resetMetricResourceUi(kind);', vue_source)
		self.assertIn("this.metricResourceFilters[kind] = '';", vue_source)
		self.assertIn('this.expandedTargetCells.name = [];', vue_source)
		self.assertIn('this.expandedTargetCells.instance = [];', vue_source)
		self.assertIn('this.expandedTargetCells.job = [];', vue_source)
		self.assertIn('this.expandedTargetCells.scrapePool = [];', vue_source)
		self.assertIn('this.expandedTargetCells.labels = [];', vue_source)
		self.assertIn('this.expandedRuleCells.query = [];', vue_source)
		self.assertIn('this.expandedRuleCells.labels = [];', vue_source)

		static_version = '20260801-geist-control-plane-01'
		self.assertEqual(page_template.count('?v=%s' % static_version), 2)
		self.assertIn("static 'css/ops-vue-pages.css'", page_template)
		self.assertIn("static 'js/ops-vue-pages.js'", page_template)

	def test_alert_notifications_page_renders(self):
		response = self.client.get(reverse('monitor:alert_notifications'))

		self.assertEqual(response.status_code, 200)
		self.assertContains(response, '告警通知')
		self.assertContains(response, '飞书')
		self.assertContains(response, '企业微信')

	def test_notification_integration_list_is_viewable_and_never_exposes_webhook_fragments(self):
		self.set_role(DevOpsRole.ROLE_VIEWER)
		AlertNotificationConfig.objects.create(
			provider=AlertNotificationConfig.PROVIDER_FEISHU,
			name='Not Configured',
			enabled=True,
			webhook_url='',
		)
		wecom_config = AlertNotificationConfig.objects.create(
			provider=AlertNotificationConfig.PROVIDER_WECOM,
			name='Configured Channel',
			enabled=False,
			webhook_url='https://notify.example.test/path/recognizable-fragment',
		)

		list_response = self.client.get(reverse('monitor:alert_notification_list'))
		list_data = self.vue_data(list_response)
		config_response = self.client.get(reverse('monitor:alert_notifications'))
		config_data = self.vue_data(config_response)

		self.assertEqual(list_response.status_code, 200)
		self.assertEqual(json.loads(list_response.context['vue_page_payload'])['kind'], 'alert-notification-list')
		self.assertFalse(list_data['can_manage_notifications'])
		self.assertEqual(list_data['configure_url'], reverse('monitor:alert_notifications'))
		self.assertEqual(len(list_data['notification_integrations']), 1)
		item = list_data['notification_integrations'][0]
		self.assertEqual(set(item), {
			'id', 'provider', 'provider_label', 'name', 'alert_name', 'alertmanager_id',
			'alertmanager_name', 'alert_type', 'created_at', 'created_by',
			'enabled', 'configured', 'updated_at', 'configure_url', 'edit_url', 'delete_url',
		})
		self.assertEqual(item['id'], wecom_config.id)
		self.assertEqual(item['provider'], AlertNotificationConfig.PROVIDER_WECOM)
		self.assertEqual(item['name'], 'Configured Channel')
		self.assertEqual(item['alert_name'], '')
		self.assertIsNone(item['alertmanager_id'])
		self.assertEqual(item['alertmanager_name'], '')
		self.assertEqual(item['alert_type'], '企业微信')
		self.assertEqual(item['created_by'], '')
		self.assertEqual(item['created_at'], '')
		self.assertFalse(item['enabled'])
		self.assertTrue(item['configured'])
		self.assertRegex(item['updated_at'], r'^\d{4}-\d{2}-\d{2} \d{2}:\d{2}$')
		self.assertEqual(item['configure_url'], reverse('monitor:alert_notifications'))
		self.assertEqual(item['edit_url'], '%s?edit=%s' % (reverse('monitor:alert_notifications'), wecom_config.id))
		self.assertEqual(item['delete_url'], reverse('monitor:alert_notification_delete', args=[wecom_config.id]))

		self.assertEqual(config_response.status_code, 200)
		self.assertFalse(config_data['can_manage_notifications'])
		self.assertEqual(config_data['list_url'], reverse('monitor:alert_notification_list'))
		self.assertTrue(config_data['notifications']['wecom']['has_webhook'])
		self.assertTrue(config_data['notifications']['wecom']['configured'])
		self.assertEqual(config_data['notifications']['wecom']['name'], 'Configured Channel')
		self.assertEqual(config_data['notifications']['wecom']['alert_name'], '')
		self.assertEqual(config_data['notifications']['wecom']['webhook_display'], '已配置')
		self.assertEqual(config_data['notifications']['wecom']['webhook_url'], '')
		self.assertNotIn('notify.example.test', list_response.context['vue_page_payload'])
		self.assertNotIn('recognizable-fragment', list_response.context['vue_page_payload'])
		self.assertNotIn('notify.example.test', config_response.context['vue_page_payload'])
		self.assertNotIn('recognizable-fragment', config_response.context['vue_page_payload'])
		self.assertNotContains(list_response, 'notify.example.test')
		self.assertNotContains(config_response, 'recognizable-fragment')

		list_actions = {item['label']: item['url'] for item in list_data['actions']}
		config_actions = {item['label']: item['url'] for item in config_data['actions']}
		self.assertEqual(list_actions['告警通知'], reverse('monitor:alert_notifications'))
		self.assertEqual(config_actions['告警列表'], reverse('monitor:alert_notification_list'))
		self.assertEqual(self.client.post(reverse('monitor:alert_notification_list')).status_code, 405)
		with open('static/js/ops-vue-pages.js', 'r') as handle:
			vue_source = handle.read()
		self.assertIn('id="alert-notification-provider"', vue_source)
		self.assertIn('id="alert-notification-query"', vue_source)
		self.assertIn('filteredAlertNotificationIntegrations', vue_source)
		self.assertIn('activeAlertNotificationGroup', vue_source)
		self.assertIn('ops-notification-list-summary', vue_source)
		self.assertIn('ops-notification-table', vue_source)
		self.assertNotIn('<th>通知名称</th>', vue_source)
		self.assertIn('<th>告警类型</th>', vue_source)
		self.assertIn('<th>Alertmanager 名称</th>', vue_source)
		self.assertIn('integration.alertmanagerName', vue_source)
		self.assertIn('<th>创建时间</th>', vue_source)
		self.assertIn('<th>创建人员</th>', vue_source)
		self.assertNotIn('<small :class="integration.configured', vue_source)
		self.assertIn('ops-notification-icon-action', vue_source)
		self.assertIn('integration.deleteUrl', vue_source)
		self.assertIn('data.editing_provider', vue_source)

	def test_operator_alert_notification_config_clears_transient_fields_on_refresh(self):
		self.set_role(DevOpsRole.ROLE_OPERATOR)
		webhook_url = 'https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=plain-key'
		AlertNotificationConfig.objects.create(
			provider=AlertNotificationConfig.PROVIDER_WECOM,
			name='Configured Channel',
			alert_name='Configured Alert',
			enabled=True,
			webhook_url=webhook_url,
		)

		response = self.client.get(reverse('monitor:alert_notifications'))
		data = self.vue_data(response)

		self.assertTrue(data['can_manage_notifications'])
		self.assertEqual(data['notifications']['wecom']['name'], 'Configured Channel')
		self.assertEqual(data['notifications']['wecom']['alert_name'], '')
		self.assertEqual(data['notifications']['wecom']['webhook_url'], '')
		self.assertEqual(data['notifications']['wecom']['webhook_display'], '已配置')
		self.assertNotContains(response, 'plain-key')
		self.assertNotContains(response, 'Configured Alert')

	def test_alert_notification_config_uses_read_only_vue_state_for_viewer(self):
		self.set_role(DevOpsRole.ROLE_VIEWER)

		viewer_response = self.client.get(reverse('monitor:alert_notifications'))
		viewer_data = self.vue_data(viewer_response)
		with open('static/js/ops-vue-pages.js', 'r') as handle:
			vue_source = handle.read()

		self.assertEqual(viewer_response.status_code, 200)
		self.assertFalse(viewer_data['can_manage_notifications'])
		self.assertIn('<form v-if="canConfigureNotifications" class="ops-form compact"', vue_source)
		self.assertIn('<div v-else class="ops-notification-readonly">', vue_source)

		self.set_role(DevOpsRole.ROLE_OPERATOR)
		operator_response = self.client.get(reverse('monitor:alert_notifications'))
		self.assertTrue(self.vue_data(operator_response)['can_manage_notifications'])

	def test_viewer_cannot_save_alert_notifications_when_roles_are_configured(self):
		self.set_role(DevOpsRole.ROLE_VIEWER)
		config = AlertNotificationConfig.objects.create(
			provider=AlertNotificationConfig.PROVIDER_WECOM,
			name='existing notification',
			enabled=True,
			webhook_url='https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=existing',
		)

		response = self.client.post(reverse('monitor:alert_notifications'), {
			'feishu_enabled': 'on',
			'feishu_name': 'feishu',
			'feishu_webhook_url': 'https://open.feishu.cn/open-apis/bot/v2/hook/test',
		})

		self.assertEqual(response.status_code, 403)
		self.assertEqual(AlertNotificationConfig.objects.count(), 1)
		config.refresh_from_db()
		self.assertEqual(config.name, 'existing notification')
		self.assertEqual(
			config.decrypted_webhook_url,
			'https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=existing',
		)

	def test_operator_can_save_alert_notifications_encrypted(self):
		self.set_role(DevOpsRole.ROLE_OPERATOR)

		response = self.client.post(reverse('monitor:alert_notifications'), {
			'feishu_enabled': 'on',
			'feishu_name': 'feishu',
			'feishu_alert_name': 'feishu alert',
			'feishu_webhook_url': 'https://open.feishu.cn/open-apis/bot/v2/hook/test',
			'wecom_enabled': 'on',
			'wecom_name': 'wecom',
			'wecom_alert_name': 'wecom alert',
			'wecom_webhook_url': 'https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=test-key',
		})

		data = self.vue_data(response)

		self.assertEqual(response.status_code, 200)
		self.assertEqual(data['save_message'], '告警通知保存成功')
		self.assertTrue(data['save_ok'])
		self.assertEqual(data['notifications']['feishu']['alert_name'], '')
		self.assertEqual(data['notifications']['wecom']['alert_name'], '')
		self.assertEqual(data['notifications']['feishu']['webhook_url'], '')
		self.assertEqual(data['notifications']['wecom']['webhook_url'], '')
		self.assertEqual(data['notifications']['feishu']['webhook_display'], '已配置')
		self.assertEqual(data['notifications']['wecom']['webhook_display'], '已配置')
		feishu = AlertNotificationConfig.objects.get(provider=AlertNotificationConfig.PROVIDER_FEISHU)
		wecom = AlertNotificationConfig.objects.get(provider=AlertNotificationConfig.PROVIDER_WECOM)
		self.assertTrue(feishu.enabled)
		self.assertTrue(wecom.enabled)
		self.assertEqual(feishu.name, 'feishu')
		self.assertEqual(feishu.alert_name, 'feishu alert')
		self.assertIsNotNone(feishu.created_at)
		self.assertEqual(feishu.created_by, 'tester')
		self.assertEqual(wecom.name, 'wecom')
		self.assertEqual(wecom.alert_name, 'wecom alert')
		self.assertIsNotNone(wecom.created_at)
		self.assertEqual(wecom.created_by, 'tester')
		self.assertTrue(feishu.webhook_url.startswith('enc:'))
		self.assertEqual(decrypt_text(feishu.webhook_url), 'https://open.feishu.cn/open-apis/bot/v2/hook/test')
		self.assertEqual(decrypt_text(wecom.webhook_url), 'https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=test-key')
		list_data = self.vue_data(self.client.get(reverse('monitor:alert_notification_list')))
		wecom_item = [
			item for item in list_data['notification_integrations']
			if item['provider'] == AlertNotificationConfig.PROVIDER_WECOM
		][0]
		self.assertRegex(wecom_item['created_at'], r'^\d{4}-\d{2}-\d{2} \d{2}:\d{2}$')
		self.assertEqual(wecom_item['created_by'], 'tester')
		self.assertTrue(AuditLog.objects.filter(action='保存告警通知').exists())

	def test_operator_can_add_multiple_alert_notifications_for_same_provider(self):
		self.set_role(DevOpsRole.ROLE_OPERATOR)

		first = self.client.post(reverse('monitor:alert_notifications'), {
			'provider': AlertNotificationConfig.PROVIDER_WECOM,
			'wecom_enabled': 'on',
			'wecom_name': 'wecom first',
			'wecom_alert_name': 'first alert',
			'wecom_webhook_url': 'https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=first-key',
		})
		second = self.client.post(reverse('monitor:alert_notifications'), {
			'provider': AlertNotificationConfig.PROVIDER_WECOM,
			'wecom_enabled': 'on',
			'wecom_name': 'wecom second',
			'wecom_alert_name': 'second alert',
			'wecom_webhook_url': 'https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=second-key',
		})

		self.assertEqual(first.status_code, 200)
		self.assertEqual(second.status_code, 200)
		wecom_configs = AlertNotificationConfig.objects.filter(
			provider=AlertNotificationConfig.PROVIDER_WECOM
		).order_by('id')
		self.assertEqual(wecom_configs.count(), 2)
		self.assertEqual([item.name for item in wecom_configs], ['wecom first', 'wecom second'])
		self.assertEqual(decrypt_text(wecom_configs[0].webhook_url), 'https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=first-key')
		self.assertEqual(decrypt_text(wecom_configs[1].webhook_url), 'https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=second-key')
		list_data = self.vue_data(self.client.get(reverse('monitor:alert_notification_list')))
		wecom_items = [
			item for item in list_data['notification_integrations']
			if item['provider'] == AlertNotificationConfig.PROVIDER_WECOM
		]
		self.assertEqual(len(wecom_items), 2)
		self.assertEqual(set(item['name'] for item in wecom_items), set(['wecom first', 'wecom second']))

	def test_operator_can_edit_alert_notification_without_showing_other_provider_form(self):
		self.set_role(DevOpsRole.ROLE_OPERATOR)
		feishu = AlertNotificationConfig.objects.create(
			provider=AlertNotificationConfig.PROVIDER_FEISHU,
			name='feishu existing',
			alert_name='feishu alert',
			enabled=True,
			webhook_url='https://open.feishu.cn/open-apis/bot/v2/hook/original',
		)
		wecom = AlertNotificationConfig.objects.create(
			provider=AlertNotificationConfig.PROVIDER_WECOM,
			name='wecom existing',
			alert_name='wecom alert',
			enabled=True,
			webhook_url='https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=original',
		)

		edit_response = self.client.get(reverse('monitor:alert_notifications'), {'edit': wecom.id})
		edit_data = self.vue_data(edit_response)

		self.assertEqual(edit_response.status_code, 200)
		self.assertEqual(edit_data['editing_notification_id'], wecom.id)
		self.assertEqual(edit_data['editing_provider'], AlertNotificationConfig.PROVIDER_WECOM)
		self.assertFalse(edit_data['notifications']['feishu']['editing'])
		self.assertTrue(edit_data['notifications']['wecom']['editing'])
		self.assertEqual(edit_data['notifications']['wecom']['name'], 'wecom existing')
		self.assertEqual(edit_data['notifications']['wecom']['alert_name'], 'wecom alert')
		self.assertEqual(edit_data['notifications']['wecom']['action'], reverse('monitor:alert_notification_update', args=[wecom.id]))
		self.assertEqual(edit_data['notifications']['wecom']['webhook_url'], '')
		self.assertNotContains(edit_response, 'original')

		update_response = self.client.post(reverse('monitor:alert_notification_update', args=[wecom.id]), {
			'provider': AlertNotificationConfig.PROVIDER_WECOM,
			'wecom_enabled': 'on',
			'wecom_name': 'wecom updated',
			'wecom_alert_name': 'wecom updated alert',
			'wecom_webhook_url': '',
			'feishu_enabled': 'on',
			'feishu_name': 'should not touch feishu',
			'feishu_alert_name': 'wrong',
			'feishu_webhook_url': 'https://open.feishu.cn/open-apis/bot/v2/hook/wrong',
		})

		self.assertEqual(update_response.status_code, 200)
		self.assertEqual(AlertNotificationConfig.objects.count(), 2)
		wecom.refresh_from_db()
		feishu.refresh_from_db()
		self.assertEqual(wecom.name, 'wecom updated')
		self.assertEqual(wecom.alert_name, 'wecom updated alert')
		self.assertEqual(decrypt_text(wecom.webhook_url), 'https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=original')
		self.assertEqual(feishu.name, 'feishu existing')
		self.assertEqual(feishu.alert_name, 'feishu alert')

	def test_alert_notification_alertmanager_select_saves_and_prefills(self):
		self.set_role(DevOpsRole.ROLE_OPERATOR)
		alertmanager = AlertmanagerConfig.objects.create(
			name='生产 Alertmanager',
			alertmanager_url='http://alertmanager.local:9093',
			enabled=True,
		)

		create_response = self.client.post(reverse('monitor:alert_notifications'), {
			'provider': AlertNotificationConfig.PROVIDER_WECOM,
			'wecom_enabled': 'on',
			'wecom_name': 'wecom with alertmanager',
			'wecom_alert_name': 'alertmanager alert',
			'wecom_alertmanager_id': str(alertmanager.id),
			'wecom_webhook_url': 'https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=alertmanager',
		})

		self.assertEqual(create_response.status_code, 200)
		config = AlertNotificationConfig.objects.get(provider=AlertNotificationConfig.PROVIDER_WECOM)
		self.assertEqual(config.alertmanager_id, alertmanager.id)
		list_data = self.vue_data(self.client.get(reverse('monitor:alert_notification_list')))
		item = list_data['notification_integrations'][0]
		self.assertEqual(item['alertmanager_id'], alertmanager.id)
		self.assertEqual(item['alertmanager_name'], '生产 Alertmanager')
		edit_data = self.vue_data(self.client.get(reverse('monitor:alert_notifications'), {'edit': config.id}))
		self.assertEqual(edit_data['alertmanager_options'], [{'id': alertmanager.id, 'name': '生产 Alertmanager'}])
		self.assertEqual(edit_data['notifications']['wecom']['alertmanager_id'], str(alertmanager.id))
		self.assertNotIn('alertmanager.local', json.dumps(edit_data))

		other = AlertmanagerConfig.objects.create(
			name='备用 Alertmanager',
			alertmanager_url='http://backup-alertmanager.local:9093',
			enabled=True,
		)
		update_response = self.client.post(reverse('monitor:alert_notification_update', args=[config.id]), {
			'provider': AlertNotificationConfig.PROVIDER_WECOM,
			'wecom_enabled': 'on',
			'wecom_name': 'wecom with alertmanager',
			'wecom_alert_name': 'alertmanager alert',
			'wecom_alertmanager_id': str(other.id),
			'wecom_webhook_url': '',
		})
		self.assertEqual(update_response.status_code, 200)
		config.refresh_from_db()
		self.assertEqual(config.alertmanager_id, other.id)

	def test_operator_can_delete_alert_notification(self):
		self.set_role(DevOpsRole.ROLE_OPERATOR)
		config = AlertNotificationConfig.objects.create(
			provider=AlertNotificationConfig.PROVIDER_WECOM,
			name='delete me',
			enabled=True,
			webhook_url='https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=delete',
		)

		response = self.client.post(reverse('monitor:alert_notification_delete', args=[config.id]))

		self.assertEqual(response.status_code, 302)
		self.assertEqual(response.url, reverse('monitor:alert_notification_list'))
		self.assertFalse(AlertNotificationConfig.objects.filter(id=config.id).exists())

	def test_alert_notifications_blank_webhook_does_not_create_new_notification(self):
		self.set_role(DevOpsRole.ROLE_OPERATOR)
		config = AlertNotificationConfig.objects.create(
			provider=AlertNotificationConfig.PROVIDER_FEISHU,
			name='old',
			enabled=True,
			webhook_url='https://open.feishu.cn/open-apis/bot/v2/hook/original',
		)

		response = self.client.post(reverse('monitor:alert_notifications'), {
			'feishu_enabled': 'on',
			'feishu_name': 'new',
			'feishu_alert_name': 'new alert',
			'feishu_webhook_url': '',
		})

		data = self.vue_data(response)

		self.assertEqual(response.status_code, 400)
		self.assertEqual(data['save_message'], '告警通知保存失败，请检查表单信息')
		self.assertFalse(data['save_ok'])
		config.refresh_from_db()
		self.assertEqual(config.decrypted_webhook_url, 'https://open.feishu.cn/open-apis/bot/v2/hook/original')
		self.assertEqual(config.name, 'old')
		self.assertEqual(config.alert_name, '')
		self.assertEqual(AlertNotificationConfig.objects.count(), 1)

	def test_alert_notifications_blank_alert_name_stays_blank(self):
		self.set_role(DevOpsRole.ROLE_OPERATOR)

		response = self.client.post(reverse('monitor:alert_notifications'), {
			'feishu_enabled': 'on',
			'feishu_name': 'feishu',
			'feishu_alert_name': '',
			'feishu_webhook_url': 'https://open.feishu.cn/open-apis/bot/v2/hook/test',
		})

		data = self.vue_data(response)

		self.assertEqual(response.status_code, 200)
		self.assertEqual(data['save_message'], '告警通知保存成功')
		self.assertTrue(data['save_ok'])
		self.assertEqual(data['notifications']['feishu']['alert_name'], '')
		config = AlertNotificationConfig.objects.get(provider=AlertNotificationConfig.PROVIDER_FEISHU)
		self.assertEqual(config.name, 'feishu')
		self.assertEqual(config.alert_name, '')

	def test_alert_notifications_rejects_invalid_webhook(self):
		self.set_role(DevOpsRole.ROLE_OPERATOR)

		response = self.client.post(reverse('monitor:alert_notifications'), {
			'feishu_enabled': 'on',
			'feishu_webhook_url': 'javascript:alert(1)',
		})

		self.assertEqual(response.status_code, 400)
		data = self.vue_data(response)
		self.assertEqual(data['save_message'], '告警通知保存失败，请检查表单信息')
		self.assertFalse(data['save_ok'])
		self.assertEqual(data['notifications']['feishu']['webhook_url'], 'javascript:alert(1)')
		self.assertContains(response, 'Webhook 地址必须是 http:// 或 https://', status_code=400)
		self.assertEqual(AlertNotificationConfig.objects.count(), 0)

	def test_alert_notifications_invalid_update_keeps_database_unchanged(self):
		self.set_role(DevOpsRole.ROLE_OPERATOR)
		config = AlertNotificationConfig.objects.create(
			provider=AlertNotificationConfig.PROVIDER_WECOM,
			name='old wecom',
			alert_name='old alert',
			enabled=True,
			webhook_url='https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=old-key',
		)
		encrypted = config.webhook_url

		response = self.client.post(reverse('monitor:alert_notifications'), {
			'provider': AlertNotificationConfig.PROVIDER_WECOM,
			'wecom_enabled': 'on',
			'wecom_name': 'new wecom',
			'wecom_alert_name': 'new alert',
			'wecom_webhook_url': 'javascript:alert(1)',
		})
		data = self.vue_data(response)

		self.assertEqual(response.status_code, 400)
		self.assertEqual(data['save_message'], '告警通知保存失败，请检查表单信息')
		self.assertEqual(data['notifications']['wecom']['name'], 'new wecom')
		self.assertEqual(data['notifications']['wecom']['alert_name'], 'new alert')
		self.assertEqual(data['notifications']['wecom']['webhook_url'], 'javascript:alert(1)')
		config.refresh_from_db()
		self.assertEqual(config.name, 'old wecom')
		self.assertEqual(config.alert_name, 'old alert')
		self.assertTrue(config.enabled)
		self.assertEqual(config.webhook_url, encrypted)
		self.assertEqual(AlertNotificationConfig.objects.count(), 1)

	@mock.patch('monitor.views.send_alert_notification', return_value={'ok': True, 'message': '测试通知发送成功'})
	def test_operator_can_test_alert_notification_without_saving(self, send_mock):
		self.set_role(DevOpsRole.ROLE_OPERATOR)

		response = self.client.post(reverse('monitor:alert_notifications_test'), {
			'provider': AlertNotificationConfig.PROVIDER_WECOM,
			'wecom_enabled': 'on',
			'wecom_name': 'wecom',
			'wecom_alert_name': 'wecom alert',
			'wecom_webhook_url': 'https://qyapi.weixin.qq.com/cgi-bin/webhook/send',
		})

		self.assertEqual(response.status_code, 200)
		self.assertContains(response, '测试通知发送成功')
		self.assertEqual(AlertNotificationConfig.objects.count(), 0)
		self.assertEqual(send_mock.call_args[0][0].provider, AlertNotificationConfig.PROVIDER_WECOM)
		self.assertEqual(send_mock.call_args[0][0].name, 'wecom')
		self.assertEqual(send_mock.call_args[0][0].alert_name, 'wecom alert')

	@mock.patch('monitor.services.urlrequest.urlopen')
	def test_wecom_receives_real_alert_when_alert_is_created(self, urlopen_mock):
		urlopen_mock.return_value = MockWebhookResponse('{"errcode":0,"errmsg":"ok"}')
		host = NewLinux.objects.create(
			linux_name='webhook-host',
			linux_ip='127.0.0.1',
			linux_hostname='webhook-host',
			linux_port='22',
			linux_user='root',
			linux_passwd='',
		)
		AlertNotificationConfig.objects.create(
			provider=AlertNotificationConfig.PROVIDER_WECOM,
			name='wecom',
			alert_name='CPU 告警',
			enabled=True,
			webhook_url='https://qyapi.weixin.qq.com/cgi-bin/webhook/send',
		)

		alert, created = record_alert(host, 'cpu', 'CPU 使用率超过阈值', AlertEvent.LEVEL_CRITICAL)

		self.assertTrue(created)
		self.assertEqual(alert.status, AlertEvent.STATUS_OPEN)
		urlopen_mock.assert_called_once()
		request = urlopen_mock.call_args[0][0]
		payload = json.loads(request.data.decode('utf-8'))
		self.assertEqual(payload['msgtype'], 'text')
		content = payload['text']['content']
		self.assertIn('告警通知：CPU 告警', content)
		self.assertIn('告警名称：CPU 告警', content)
		self.assertIn('主机：webhook-host', content)
		self.assertIn('指标：cpu', content)
		self.assertIn('状态：open', content)
		self.assertIn('内容：CPU 使用率超过阈值', content)
		self.assertNotIn('qyapi.weixin.qq.com', content)

	@mock.patch('monitor.services.send_alert_notification')
	def test_alertmanager_webhook_pushes_firing_to_bound_wecom_notification(self, send_mock):
		send_mock.return_value = {'ok': True, 'message': '告警通知发送成功'}
		bound = AlertmanagerConfig.objects.create(
			name='Bound Alertmanager',
			alertmanager_url='http://bound-alertmanager.local:9093',
			enabled=True,
		)
		other = AlertmanagerConfig.objects.create(
			name='Other Alertmanager',
			alertmanager_url='http://other-alertmanager.local:9093',
			enabled=True,
		)
		bound_wecom = AlertNotificationConfig.objects.create(
			provider=AlertNotificationConfig.PROVIDER_WECOM,
			alertmanager=bound,
			name='bound wecom',
			alert_name='绑定告警',
			enabled=True,
			webhook_url='https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=bound',
		)
		AlertNotificationConfig.objects.create(
			provider=AlertNotificationConfig.PROVIDER_WECOM,
			alertmanager=other,
			name='other wecom',
			alert_name='其他告警',
			enabled=True,
			webhook_url='https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=other',
		)
		AlertNotificationConfig.objects.create(
			provider=AlertNotificationConfig.PROVIDER_FEISHU,
			alertmanager=bound,
			name='bound feishu',
			enabled=True,
			webhook_url='https://open.feishu.cn/open-apis/bot/v2/hook/bound',
		)
		payload = {
			'status': 'firing',
			'alerts': [
				{
					'status': 'firing',
					'labels': {'alertname': 'HighCPU', 'instance': 'node-1'},
					'annotations': {'summary': 'CPU 高', 'description': 'CPU 使用率过高'},
					'startsAt': '2026-07-15T07:00:00Z',
				},
				{
					'status': 'resolved',
					'labels': {'alertname': 'Recovered', 'instance': 'node-2'},
					'annotations': {'summary': '已恢复'},
				},
			],
		}

		response = self.client.post(
			reverse('monitor:alertmanager_webhook', args=[bound.id]),
			data=json.dumps(payload),
			content_type='application/json',
		)
		data = json.loads(response.content.decode('utf-8'))

		self.assertEqual(response.status_code, 200)
		self.assertTrue(data['ok'])
		self.assertEqual(data['received'], 2)
		self.assertEqual(data['firing'], 1)
		self.assertEqual(data['matched_notifications'], 1)
		self.assertEqual(data['pushed'], 1)
		send_mock.assert_called_once()
		self.assertEqual(send_mock.call_args[0][0].id, bound_wecom.id)
		self.assertIn('绑定告警', send_mock.call_args[0][1])
		content = send_mock.call_args[0][2]
		self.assertIn('Alertmanager：Bound Alertmanager', content)
		self.assertIn('主机：node-1', content)
		self.assertIn('状态：firing', content)
		self.assertIn('内容：CPU 使用率过高', content)

	@mock.patch('monitor.views.send_alert_notification')
	def test_alertmanager_webhook_ignores_non_firing_alerts(self, send_mock):
		alertmanager = AlertmanagerConfig.objects.create(
			name='Bound Alertmanager',
			alertmanager_url='http://bound-alertmanager.local:9093',
			enabled=True,
		)
		AlertNotificationConfig.objects.create(
			provider=AlertNotificationConfig.PROVIDER_WECOM,
			alertmanager=alertmanager,
			name='bound wecom',
			enabled=True,
			webhook_url='https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=bound',
		)
		payload = {
			'status': 'resolved',
			'alerts': [
				{'status': 'resolved', 'labels': {'alertname': 'Recovered'}},
			],
		}

		response = self.client.post(
			reverse('monitor:alertmanager_webhook', args=[alertmanager.id]),
			data=json.dumps(payload),
			content_type='application/json',
		)
		data = json.loads(response.content.decode('utf-8'))

		self.assertEqual(response.status_code, 200)
		self.assertEqual(data['firing'], 0)
		self.assertEqual(data['pushed'], 0)
		send_mock.assert_not_called()

	@mock.patch('monitor.services.send_alert_notification')
	def test_alertmanager_webhook_silences_matching_active_maintenance_window(self, send_mock):
		host = NewLinux.objects.create(
			linux_name='maintenance-webhook',
			linux_ip='127.0.0.7',
			linux_hostname='maintenance-webhook',
			linux_port='22',
			linux_user='root',
			linux_passwd='',
		)
		window = MaintenanceWindow.objects.create(
			name='webhook maintenance',
			starts_at=timezone.now() - timedelta(minutes=1),
			ends_at=timezone.now() + timedelta(minutes=1),
		)
		window.hosts.add(host)
		alertmanager = AlertmanagerConfig.objects.create(
			name='Webhook Alertmanager',
			alertmanager_url='http://webhook-alertmanager.local:9093',
			enabled=True,
		)
		AlertNotificationConfig.objects.create(
			provider=AlertNotificationConfig.PROVIDER_WECOM,
			alertmanager=alertmanager,
			name='企业微信',
			enabled=True,
			webhook_url='https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=maintenance',
		)

		response = self.client.post(
			reverse('monitor:alertmanager_webhook', args=[alertmanager.id]),
			data=json.dumps({
				'status': 'firing',
				'alerts': [{
					'status': 'firing',
					'fingerprint': 'webhook-maintenance',
					'labels': {'alertname': 'HighCPU', 'instance': 'maintenance-webhook:9100'},
					'annotations': {'description': 'CPU 使用率过高'},
				}],
			}),
			content_type='application/json',
		)

		self.assertEqual(response.status_code, 200)
		data = json.loads(response.content.decode('utf-8'))
		self.assertTrue(data['ok'])
		self.assertEqual(data['pushed'], 0)
		self.assertEqual(data['silenced'], 1)
		send_mock.assert_not_called()
		event = AlertEvent.objects.get(fingerprint='alertmanager:%s:webhook-maintenance' % alertmanager.id)
		self.assertEqual(event.host, host)
		self.assertEqual(event.status, AlertEvent.STATUS_SILENCED)

	@mock.patch('monitor.services.send_alert_notification')
	@mock.patch('monitor.services.alertmanager_get_json')
	def test_poll_alertmanager_pushes_active_alert_once(self, get_json_mock, send_mock):
		send_mock.return_value = {'ok': True, 'message': '告警通知发送成功'}
		bound = AlertmanagerConfig.objects.create(
			name='生产环境',
			alertmanager_url='http://alertmanager.local:9093',
			enabled=True,
		)
		other = AlertmanagerConfig.objects.create(
			name='其他环境',
			alertmanager_url='http://other-alertmanager.local:9093',
			enabled=True,
		)
		bound_wecom = AlertNotificationConfig.objects.create(
			provider=AlertNotificationConfig.PROVIDER_WECOM,
			alertmanager=bound,
			name='企业微信',
			alert_name='生产告警',
			enabled=True,
			webhook_url='https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=bound',
		)
		AlertNotificationConfig.objects.create(
			provider=AlertNotificationConfig.PROVIDER_WECOM,
			alertmanager=other,
			name='其他企业微信',
			alert_name='其他告警',
			enabled=True,
			webhook_url='https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=other',
		)
		get_json_mock.side_effect = [
			{
				'ok': True,
				'body': [
					{
						'status': {'state': 'active'},
						'fingerprint': 'abc123',
						'labels': {'alertname': 'HighCPU', 'instance': 'node-1'},
						'annotations': {'description': 'CPU 使用率过高'},
						'startsAt': '2026-07-15T07:00:00Z',
					},
					{
						'status': {'state': 'suppressed'},
						'fingerprint': 'resolved123',
						'labels': {'alertname': 'Recovered'},
					},
				],
			},
			{'ok': True, 'body': []},
		]

		result = services.poll_alertmanager_firing_alerts()

		self.assertEqual(result['alertmanagers'], 2)
		self.assertEqual(result['received'], 2)
		self.assertEqual(result['firing'], 1)
		self.assertEqual(result['pushed'], 1)
		self.assertEqual(result['skipped'], 0)
		send_mock.assert_called_once()
		self.assertEqual(send_mock.call_args[0][0].id, bound_wecom.id)
		self.assertIn('生产告警', send_mock.call_args[0][1])
		self.assertIn('Alertmanager：生产环境', send_mock.call_args[0][2])
		self.assertIn('主机：node-1', send_mock.call_args[0][2])
		self.assertEqual(AlertEvent.objects.filter(fingerprint='alertmanager:%s:abc123' % bound.id).count(), 1)

	@mock.patch('monitor.services.send_alert_notification')
	@mock.patch('monitor.services.alertmanager_get_json')
	def test_poll_alertmanager_does_not_resend_duplicate_firing_alert(self, get_json_mock, send_mock):
		send_mock.return_value = {'ok': True, 'message': '告警通知发送成功'}
		alertmanager = AlertmanagerConfig.objects.create(
			name='生产环境',
			alertmanager_url='http://alertmanager.local:9093',
			enabled=True,
		)
		AlertNotificationConfig.objects.create(
			provider=AlertNotificationConfig.PROVIDER_WECOM,
			alertmanager=alertmanager,
			name='企业微信',
			enabled=True,
			webhook_url='https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=bound',
		)
		get_json_mock.return_value = {
			'ok': True,
			'body': [
				{
					'status': {'state': 'active'},
					'fingerprint': 'same-alert',
					'labels': {'alertname': 'HighCPU', 'instance': 'node-1'},
					'annotations': {'description': 'CPU 使用率过高'},
				},
			],
		}

		first = services.poll_alertmanager_firing_alerts()
		second = services.poll_alertmanager_firing_alerts()

		self.assertEqual(first['pushed'], 1)
		self.assertEqual(first['skipped'], 0)
		self.assertEqual(second['pushed'], 0)
		self.assertEqual(second['skipped'], 1)
		send_mock.assert_called_once()
		event = AlertEvent.objects.get(fingerprint='alertmanager:%s:same-alert' % alertmanager.id)
		self.assertEqual(event.repeat_count, 2)

	@mock.patch('monitor.services.send_alert_notification')
	def test_alertmanager_poll_silences_matching_active_maintenance_window(self, send_mock):
		host = NewLinux.objects.create(
			linux_name='maintenance-node',
			linux_ip='127.0.0.8',
			linux_hostname='maintenance-node',
			linux_port='22',
			linux_user='root',
			linux_passwd='',
		)
		window = MaintenanceWindow.objects.create(
			name='planned maintenance',
			starts_at=timezone.now() - timedelta(minutes=1),
			ends_at=timezone.now() + timedelta(minutes=1),
		)
		window.hosts.add(host)
		alertmanager = AlertmanagerConfig.objects.create(
			name='生产环境',
			alertmanager_url='http://alertmanager.local:9093',
			enabled=True,
		)
		AlertNotificationConfig.objects.create(
			provider=AlertNotificationConfig.PROVIDER_WECOM,
			alertmanager=alertmanager,
			name='企业微信',
			enabled=True,
			webhook_url='https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=bound',
		)

		result = services.push_alertmanager_firing_alerts(alertmanager, [{
			'status': {'state': 'active'},
			'fingerprint': 'maintenance-alert',
			'labels': {'alertname': 'HighCPU', 'instance': 'maintenance-node:9100'},
			'annotations': {'description': 'CPU 使用率过高'},
		}], dedupe=True)

		self.assertEqual(result['attempted'], 1)
		self.assertEqual(result['pushed'], 0)
		self.assertEqual(result['silenced'], 1)
		self.assertEqual(result['results'], [])
		send_mock.assert_not_called()
		event = AlertEvent.objects.get(fingerprint='alertmanager:%s:maintenance-alert' % alertmanager.id)
		self.assertEqual(event.host, host)
		self.assertEqual(event.status, AlertEvent.STATUS_SILENCED)
		self.assertEqual(event.remark, '命中维护窗口')

	@mock.patch('monitor.services.send_alert_notification')
	def test_alertmanager_poll_keeps_notifications_available_when_maintenance_lookup_fails(self, send_mock):
		host = NewLinux.objects.create(
			linux_name='maintenance-lookup-failure',
			linux_ip='127.0.0.9',
			linux_hostname='maintenance-lookup-failure',
			linux_port='22',
			linux_user='root',
			linux_passwd='',
		)
		alertmanager = AlertmanagerConfig.objects.create(
			name='生产环境',
			alertmanager_url='http://alertmanager.local:9093',
			enabled=True,
		)
		AlertNotificationConfig.objects.create(
			provider=AlertNotificationConfig.PROVIDER_WECOM,
			alertmanager=alertmanager,
			name='企业微信',
			enabled=True,
			webhook_url='https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=bound',
		)
		with mock.patch('devops.services.active_maintenance_windows_for_host', side_effect=RuntimeError('db unavailable')):
			result = services.push_alertmanager_firing_alerts(alertmanager, [{
				'status': {'state': 'active'},
				'fingerprint': 'maintenance-lookup-failure',
				'labels': {'alertname': 'HighCPU', 'instance': host.linux_name},
				'annotations': {'description': 'CPU 使用率过高'},
			}], dedupe=True)

		self.assertEqual(result['pushed'], 1)
		self.assertEqual(result['silenced'], 0)
		send_mock.assert_called_once()
		event = AlertEvent.objects.get(fingerprint='alertmanager:%s:maintenance-lookup-failure' % alertmanager.id)
		self.assertEqual(event.status, AlertEvent.STATUS_OPEN)

	@mock.patch('monitor.crontab.poll_alertmanager_firing_alerts')
	def test_poll_alertmanager_notifications_returns_summary(self, poll_mock):
		poll_mock.return_value = {
			'alertmanagers': 1,
			'received': 2,
			'firing': 1,
			'pushed': 1,
			'skipped': 0,
			'errors': [],
		}

		result = poll_alertmanager_notifications()

		self.assertEqual(result['pushed'], 1)
		poll_mock.assert_called_once()

	@mock.patch('monitor.services.urlrequest.urlopen')
	def test_duplicate_alert_does_not_resend_wecom_notification(self, urlopen_mock):
		urlopen_mock.return_value = MockWebhookResponse('{"errcode":0,"errmsg":"ok"}')
		host = NewLinux.objects.create(
			linux_name='dedupe-host',
			linux_ip='127.0.0.1',
			linux_hostname='dedupe-host',
			linux_port='22',
			linux_user='root',
			linux_passwd='',
		)
		AlertNotificationConfig.objects.create(
			provider=AlertNotificationConfig.PROVIDER_WECOM,
			name='wecom',
			enabled=True,
			webhook_url='https://qyapi.weixin.qq.com/cgi-bin/webhook/send',
		)

		record_alert(host, 'disk', '磁盘使用率超过阈值')
		record_alert(host, 'disk', '磁盘仍然超过阈值')

		urlopen_mock.assert_called_once()

	@mock.patch('monitor.services.urlrequest.urlopen')
	def test_wecom_receives_recovery_alert_when_alert_resolves(self, urlopen_mock):
		urlopen_mock.return_value = MockWebhookResponse('{"errcode":0,"errmsg":"ok"}')
		host = NewLinux.objects.create(
			linux_name='recover-host',
			linux_ip='127.0.0.1',
			linux_hostname='recover-host',
			linux_port='22',
			linux_user='root',
			linux_passwd='',
		)
		AlertNotificationConfig.objects.create(
			provider=AlertNotificationConfig.PROVIDER_WECOM,
			name='wecom',
			alert_name='',
			enabled=True,
			webhook_url='https://qyapi.weixin.qq.com/cgi-bin/webhook/send',
		)
		record_alert(host, 'memory', '内存使用率超过阈值')

		alert = resolve_alert(host, 'memory', '内存使用率恢复正常')

		self.assertIsNotNone(alert)
		self.assertEqual(urlopen_mock.call_count, 2)
		request = urlopen_mock.call_args[0][0]
		payload = json.loads(request.data.decode('utf-8'))
		content = payload['text']['content']
		self.assertIn('状态：resolved', content)
		self.assertIn('内容：内存使用率恢复正常', content)

	def test_wecom_nonzero_errcode_is_failure(self):
		config = AlertNotificationConfig.objects.create(
			provider=AlertNotificationConfig.PROVIDER_WECOM,
			name='wecom',
			enabled=True,
			webhook_url='https://qyapi.weixin.qq.com/cgi-bin/webhook/send',
		)

		with mock.patch('monitor.services.urlrequest.urlopen', return_value=MockWebhookResponse('{"errcode":40001,"errmsg":"invalid"}')):
			result = services.send_alert_notification(config, '告警通知：CPU', '内容')

		self.assertFalse(result['ok'])
		self.assertEqual(result['message'], '通知平台返回失败，请检查通知配置')

	@mock.patch('monitor.services.urlrequest.urlopen')
	def test_https_alert_notification_uses_certifi_context(self, urlopen_mock):
		urlopen_mock.return_value = MockWebhookResponse('{"errcode":0,"errmsg":"ok"}')
		config = AlertNotificationConfig.objects.create(
			provider=AlertNotificationConfig.PROVIDER_WECOM,
			name='wecom',
			enabled=True,
			webhook_url='https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=test-key',
		)

		result = services.send_alert_notification(config)

		self.assertTrue(result['ok'])
		self.assertIn('context', urlopen_mock.call_args[1])

	@mock.patch('monitor.services.urlrequest.urlopen')
	def test_alert_notification_ssl_failure_returns_safe_message(self, urlopen_mock):
		urlopen_mock.side_effect = services.urlerror.URLError(
			ssl.SSLError('certificate verify failed: sensitive detail')
		)
		config = AlertNotificationConfig.objects.create(
			provider=AlertNotificationConfig.PROVIDER_WECOM,
			name='wecom',
			enabled=True,
			webhook_url='https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=test-key',
		)

		result = services.send_alert_notification(config)

		self.assertFalse(result['ok'])
		self.assertEqual(result['message'], 'HTTPS 证书校验失败，请检查运行环境 CA 证书配置')
		self.assertNotIn('sensitive detail', result['message'])

	@mock.patch('monitor.views.send_alert_notification')
	def test_alert_notification_test_masks_untrusted_provider_failure_details(self, send_mock):
		self.set_role(DevOpsRole.ROLE_OPERATOR)
		send_mock.return_value = {
			'ok': False,
			'message': 'untrusted response with recognizable-fragment',
		}

		response = self.client.post(reverse('monitor:alert_notifications_test'), {
			'provider': AlertNotificationConfig.PROVIDER_WECOM,
			'wecom_enabled': 'on',
			'wecom_name': 'wecom',
			'wecom_webhook_url': 'https://notify.example.test/path/secret-fragment',
		})
		data = self.vue_data(response)

		self.assertEqual(response.status_code, 400)
		self.assertEqual(data['test_message'], '测试通知发送失败，请检查通知配置和网络')
		self.assertNotIn('recognizable-fragment', response.context['vue_page_payload'])
		self.assertNotIn('secret-fragment', response.context['vue_page_payload'])
		self.assertNotContains(response, 'recognizable-fragment', status_code=400)
		self.assertNotContains(response, 'secret-fragment', status_code=400)

	@mock.patch('monitor.views.query_alertmanager_alerts')
	def test_metric_query_alerts_selects_enabled_alertmanager_and_returns_safe_rows(self, query_mock):
		AlertmanagerConfig.objects.create(name='Disabled', alertmanager_url='http://disabled.local:9093', enabled=False)
		selected = AlertmanagerConfig.objects.create(name='Primary', alertmanager_url='http://alerts.local:9093', enabled=True)
		query_mock.return_value = {'ok': True, 'body': [{
			'status': {'state': 'active'}, 'startsAt': '2025-01-01T00:00:00Z',
			'labels': {'alertname': 'HostDown', 'token': 'private-token'},
			'annotations': {'summary': 'Host down', 'password': 'private-password'},
		}]}

		response = self.client.post(reverse('monitor:metric_query_alerts'), {'alertmanager_id': selected.id})

		self.assertEqual(response.status_code, 200)
		self.assertEqual(response.json()['alertmanager_id'], selected.id)
		self.assertEqual(response.json()['alerts']['rows'][0]['status'], 'firing')
		self.assertEqual(response.json()['alerts']['rows'][0]['labels'], {'alertname': 'HostDown'})
		self.assertEqual(response.json()['alerts']['rows'][0]['annotations'], {'summary': 'Host down'})
		self.assertNotIn('private-token', response.content.decode('utf-8'))
		query_mock.assert_called_once_with(selected)

	@mock.patch('monitor.views.query_alertmanager_alerts')
	def test_metric_query_alerts_rejects_invalid_config_and_masks_failure(self, query_mock):
		config = AlertmanagerConfig.objects.create(alertmanager_url='http://alerts.local:9093', enabled=True)
		invalid = self.client.post(reverse('monitor:metric_query_alerts'), {'alertmanager_id': 'bad'})
		missing = self.client.post(reverse('monitor:metric_query_alerts'))
		query_mock.return_value = {'ok': False, 'message': 'raw upstream token=private-value'}
		failed = self.client.post(reverse('monitor:metric_query_alerts'), {'alertmanager_id': config.id})

		self.assertEqual(invalid.status_code, 400)
		self.assertEqual(invalid.json(), {'ok': False, 'message': '选择的 Alertmanager 对接不可用'})
		self.assertEqual(missing.status_code, 502)
		self.assertEqual(missing.json(), {'ok': False, 'message': 'Alertmanager 告警查询失败'})
		self.assertEqual(failed.status_code, 502)
		self.assertEqual(failed.json(), {'ok': False, 'message': 'Alertmanager 告警查询失败'})
		self.assertNotIn('private-value', failed.content.decode('utf-8'))

	def test_metric_query_alerts_payload_and_frontend_contract(self):
		primary = AlertmanagerConfig.objects.create(
			name='Primary Alerts', alertmanager_url='http://alerts-primary.local:9093', enabled=True,
		)
		secondary = AlertmanagerConfig.objects.create(
			name='Secondary Alerts', alertmanager_url='http://alerts-secondary.local:9093', enabled=True,
		)
		data = self.vue_data(self.client.get(reverse('monitor:alert_query')))
		with open('static/js/ops-vue-pages.js', 'r') as handle:
			vue_source = handle.read()
		with open('static/css/ops-vue-pages.css', 'r') as handle:
			css_source = handle.read()

		self.assertEqual(data['alerts_url'], reverse('monitor:metric_query_alerts'))
		self.assertEqual(data['alertmanager_configs'], [
			{'id': primary.id, 'name': 'Primary Alerts'},
			{'id': secondary.id, 'name': 'Secondary Alerts'},
		])
		self.assertEqual(data['selected_alertmanager_id'], primary.id)
		for text in (
			'metric-tab-alerts', 'metric-view-alerts', 'metricAlertmanagerConfigs',
			'selectedMetricAlertmanagerId', 'canExecuteMetricAlerts',
			"form.set(kind === 'alerts' ? 'alertmanager_id' : 'prometheus_id'",
			'v-for="config in metricAlertmanagerConfigs"', 'normalizeMetricAlerts',
		):
			self.assertIn(text, vue_source)
		self.assertEqual(vue_source.count('id="metric-tab-'), 4)
		self.assertIn('grid-template-columns: repeat(4, minmax(0, 1fr));', css_source)


class MonitorDashboardTests(TestCase):
	def setUp(self):
		self.user = User.objects.create(
			user='dashboard-user', email='dashboard@example.com',
			password='plain-password', confirm_pwd='plain-password',
		)
		session = self.client.session
		session['is_login'] = True
		session['user_id'] = self.user.id
		session['user_name'] = self.user.user
		session.save()

	def vue_data(self, response):
		return json.loads(response.context['vue_page_payload'])['data']

	def test_dashboard_page_requires_login_and_lists_enabled_prometheus_only(self):
		enabled = PrometheusConfig.objects.create(name='主集群', prometheus_url='http://prometheus.local', enabled=True)
		PrometheusConfig.objects.create(name='停用', prometheus_url='http://disabled.local', enabled=False)
		response = self.client.get(reverse('monitor:monitor_dashboard'))
		data = self.vue_data(response)

		self.assertEqual(response.status_code, 200)
		self.assertEqual(response.context['vue_page_kind'], 'monitor-dashboard')
		self.assertEqual(data['prometheus_configs'], [{'id': enabled.id, 'name': '主集群'}])
		self.assertEqual(data['selected_prometheus_id'], enabled.id)
		self.assertEqual(data['dashboard_url'], reverse('monitor:monitor_dashboard_data'))
		self.assertContains(response, 'css/monitor-command-center.css')
		self.assertContains(response, 'monitor-command-center.css?v=20260807-dense-observability')
		self.assertContains(response, 'ops-vue-pages.js?v=20260807-monitor-dense-observability')

		session = self.client.session
		session.clear()
		session.save()
		unauthorized = self.client.get(reverse('monitor:monitor_dashboard'))
		self.assertEqual(unauthorized.status_code, 302)

	def test_dashboard_frontend_shows_node_resource_details_and_single_row_options(self):
		with open('static/js/ops-vue-pages.js', 'r') as handle:
			vue_source = handle.read()
		with open('static/css/monitor-command-center.css', 'r') as handle:
			css_source = handle.read()

		fcc_target = vue_source.split('class="fcc-target"', 1)[1].split('</article>', 1)[0]
		for text in ('CPU 使用率', '总核数 [[ resource.total ]]', 'fcc-resource-grid',
					 '使用率 [[ dashboardMetricText(resource.key === \'memory\' ? row.memory : row.disk) ]]',
					 '总量 <strong>[[ resource.total ]]</strong>', '已用 <strong>[[ resource.used ]]</strong>',
					 '剩余 <strong>[[ resource.remaining ]]</strong>', '磁盘 I/O', '[[ row.io.read ]]',
					 '[[ row.io.write ]]'):
			self.assertIn(text, fcc_target)
		self.assertIn('.fcc-resource-grid {', css_source)
		self.assertIn('.fcc-io {', css_source)
		self.assertIn('.ops-dashboard-node-option {', css_source)
		self.assertIn('display: flex;', css_source)
		self.assertIn('width: 100%;', css_source)
		self.assertIn('white-space: nowrap;', css_source)

	def test_dashboard_frontend_uses_dense_observability_sections(self):
		with open('static/js/ops-vue-pages.js', 'r') as handle:
			vue_source = handle.read()
		with open('static/css/monitor-command-center.css', 'r') as handle:
			css_source = handle.read()

		for marker in (
			'ops-monitor-overview', 'ops-monitor-summary-grid',
			'ops-monitor-chart-grid', 'ops-monitor-resource-table',
		):
			self.assertIn(marker, vue_source)
		self.assertIn('.ops-monitor-overview {', css_source)
		self.assertIn('@media (max-width: 760px)', css_source)

	@mock.patch('monitor.views.query_prometheus_dashboard')
	def test_dashboard_data_requires_post_and_selected_enabled_config(self, query_dashboard):
		config = PrometheusConfig.objects.create(name='Prometheus', prometheus_url='http://prometheus.local', enabled=True)
		self.assertEqual(self.client.get(reverse('monitor:monitor_dashboard_data')).status_code, 405)

		invalid = self.client.post(reverse('monitor:monitor_dashboard_data'), {'prometheus_id': config.id + 99})
		self.assertEqual(invalid.status_code, 400)
		self.assertEqual(invalid.json(), {'ok': False, 'message': '选择的 Prometheus 对接不可用'})
		query_dashboard.assert_not_called()

		query_dashboard.return_value = {
			'ok': True, 'hosts': [{'instance': 'node-a', 'cpu': 12.5}],
			'pods': [{'namespace': 'ops', 'pod': 'api-0', 'status': 'Running'}],
			'errors': ['Pod 内存指标暂时不可用'],
		}
		response = self.client.post(reverse('monitor:monitor_dashboard_data'), {'prometheus_id': config.id})
		self.assertEqual(response.status_code, 200)
		self.assertEqual(response.json()['prometheus_id'], config.id)
		self.assertEqual(response.json()['hosts'][0]['instance'], 'node-a')
		self.assertEqual(response.json()['errors'], ['Pod 内存指标暂时不可用'])
		query_dashboard.assert_called_once_with(config)

	@mock.patch('monitor.views.query_prometheus_dashboard')
	def test_dashboard_data_returns_safe_502_only_when_all_metric_groups_fail(self, query_dashboard):
		config = PrometheusConfig.objects.create(name='Prometheus', prometheus_url='http://prometheus.local', enabled=True)
		query_dashboard.return_value = {
			'ok': True, 'hosts': [], 'pods': [],
			'errors': ['指标%s不可用' % index for index in range(len(services.PROMETHEUS_DASHBOARD_QUERIES))],
		}

		response = self.client.post(reverse('monitor:monitor_dashboard_data'), {'prometheus_id': config.id})

		self.assertEqual(response.status_code, 502)
		self.assertEqual(response.json(), {
			'ok': False,
			'message': '监控看板数据暂时不可用，请稍后刷新',
		})

	@mock.patch('monitor.services.query_prometheus')
	def test_dashboard_service_normalizes_safe_partial_metric_data(self, query_prometheus_mock):
		config = PrometheusConfig(name='主集群', prometheus_url='http://prometheus.local', enabled=True)

		def response(rows):
			return {'ok': True, 'body': {'status': 'success', 'data': {'resultType': 'vector', 'result': rows}}}

		query_prometheus_mock.side_effect = [
			response([{'metric': {'instance': 'node-a:9100', 'apiToken': 'hidden'}, 'value': [1, '27.25']}]),
			response([{'metric': {'instance': 'node-a:9100'}, 'value': [1, '63']}]),
			{'ok': False, 'message': 'http://private.internal/secret'},
			response([{'metric': {'instance': 'node-a:9100'}, 'value': [1, '8']}]),
			response([{'metric': {'instance': 'node-a:9100'}, 'value': [1, '16000']}]),
			response([{'metric': {'instance': 'node-a:9100'}, 'value': [1, '5920']}]),
			response([{'metric': {'instance': 'node-a:9100'}, 'value': [1, '100000']}]),
			response([{'metric': {'instance': 'node-a:9100'}, 'value': [1, '25000']}]),
			response([{'metric': {'instance': 'node-a:9100'}, 'value': [1, '1048576.5']}]),
			response([{'metric': {'instance': 'node-a:9100'}, 'value': [1, '2097152.25']}]),
			response([{'metric': {'instance': 'node-a:9100'}, 'value': [1, '1.5']}]),
			response([{'metric': {'instance': 'node-a:9100'}, 'value': [1, '1.25']}]),
			response([{'metric': {'instance': 'node-a:9100'}, 'value': [1, '0.75']}]),
			response([{'metric': {'namespace': 'ops', 'pod': 'api-0', 'kubernetes_cluster': 'cluster-a'}, 'value': [1, '2.5']}]),
			response([{'metric': {'namespace': 'ops', 'pod': 'api-0', 'cluster_name': 'ignored-lower-priority'}, 'value': [1, '48.8']}]),
			response([{'metric': {'namespace': 'ops', 'pod': 'api-0', 'phase': 'Running'}, 'value': [1, '1']}]),
		]

		result = services.query_prometheus_dashboard(config)

		self.assertEqual(len(query_prometheus_mock.call_args_list), 16)
		self.assertEqual(services.PROMETHEUS_DASHBOARD_QUERIES['host_io_read'],
			'sum by (instance) (rate(node_disk_read_bytes_total[5m]))')
		self.assertEqual(services.PROMETHEUS_DASHBOARD_QUERIES['host_io_write'],
			'sum by (instance) (rate(node_disk_written_bytes_total[5m]))')
		self.assertEqual(services.PROMETHEUS_DASHBOARD_QUERIES['host_load_one'], 'node_load1')
		self.assertEqual(services.PROMETHEUS_DASHBOARD_QUERIES['host_load_five'], 'node_load5')
		self.assertEqual(services.PROMETHEUS_DASHBOARD_QUERIES['host_load_fifteen'], 'node_load15')
		self.assertEqual(result['hosts'], [{
			'instance': 'node-a:9100', 'cpu': 27.25, 'memory': 63.0,
			'io_read': 1048576.5, 'io_write': 2097152.25,
			'load': {'one': 1.5, 'five': 1.25, 'fifteen': 0.75},
			'capacity': {
				'cpu': {'total': 8.0, 'used': 2.18, 'remaining': 5.82},
				'memory': {'total': 16000.0, 'used': 10080.0, 'remaining': 5920.0},
				'disk': {'total': 100000.0, 'used': 75000.0, 'remaining': 25000.0},
			},
		}])
		self.assertEqual(result['pods'], [
			{'cluster': 'cluster-a', 'namespace': 'ops', 'pod': 'api-0', 'cpu': 2.5},
			{'cluster': 'ignored-lower-priority', 'namespace': 'ops', 'pod': 'api-0', 'memory': 48.8},
			{'cluster': '主集群', 'namespace': 'ops', 'pod': 'api-0', 'status': 'Running'},
		])
		self.assertEqual(result['errors'], ['主机磁盘 指标暂时不可用'])
		self.assertNotIn('hidden', json.dumps(result))
		self.assertNotIn('private.internal', json.dumps(result))

	@mock.patch('monitor.services.query_prometheus')
	def test_dashboard_service_uses_cluster_label_priority_and_config_fallback(self, query_prometheus_mock):
		config = PrometheusConfig(name='配置集群', prometheus_url='http://prometheus.local', enabled=True)

		def response(rows):
			return {'ok': True, 'body': {'status': 'success', 'data': {'resultType': 'vector', 'result': rows}}}

		query_prometheus_mock.side_effect = [response([])] * 13 + [
			response([{'metric': {
				'namespace': 'ops', 'pod': 'api-0', 'cluster': 'primary',
				'kubernetes_cluster': 'secondary', 'cluster_name': 'tertiary', 'token': 'private',
			}, 'value': [1, '1']}]),
			response([{'metric': {'namespace': 'ops', 'pod': 'worker-0'}, 'value': [1, '2']}]),
			response([]),
		]

		result = services.query_prometheus_dashboard(config)

		self.assertEqual(result['pods'], [
			{'cluster': 'primary', 'namespace': 'ops', 'pod': 'api-0', 'cpu': 1.0},
			{'cluster': '配置集群', 'namespace': 'ops', 'pod': 'worker-0', 'memory': 2.0},
		])
		self.assertNotIn('private', json.dumps(result))


class PrometheusServiceTests(TestCase):
	def prometheus_config(self):
		return PrometheusConfig(
			prometheus_url='http://prometheus.local:9090',
			enabled=True,
		)

	@mock.patch('monitor.services.prometheus_get_json')
	def test_query_metadata_uses_prometheus_paths_and_sanitizes_identifiers(
			self, prometheus_get_json):
		config = self.prometheus_config()
		metrics = ['metric_%04d' % index for index in range(
			services.PROMETHEUS_METADATA_MAX_METRICS + 5
		)]
		metrics.extend(['up', 'up', ':node_metric', 'bad-name', ' value', 123])
		labels = ['label_%04d' % index for index in range(
			services.PROMETHEUS_METADATA_MAX_LABELS + 5
		)]
		labels.extend([
			'instance', 'instance', '__name__', 'api_token', 'clientSecret',
			'bad-label', ':invalid', 'x' * (services.PROMETHEUS_IDENTIFIER_MAX_LENGTH + 1),
			None,
		])
		prometheus_get_json.side_effect = [
			{'ok': True, 'body': {'status': 'success', 'data': metrics}},
			{'ok': True, 'body': {'status': 'success', 'data': labels}},
		]

		result = services.query_prometheus_metadata(config)

		self.assertTrue(result['ok'])
		self.assertEqual(len(result['metrics']), services.PROMETHEUS_METADATA_MAX_METRICS)
		self.assertEqual(len(result['labels']), services.PROMETHEUS_METADATA_MAX_LABELS)
		self.assertEqual(result['metrics'], sorted(set(result['metrics'])))
		self.assertEqual(result['labels'], sorted(set(result['labels'])))
		self.assertNotIn('bad-name', result['metrics'])
		self.assertNotIn('value', result['metrics'])
		self.assertNotIn('api_token', result['labels'])
		self.assertNotIn('clientSecret', result['labels'])
		self.assertNotIn(':invalid', result['labels'])
		self.assertEqual(prometheus_get_json.call_args_list, [
			mock.call(config, '/api/v1/label/__name__/values'),
			mock.call(config, '/api/v1/labels'),
		])

	@mock.patch('monitor.services.prometheus_get_json')
	def test_query_metadata_rejects_failed_and_malformed_upstream_without_leaks(
			self, prometheus_get_json):
		config = self.prometheus_config()
		cases = (
			(
				{'ok': False, 'message': 'token=transport-secret'},
				services.PROMETHEUS_METADATA_FAILURE_MESSAGE,
			),
			(
				{'ok': True, 'body': {'status': 'error', 'error': 'upstream-secret'}},
				services.PROMETHEUS_METADATA_FAILURE_MESSAGE,
			),
			(
				{'ok': True, 'body': {'status': 'success', 'data': {}}},
				services.PROMETHEUS_METADATA_FORMAT_MESSAGE,
			),
			(
				{'ok': True, 'body': {'status': 'unexpected', 'data': []}},
				services.PROMETHEUS_METADATA_FORMAT_MESSAGE,
			),
		)
		for upstream_result, expected_message in cases:
			with self.subTest(expected_message=expected_message, upstream=upstream_result):
				prometheus_get_json.reset_mock()
				prometheus_get_json.return_value = upstream_result
				result = services.query_prometheus_metadata(config)
				self.assertEqual(result, {'ok': False, 'message': expected_message})
				self.assertNotIn('secret', json.dumps(result))
				prometheus_get_json.assert_called_once_with(
					config, '/api/v1/label/__name__/values',
				)

	@mock.patch('monitor.services.prometheus_get_json')
	def test_query_metadata_rejects_malformed_labels_response(self, prometheus_get_json):
		config = self.prometheus_config()
		prometheus_get_json.side_effect = [
			{'ok': True, 'body': {'status': 'success', 'data': ['up']}},
			{'ok': True, 'body': {'status': 'success', 'data': 'private-label-value'}},
		]

		result = services.query_prometheus_metadata(config)

		self.assertEqual(result, {
			'ok': False,
			'message': services.PROMETHEUS_METADATA_FORMAT_MESSAGE,
		})
		self.assertNotIn('private-label-value', json.dumps(result))

	def test_target_name_uses_safe_label_priority_and_endpoint_fallback(self):
		payload = services.normalize_prometheus_targets({
			'data': {'activeTargets': [
				{'labels': {
					'name': 'explicit-name', 'pod': 'pod-name', 'node': 'node-name',
					'service': 'service-name', 'endpoint': 'endpoint-name',
					'instance': 'host-a:9100', 'job': 'node',
				}},
				{'labels': {'endpoint': 'metrics', 'instance': 'host-b:9100'}},
				{'labels': {'endpoint': 'token=private-value', 'instance': 'host-c:9100'}},
			]},
		})

		self.assertEqual(payload['rows'][0]['name'], 'explicit-name')
		self.assertEqual(payload['rows'][1]['name'], 'metrics')
		self.assertEqual(payload['rows'][2]['name'], 'host-c:9100')
		self.assertNotIn('private-value', json.dumps(payload))

	@mock.patch('monitor.services.prometheus_get_json')
	def test_targets_nonempty_does_not_fallback_and_rules_allow_empty_results(self, prometheus_get_json):
		config = self.prometheus_config()
		prometheus_get_json.side_effect = [
			{'ok': True, 'body': {'status': 'success', 'data': {'activeTargets': [
				{'labels': {'instance': 'host-a'}, 'health': 'up'},
			]}}},
			{'ok': True, 'body': {'status': 'success', 'data': {'groups': []}}},
		]

		targets_result = services.query_prometheus_targets(config)
		rules_result = services.query_prometheus_rules(config)

		self.assertTrue(targets_result['ok'])
		self.assertTrue(rules_result['ok'])
		self.assertEqual(
			services.normalize_prometheus_targets(targets_result['body'])['summary']['up'],
			1,
		)
		self.assertEqual(services.normalize_prometheus_rules(rules_result['body']), services.empty_prometheus_rules())
		self.assertEqual(prometheus_get_json.call_args_list, [
			mock.call(config, '/api/v1/targets', {'state': 'active'}),
			mock.call(config, '/api/v1/rules', None),
		])

	@mock.patch('monitor.services.query_prometheus')
	@mock.patch('monitor.services.prometheus_get_json')
	def test_targets_empty_uses_up_fallback_and_sanitizes_labels(
			self, prometheus_get_json, query_prometheus_mock):
		config = self.prometheus_config()
		prometheus_get_json.return_value = {
			'ok': True,
			'body': {'status': 'success', 'data': {'activeTargets': []}},
		}
		query_prometheus_mock.return_value = {
			'ok': True,
			'body': {
				'status': 'success',
				'data': {
					'resultType': 'vector',
					'result': [
						{
							'metric': {
								'__name__': 'up',
								'instance': 'host-a:9100',
								'job': 'node',
								'pod': 'node-exporter-a',
								'api_token': 'private-token',
							},
							'value': [1710000000, '1'],
						},
						{
							'metric': {'instance': 'host-b:9100', 'job': 'node'},
							'value': [1710000000, '0'],
						},
					],
				},
			},
		}

		result = services.query_prometheus_targets(config)
		payload = services.normalize_prometheus_targets(result['body'])

		self.assertTrue(result['ok'])
		self.assertEqual(payload['summary'], {
			'total': 2,
			'up': 1,
			'down': 1,
			'unknown': 0,
			'with_errors': 0,
		})
		self.assertEqual(payload['rows'][0]['scrape_pool'], 'node')
		self.assertEqual(payload['rows'][0]['name'], 'node-exporter-a')
		self.assertEqual(payload['rows'][0]['last_scrape'], '2024-03-09T16:00:00Z')
		self.assertNotIn('api_token', payload['rows'][0]['labels'])
		self.assertNotIn('private-token', json.dumps(payload))
		query_prometheus_mock.assert_called_once_with(config, 'up')

	def test_up_fallback_timestamp_is_safe_and_does_not_change_health_value(self):
		body = {
			'data': {
				'resultType': 'vector',
				'result': [
					{'metric': {'instance': 'valid'}, 'value': [1710000000, '1']},
					{'metric': {'instance': 'text'}, 'value': ['invalid', '0']},
					{'metric': {'instance': 'infinite'}, 'value': [float('inf'), '1']},
					{'metric': {'instance': 'negative'}, 'value': [-1, '0']},
					{'metric': {'instance': 'overflow'}, 'value': [10 ** 100, '1']},
				],
			},
		}

		payload = services.normalize_prometheus_targets(
			services._prometheus_up_targets_body(body)
		)

		self.assertEqual(payload['rows'][0]['last_scrape'], '2024-03-09T16:00:00Z')
		self.assertEqual(
			[row['last_scrape'] for row in payload['rows'][1:]],
			['', '', '', ''],
		)
		self.assertEqual(
			[row['health'] for row in payload['rows']],
			['up', 'down', 'up', 'down', 'up'],
		)

	@mock.patch('monitor.services.query_prometheus')
	@mock.patch('monitor.services.prometheus_get_json')
	def test_targets_empty_returns_safe_failure_when_up_fallback_fails(
			self, prometheus_get_json, query_prometheus_mock):
		config = self.prometheus_config()
		prometheus_get_json.return_value = {
			'ok': True,
			'body': {'status': 'success', 'data': {'activeTargets': []}},
		}
		query_prometheus_mock.return_value = {
			'ok': False,
			'message': 'raw internal fallback error',
		}

		result = services.query_prometheus_targets(config)

		self.assertEqual(result, {
			'ok': False,
			'message': services.PROMETHEUS_TARGETS_FAILURE_MESSAGE,
		})
		self.assertNotIn('raw internal', result['message'])

	@mock.patch('monitor.services.query_prometheus')
	@mock.patch('monitor.services.prometheus_get_json')
	def test_targets_up_fallback_preserves_total_and_caps_rows(
			self, prometheus_get_json, query_prometheus_mock):
		config = self.prometheus_config()
		prometheus_get_json.return_value = {
			'ok': True,
			'body': {'status': 'success', 'data': {'activeTargets': []}},
		}
		total = services.PROMETHEUS_TABLE_MAX_ROWS + 3
		query_prometheus_mock.return_value = {
			'ok': True,
			'body': {
				'status': 'success',
				'data': {
					'resultType': 'vector',
					'result': [
						{
							'metric': {'instance': 'host-%s' % index},
							'value': [1710000000, '1'],
						}
						for index in range(total)
					],
				},
			},
		}

		result = services.query_prometheus_targets(config)
		payload = services.normalize_prometheus_targets(result['body'])

		self.assertEqual(payload['total_rows'], total)
		self.assertEqual(payload['summary']['up'], total)
		self.assertEqual(len(payload['rows']), services.PROMETHEUS_TABLE_MAX_ROWS)
		self.assertTrue(payload['truncated'])

	@mock.patch('monitor.services.prometheus_get_json')
	def test_targets_and_rules_queries_reject_formats_and_mask_upstream_details(self, prometheus_get_json):
		config = self.prometheus_config()
		cases = (
			(
				services.query_prometheus_targets,
				services.PROMETHEUS_TARGETS_FORMAT_MESSAGE,
				services.PROMETHEUS_TARGETS_FAILURE_MESSAGE,
			),
			(
				services.query_prometheus_rules,
				services.PROMETHEUS_RULES_FORMAT_MESSAGE,
				services.PROMETHEUS_RULES_FAILURE_MESSAGE,
			),
		)
		for query_function, format_message, failure_message in cases:
			with self.subTest(query_function=query_function.__name__, failure='format'):
				prometheus_get_json.return_value = {
					'ok': True,
					'body': {'status': 'success', 'data': {}},
				}
				self.assertEqual(query_function(config), {
					'ok': False,
					'message': format_message,
				})
			with self.subTest(query_function=query_function.__name__, failure='transport'):
				prometheus_get_json.return_value = {
					'ok': False,
					'message': 'raw upstream internal detail',
				}
				result = query_function(config)
				self.assertEqual(result, {'ok': False, 'message': failure_message})
				self.assertNotIn('raw upstream', result['message'])
			with self.subTest(query_function=query_function.__name__, failure='status'):
				prometheus_get_json.return_value = {
					'ok': True,
					'body': {'status': 'error', 'error': 'private upstream detail'},
				}
				result = query_function(config)
				self.assertEqual(result, {'ok': False, 'message': failure_message})
				self.assertNotIn('private upstream', result['message'])

	def test_normalize_targets_uses_whitelist_and_filters_sensitive_labels(self):
		labels = {
			'instance': 'host-a',
			'job': 'node',
			'a_long': 'x' * (services.PROMETHEUS_LABEL_VALUE_MAX_LENGTH + 20),
			'password': 'label-password-secret',
			'api_token': 'label-token-secret',
			'authorization': 'label-auth-secret',
			'authorizationHeader': 'label-camel-auth-secret',
			'a_nested': {'private': 'nested-secret'},
			'a_number': 12,
			'a_boolean': True,
			'a_infinite': float('inf'),
		}
		for index in range(services.PROMETHEUS_LABEL_MAX_ITEMS + 10):
			labels['label_%03d' % index] = 'value-%s' % index
		body = {
			'data': {
				'activeTargets': [{
					'labels': labels,
					'discoveredLabels': {'password': 'discovered-secret'},
					'scrapePool': 'node-pool',
					'scrapeUrl': 'http://private-target.local/metrics',
					'globalUrl': 'http://private-global.local/metrics',
					'health': 'up',
					'lastScrape': '2026-07-12T00:00:00Z',
					'lastScrapeDuration': -3,
					'lastError': 'raw target error secret',
				}],
			},
		}

		payload = services.normalize_prometheus_targets(body)
		row = payload['rows'][0]
		serialized = json.dumps(payload)

		self.assertEqual(set(row), {
			'name', 'instance', 'job', 'scrape_pool', 'health', 'last_scrape',
			'last_scrape_duration', 'labels', 'has_error',
		})
		self.assertEqual(row['instance'], 'host-a')
		self.assertEqual(row['name'], 'host-a')
		self.assertEqual(row['job'], 'node')
		self.assertIsNone(row['last_scrape_duration'])
		self.assertTrue(row['has_error'])
		self.assertEqual(payload['summary'], {
			'total': 1,
			'up': 1,
			'down': 0,
			'unknown': 0,
			'with_errors': 1,
		})
		self.assertEqual(list(row['labels']), sorted(row['labels']))
		self.assertEqual(len(row['labels']), services.PROMETHEUS_LABEL_MAX_ITEMS)
		self.assertEqual(len(row['labels']['a_long']), services.PROMETHEUS_LABEL_VALUE_MAX_LENGTH)
		self.assertEqual(row['labels']['a_number'], '12')
		self.assertEqual(row['labels']['a_boolean'], 'true')
		self.assertNotIn('password', row['labels'])
		self.assertNotIn('api_token', row['labels'])
		self.assertNotIn('authorization', row['labels'])
		self.assertNotIn('authorizationHeader', row['labels'])
		self.assertNotIn('a_nested', row['labels'])
		self.assertNotIn('a_infinite', row['labels'])
		for private_value in (
			'label-password-secret', 'label-token-secret', 'label-auth-secret',
			'label-camel-auth-secret',
			'nested-secret', 'discovered-secret', 'private-target.local',
			'private-global.local', 'raw target error secret',
		):
			self.assertNotIn(private_value, serialized)

	def test_normalize_rules_redacts_queries_and_omits_raw_rule_details(self):
		query = (
			'metric{token="query-token-secret", password!="query-password-secret", '
			'api_key=~"query-key-secret", job="node"} '
			+ ('x' * services.PROMETHEUS_RULE_QUERY_MAX_LENGTH)
		)
		body = {
			'data': {
				'groups': [{
					'name': 'system-rules',
					'file': '/private/rules/internal.yml',
					'lastEvaluation': '2026-07-12T00:00:00Z',
					'evaluationTime': 0.4,
					'rules': [
						{
							'name': 'HostDown',
							'type': 'alerting',
							'health': 'err',
							'state': 'firing',
							'query': query,
							'duration': 15,
							'labels': {
								'severity': 'critical',
								'webhook': 'label-webhook-secret',
								'credential_id': 'label-credential-secret',
								'nested': {'value': 'label-nested-secret'},
							},
							'annotations': {'summary': 'annotation-secret'},
							'alerts': [{'labels': {'token': 'alert-secret'}}],
							'lastError': 'rule-last-error-secret',
							'evaluationTime': -2,
						},
						{
							'name': 'HostCount',
							'type': 'recording',
							'health': 'ok',
							'query': 'sum(up)',
							'duration': -1,
						},
					],
				}],
			},
		}

		payload = services.normalize_prometheus_rules(body)
		row = payload['rows'][0]
		serialized = json.dumps(payload)

		self.assertEqual(set(row), {
			'group', 'name', 'type', 'health', 'state', 'query', 'duration',
			'labels', 'last_evaluation', 'evaluation_time', 'active_alerts', 'has_error',
		})
		self.assertEqual(payload['summary'], {
			'total': 2,
			'alerting': 1,
			'recording': 1,
			'unhealthy': 1,
			'firing': 1,
			'pending': 0,
		})
		self.assertEqual(row['active_alerts'], 1)
		self.assertTrue(row['has_error'])
		self.assertEqual(row['duration'], 15.0)
		self.assertIsNone(row['evaluation_time'])
		self.assertLessEqual(len(row['query']), services.PROMETHEUS_RULE_QUERY_MAX_LENGTH)
		self.assertEqual(row['query'].count('<redacted>'), 3)
		self.assertIn('job="node"', row['query'])
		self.assertEqual(row['labels'], {'severity': 'critical'})
		self.assertIsNone(payload['rows'][1]['duration'])
		self.assertEqual(payload['rows'][1]['evaluation_time'], 0.4)
		for private_value in (
			'query-token-secret', 'query-password-secret', 'query-key-secret',
			'/private/rules/internal.yml', 'label-webhook-secret',
			'label-credential-secret', 'label-nested-secret', 'annotation-secret',
			'alert-secret', 'rule-last-error-secret',
		):
				self.assertNotIn(private_value, serialized)

	def test_metadata_filters_compact_sensitive_keys_and_credential_values(self):
		targets_payload = services.normalize_prometheus_targets({
			'data': {'activeTargets': [{
				'labels': {
					'clientSecret': 'client-secret-value',
					'apitoken': 'api-token-value',
					'accesskey': 'access-key-value',
					'endpoint': 'https://user:pass@private.example.test/metrics',
					'query_url': 'https://public.example.test/metrics?token=query-secret',
					'fragment_url': 'https://public.example.test/metrics#private-fragment',
					'parameter': 'token=parameter-secret',
					'instance': 'host-a:9090',
					'plain_url': 'https://public.example.test/metrics',
				},
			}]},
		})
		rules_payload = services.normalize_prometheus_rules({
			'data': {'groups': [{
				'name': 'security',
				'rules': [{
					'name': 'SafeRule',
					'type': 'alerting',
					'health': 'ok',
					'query': (
						'metric{clientsecret="matcher-key-secret", '
						'endpoint="https://user:pass@private.example.test/metrics", '
						'callback="https://public.example.test/path?token=matcher-query-secret", '
						'note="token=matcher-parameter-secret", instance="host-a:9090"}'
					),
					'labels': {
						'callback': 'https://user:pass@private.example.test/callback',
						'instance': 'host-a:9090',
					},
				}],
			}]},
		})

		target_labels = targets_payload['rows'][0]['labels']
		rule_row = rules_payload['rows'][0]
		serialized = json.dumps({'targets': targets_payload, 'rules': rules_payload})

		self.assertEqual(target_labels, {
			'instance': 'host-a:9090',
			'plain_url': 'https://public.example.test/metrics',
		})
		self.assertEqual(rule_row['labels'], {'instance': 'host-a:9090'})
		self.assertEqual(rule_row['query'].count('<redacted>'), 4)
		self.assertIn('instance="host-a:9090"', rule_row['query'])
		for private_value in (
			'client-secret-value', 'api-token-value', 'access-key-value',
			'query-secret', 'private-fragment', 'parameter-secret',
			'matcher-key-secret', 'matcher-query-secret', 'matcher-parameter-secret',
			'user:pass',
		):
			self.assertNotIn(private_value, serialized)

	def test_targets_and_rules_normalizers_cap_rows_and_preserve_totals(self):
		total = services.PROMETHEUS_TABLE_MAX_ROWS + 3
		targets = [
			{'labels': {'instance': 'host-%s' % index}, 'health': 'up'}
			for index in range(total)
		]
		rules = [
			{'name': 'rule-%s' % index, 'type': 'recording', 'health': 'ok'}
			for index in range(total)
		]

		targets_payload = services.normalize_prometheus_targets({
			'data': {'activeTargets': targets},
		})
		rules_payload = services.normalize_prometheus_rules({
			'data': {'groups': [{'name': 'group', 'rules': rules}]},
		})

		self.assertEqual(len(targets_payload['rows']), services.PROMETHEUS_TABLE_MAX_ROWS)
		self.assertEqual(targets_payload['total_rows'], total)
		self.assertEqual(targets_payload['summary']['up'], total)
		self.assertTrue(targets_payload['truncated'])
		self.assertEqual(len(rules_payload['rows']), services.PROMETHEUS_TABLE_MAX_ROWS)
		self.assertEqual(rules_payload['total_rows'], total)
		self.assertEqual(rules_payload['summary']['recording'], total)
		self.assertTrue(rules_payload['truncated'])

	def test_metadata_durations_distinguish_missing_values_from_real_zero(self):
		targets_payload = services.normalize_prometheus_targets({
			'data': {'activeTargets': [
				{'labels': {'instance': 'missing'}},
				{'labels': {'instance': 'zero'}, 'lastScrapeDuration': 0},
			]},
		})
		rules_payload = services.normalize_prometheus_rules({
			'data': {'groups': [{
				'name': 'durations',
				'rules': [
					{'name': 'missing', 'type': 'recording', 'health': 'ok'},
					{
						'name': 'zero',
						'type': 'recording',
						'health': 'ok',
						'duration': 0,
						'evaluationTime': 0,
					},
				],
			}]},
		})

		self.assertIsNone(targets_payload['rows'][0]['last_scrape_duration'])
		self.assertEqual(targets_payload['rows'][1]['last_scrape_duration'], 0.0)
		self.assertIsNone(rules_payload['rows'][0]['duration'])
		self.assertIsNone(rules_payload['rows'][0]['evaluation_time'])
		self.assertEqual(rules_payload['rows'][1]['duration'], 0.0)
		self.assertEqual(rules_payload['rows'][1]['evaluation_time'], 0.0)

	@mock.patch('monitor.services.urlrequest.urlopen')
	def test_query_maps_http_error_json_to_safe_invalid_promql_failure(self, urlopen):
		body = json.dumps({
			'status': 'error',
			'errorType': 'bad_data',
			'error': 'parse failure for internal_expression',
		}).encode('utf-8')
		urlopen.side_effect = services.urlerror.HTTPError(
			'http://prometheus.local:9090/api/v1/query',
			422,
			'Unprocessable Entity',
			{},
			io.BytesIO(body),
		)

		result = services.query_prometheus(self.prometheus_config(), 'internal_metric{scope="private"')

		self.assertEqual(result, {
			'ok': False,
			'message': services.PROMETHEUS_INVALID_QUERY_MESSAGE,
			'error_kind': 'invalid_query',
		})
		self.assertNotIn('parse failure', result['message'])
		self.assertNotIn('internal_metric', result['message'])

	@mock.patch('monitor.services.urlrequest.urlopen')
	def test_query_maps_non_json_http_500_to_safe_service_failure(self, urlopen):
		urlopen.side_effect = services.urlerror.HTTPError(
			'http://prometheus.local:9090/api/v1/query',
			500,
			'Internal Server Error',
			{},
			io.BytesIO(b'internal upstream detail'),
		)

		result = services.query_prometheus(self.prometheus_config(), 'up')

		self.assertEqual(result, {
			'ok': False,
			'message': 'Prometheus 服务暂时不可用，请稍后重试',
		})
		self.assertNotIn('internal upstream detail', result['message'])

	@mock.patch('monitor.services.prometheus_get_json')
	def test_query_rejects_malformed_success_response_shapes(self, prometheus_get_json):
		malformed_bodies = (
			None,
			[],
			{},
			{'status': 'success'},
			{'status': 'success', 'data': []},
			{'status': 'success', 'data': {'resultType': 'histogram', 'result': []}},
			{'status': 'success', 'data': {'resultType': 'vector', 'result': {}}},
			{'status': 'success', 'data': {'resultType': 'scalar', 'result': []}},
		)
		for body in malformed_bodies:
			with self.subTest(body=body):
				prometheus_get_json.return_value = {'ok': True, 'body': body}

				result = services.query_prometheus(self.prometheus_config(), 'up')

				self.assertEqual(result, {
					'ok': False,
					'message': services.PROMETHEUS_QUERY_FORMAT_MESSAGE,
				})

	@mock.patch('monitor.services.prometheus_get_json')
	def test_query_masks_untrusted_transport_failure_message(self, prometheus_get_json):
		prometheus_get_json.return_value = {
			'ok': False,
			'message': 'raw upstream error containing internal expression',
		}

		result = services.query_prometheus(self.prometheus_config(), 'internal_metric')

		self.assertEqual(result, {'ok': False, 'message': 'Prometheus 查询失败'})
		self.assertNotIn('raw upstream error', result['message'])

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
	@mock.patch('monitor.services.alertmanager_get_json')
	def test_query_alerts_uses_v2_endpoint_and_normalizes_safe_bounded_rows(self, alertmanager_get_json):
		config = AlertmanagerConfig(alertmanager_url='http://alertmanager.local:9093', enabled=True)
		alertmanager_get_json.return_value = {'ok': True, 'body': [{
			'status': {'state': 'firing'}, 'labels': {'alertname': 'DiskFull', 'apiToken': 'private'},
			'annotations': {'summary': 'Disk full', 'webhook': 'private'},
			'startsAt': '2025-01-01T00:00:00Z', 'updatedAt': 'bad-value', 'endsAt': '2025-01-02T00:00:00Z',
		}]}

		result = services.query_alertmanager_alerts(config)
		payload = services.normalize_alertmanager_alerts(result['body'])

		alertmanager_get_json.assert_called_once_with(config, '/api/v2/alerts')
		self.assertEqual(payload['rows'][0]['labels'], {'alertname': 'DiskFull'})
		self.assertEqual(payload['rows'][0]['annotations'], {'summary': 'Disk full'})
		self.assertEqual(payload['rows'][0]['updated_at'], '')
		self.assertNotIn('private', json.dumps(payload))
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


class MonitorPrometheusRulePageTests(TestCase):
	def setUp(self):
		self.user = User.objects.create(
			user='prometheus-rule-user',
			email='prometheus-rule@example.com',
			password='plain-password',
			confirm_pwd='plain-password',
		)
		session = self.client.session
		session['is_login'] = True
		session['user_id'] = self.user.id
		session['user_name'] = self.user.user
		session.save()
		self.cluster = K8sCluster.objects.create(
			name='monitor-cluster', api_server='https://k8s.example.test',
			default_namespace='monitoring', kubeconfig='apiVersion: v1\nclusters: []',
		)

	def set_cluster_permission(self, role):
		DevOpsRole.objects.update_or_create(user=self.user, defaults={'role': role})
		DevOpsModulePermission.objects.update_or_create(
			user=self.user,
			module=DevOpsModulePermission.MODULE_CLUSTER,
			defaults={'role': role},
		)

	def vue_data(self, response):
		return json.loads(response.context['vue_page_payload'])['data']

	def valid_yaml(self):
		return '''apiVersion: monitoring.coreos.com/v1
kind: PrometheusRule
metadata:
  name: api-errors
  namespace: monitoring
spec:
  groups: []
'''

	@mock.patch('monitor.views.list_prometheus_rules')
	def test_viewer_sees_selected_cluster_rule_summaries_without_create_form(self, list_rules):
		self.set_cluster_permission(DevOpsRole.ROLE_VIEWER)
		list_rules.return_value = {'ok': True, 'code': 'ok', 'rules': [{
			'namespace': 'monitoring', 'name': 'api-errors',
			'resource_version': '42', 'created_at': '2026-07-22T10:00:00Z',
		}]}

		response = self.client.get(reverse('monitor:monitor_index'), {'cluster': self.cluster.id})
		data = self.vue_data(response)

		self.assertEqual(response.status_code, 200)
		self.assertTrue(data['prometheus_rules']['configured'])
		self.assertEqual(data['prometheus_rules']['selected_cluster_name'], self.cluster.name)
		self.assertFalse(data['prometheus_rules']['can_create'])
		self.assertEqual(data['prometheus_rules']['rules'][0], {
			'namespace': 'monitoring', 'name': 'api-errors', 'resource_version': '42',
			'created_at': '2026-07-22T10:00:00Z',
			'detail_url': reverse('devops:prometheus_rule_detail', args=[self.cluster.id, 'monitoring', 'api-errors']),
		})
		list_rules.assert_called_once_with(self.cluster)

	def test_rule_management_page_payload_omits_legacy_threshold_fields(self):
		self.set_cluster_permission(DevOpsRole.ROLE_VIEWER)

		response = self.client.get(reverse('monitor:monitor_index'))
		data = self.vue_data(response)

		self.assertEqual(response.status_code, 200)
		self.assertEqual(data['subtitle'], '管理 Kubernetes 集群中的 PrometheusRule 规则摘要与双人复核草稿')
		self.assertNotIn('monitor', data)
		self.assertNotIn('errors', data)
		with open('static/js/ops-vue-pages.js', 'r') as handle:
			page_template = handle.read()
		for legacy_field in ('monitor_email', 'monitor_cpu', 'monitor_men', 'monitor_disk'):
			self.assertNotIn(legacy_field, page_template)

	def test_rule_management_static_template_uses_workbench_and_new_cache_marker(self):
		with open('static/js/ops-vue-pages.js', 'r') as handle:
			page_template = handle.read()
		with open('static/css/ops-vue-pages.css', 'r') as handle:
			page_styles = handle.read()
		with open('templates/vue/page.html', 'r') as handle:
			page_shell = handle.read()

		self.assertIn('ops-rule-workbench', page_template)
		self.assertIn('<section v-else-if="kind === \'monitor\'" class="ops-rule-workbench">', page_template)
		self.assertNotIn('class="ops-panel ops-rule-workbench"', page_template)
		self.assertIn('ops-rule-workbench__creator', page_template)
		self.assertIn("v-if=\"data.prometheus_rules.can_create && data.prometheus_rules.configured\"", page_template)
		self.assertIn('ops-rule-workbench__state is-denied', page_template)
		self.assertIn('.ops-rule-workbench', page_styles)
		self.assertIn('20260801-geist-control-plane-01', page_shell)
		self.assertIn('修订管理', page_template)
		self.assertIn('创建待复核草稿', page_template)
		self.assertIn('规则摘要不可用', page_template)
		self.assertIn('创建草稿失败', page_template)
		self.assertIn('data.prometheus_rules.create_error', page_template)
		self.assertNotIn('v-if="!data.prometheus_rules.error" class="ops-rule-workbench__layout"', page_template)

	@mock.patch('monitor.views.list_prometheus_rules')
	def test_admin_sees_create_form_and_user_without_cluster_permission_sees_no_rule_data(self, list_rules):
		self.set_cluster_permission(DevOpsRole.ROLE_ADMIN)

		admin_data = self.vue_data(self.client.get(reverse('monitor:monitor_index'), {'cluster': self.cluster.id}))

		self.assertTrue(admin_data['prometheus_rules']['can_create'])
		self.assertEqual(admin_data['prometheus_rules']['create_url'], '/monitor/prometheus-rules/create/')
		self.assertEqual(admin_data['prometheus_rules']['revision_list_url'], reverse('devops:prometheus_rule_revisions'))
		self.assertIn('yaml', admin_data['prometheus_rules']['form'])
		self.assertEqual(list_rules.call_count, 1)
		DevOpsRole.objects.filter(user=self.user).update(role=DevOpsRole.ROLE_VIEWER)
		DevOpsModulePermission.objects.update_or_create(
			user=self.user,
			module=DevOpsModulePermission.MODULE_CLUSTER,
			defaults={'role': DevOpsModulePermission.ROLE_NONE},
		)

		no_permission_data = self.vue_data(self.client.get(reverse('monitor:monitor_index'), {'cluster': self.cluster.id}))

		no_permission_rules = no_permission_data['prometheus_rules']
		self.assertTrue(no_permission_rules['permission_denied'])
		self.assertNotIn('selected_cluster_name', no_permission_rules)
		self.assertNotIn('clusters', no_permission_rules)
		self.assertNotIn('rules', no_permission_rules)
		self.assertNotIn('form', no_permission_rules)
		self.assertEqual(list_rules.call_count, 1)

	def test_create_requires_cluster_admin_and_post(self):
		self.set_cluster_permission(DevOpsRole.ROLE_VIEWER)

		response = self.client.post('/monitor/prometheus-rules/create/', {
			'cluster': self.cluster.id, 'yaml': self.valid_yaml(),
		})

		self.assertEqual(response.status_code, 403)
		self.assertNotContains(response, self.valid_yaml(), status_code=403)
		self.assertFalse(AuditLog.objects.filter(action='创建PrometheusRule草稿').exists())
		self.set_cluster_permission(DevOpsRole.ROLE_ADMIN)
		self.assertEqual(self.client.get('/monitor/prometheus-rules/create/').status_code, 405)

	@mock.patch('monitor.views.create_prometheus_rule_draft')
	def test_invalid_yaml_is_a_create_error_and_keeps_the_editor_available(self, create_draft):
		self.set_cluster_permission(DevOpsRole.ROLE_ADMIN)
		yaml_text = 'apiVersion: monitoring.coreos.com/v1\nkind: PrometheusRule\nmetadata: ['

		response = self.client.post('/monitor/prometheus-rules/create/', {
			'cluster': self.cluster.id, 'yaml': yaml_text,
		})
		rules_data = self.vue_data(response)['prometheus_rules']

		self.assertEqual(response.status_code, 400)
		self.assertEqual(rules_data['error'], '')
		self.assertEqual(rules_data['create_error'], '规则 YAML 格式或资源身份无效。')
		self.assertTrue(rules_data['configured'])
		self.assertTrue(rules_data['can_create'])
		self.assertEqual(rules_data['form']['yaml'], yaml_text)
		create_draft.assert_not_called()

	@mock.patch('monitor.views.create_prometheus_rule_draft')
	def test_successful_create_creates_draft_audits_safe_identity_and_redirects(self, create_draft):
		self.set_cluster_permission(DevOpsRole.ROLE_ADMIN)
		create_draft.return_value = {'ok': True, 'code': 'ok', 'revision': {
			'id': 17, 'status': 'draft', 'cluster_id': self.cluster.id,
			'name': 'api-errors', 'namespace': 'monitoring',
		}}

		response = self.client.post('/monitor/prometheus-rules/create/', {
			'cluster': self.cluster.id, 'yaml': self.valid_yaml(),
		})

		self.assertEqual(response.status_code, 302)
		self.assertEqual(response.url, '%s?cluster=%s&draft=created' % (reverse('monitor:monitor_index'), self.cluster.id))
		create_draft.assert_called_once()
		call_args, call_kwargs = create_draft.call_args
		self.assertEqual(call_args[1], self.cluster)
		self.assertEqual(call_args[2], self.valid_yaml().strip())
		self.assertEqual(call_kwargs, {'action': 'create'})
		audit_log = AuditLog.objects.get(action='创建PrometheusRule草稿')
		self.assertEqual(audit_log.target_type, 'K8sCluster')
		self.assertEqual(audit_log.target_id, str(self.cluster.id))
		self.assertEqual(audit_log.detail, 'cluster=%s, namespace=monitoring, name=api-errors, action=create, outcome=draft' % self.cluster.id)
		self.assertNotIn('spec:', audit_log.detail)

	@mock.patch('monitor.views.create_prometheus_rule_draft')
	def test_draft_creation_failures_keep_admin_yaml_and_write_safe_audits(self, create_draft):
		self.set_cluster_permission(DevOpsRole.ROLE_ADMIN)
		yaml_text = self.valid_yaml().strip()
		with open('static/js/ops-vue-pages.js', 'r') as handle:
			self.assertIn('monitor-prometheus-rule-yaml', handle.read())
		for result, status, message, outcome in (
			({'ok': False, 'code': 'invalid_yaml', 'message': 'raw yaml parser detail'}, 400,
				'规则 YAML 格式或资源身份无效。', 'invalid_yaml'),
			({'ok': False, 'code': 'validation_error', 'message': 'raw revision validation detail'}, 400,
				'规则 YAML 格式或资源身份无效。', 'validation_error'),
			({'ok': False, 'code': 'offline', 'message': 'raw token=secret'}, 503,
				'无法连接 Kubernetes 集群，请确认集群状态后重试。', 'offline'),
			({'ok': False, 'code': 'untrusted_code', 'message': 'raw kubeconfig marker'}, 503,
				'无法操作 PrometheusRule，请稍后重试。', 'offline'),
		):
			create_draft.return_value = result
			response = self.client.post('/monitor/prometheus-rules/create/', {
				'cluster': self.cluster.id, 'yaml': yaml_text,
			})
			data = self.vue_data(response)
			rules_data = data['prometheus_rules']

			self.assertEqual(response.status_code, status)
			self.assertEqual(rules_data['selected_cluster_id'], self.cluster.id)
			self.assertTrue(rules_data['configured'])
			self.assertTrue(rules_data['can_create'])
			self.assertEqual(rules_data['form']['yaml'], yaml_text)
			self.assertEqual(rules_data['create_error'], message)
			self.assertEqual(rules_data['error'], '')
			self.assertNotContains(response, result['message'], status_code=status)
			audit_log = AuditLog.objects.filter(
				action='创建PrometheusRule草稿', target_id=str(self.cluster.id),
			).order_by('id').last()
			self.assertEqual(
				audit_log.detail,
				'cluster=%s, namespace=monitoring, name=api-errors, action=create, outcome=%s' % (
					self.cluster.id, outcome,
				),
			)
			self.assertNotIn(yaml_text, audit_log.detail)
			self.assertNotIn(result['message'], audit_log.detail)
		self.assertEqual(AuditLog.objects.filter(action='创建PrometheusRule草稿').count(), 4)

	@mock.patch('monitor.views.list_prometheus_rules')
	def test_rule_summary_failure_keeps_authorized_creator_available(self, list_rules):
		self.set_cluster_permission(DevOpsRole.ROLE_ADMIN)
		list_rules.return_value = {
			'ok': False, 'code': 'offline', 'message': 'raw cluster endpoint detail',
		}

		response = self.client.get(reverse('monitor:monitor_index'), {'cluster': self.cluster.id})
		rules_data = self.vue_data(response)['prometheus_rules']

		self.assertEqual(response.status_code, 200)
		self.assertEqual(rules_data['error'], '无法连接 Kubernetes 集群，请确认集群状态后重试。')
		self.assertEqual(rules_data['create_error'], '')
		self.assertTrue(rules_data['configured'])
		self.assertTrue(rules_data['can_create'])
		self.assertIn('yaml', rules_data['form'])
		self.assertNotContains(response, 'raw cluster endpoint detail')

	@mock.patch('monitor.views.list_prometheus_rules')
	def test_created_draft_notice_never_claims_rule_was_published(self, list_rules):
		self.set_cluster_permission(DevOpsRole.ROLE_ADMIN)
		list_rules.return_value = {'ok': True, 'code': 'ok', 'rules': []}

		response = self.client.get(reverse('monitor:monitor_index'), {
			'cluster': self.cluster.id, 'draft': 'created',
		})

		data = self.vue_data(response)
		self.assertEqual(
			data['prometheus_rules']['notice'],
			'PrometheusRule 草稿已创建，正等待另一名集群管理员复核后发布。',
		)
		self.assertNotIn('已发布', data['prometheus_rules']['notice'])
