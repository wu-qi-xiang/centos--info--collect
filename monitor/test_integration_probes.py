from types import SimpleNamespace
from unittest import mock
from urllib import error as urlerror

from django.test import TestCase

from .services import probe_monitor_integrations, probe_wecom_notification_transport


class IntegrationProbeTests(TestCase):
    @mock.patch('monitor.services.test_alertmanager_connection')
    @mock.patch('monitor.services.test_prometheus_connection')
    def test_monitor_probe_returns_fixed_safe_categories(self, prometheus, alertmanager):
        from .models import AlertmanagerConfig, PrometheusConfig
        PrometheusConfig.objects.create(name='metrics', prometheus_url='https://metrics.example')
        AlertmanagerConfig.objects.create(name='alerts', alertmanager_url='https://alerts.example')
        prometheus.return_value = {'ok': True, 'message': 'Prometheus 连接正常'}
        alertmanager.return_value = {'ok': False, 'message': 'Alertmanager 请求超时，请检查地址和网络'}

        result = probe_monitor_integrations()

        self.assertEqual(result['prometheus'][0]['category'], 'ok')
        self.assertEqual(result['alertmanager'][0]['category'], 'timeout')
        self.assertNotIn('https://', repr(result))

    @mock.patch('monitor.services.urlrequest.urlopen')
    def test_wecom_probe_uses_head_and_treats_405_as_transport_success(self, urlopen):
        config = SimpleNamespace(
            id=7, name='operations-bot',
            decrypted_webhook_url='https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=private',
        )
        urlopen.side_effect = urlerror.HTTPError(config.decrypted_webhook_url, 405, 'Method Not Allowed', {}, None)

        result = probe_wecom_notification_transport(config)

        self.assertTrue(result['ok'])
        self.assertEqual(result['category'], 'ok')
        self.assertEqual(urlopen.call_args[0][0].method, 'HEAD')

