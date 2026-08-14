import json
from unittest import mock

from django.test import TestCase
from django.urls import reverse

from RemoteLinux.models import User
from monitor.models import AlertNotificationConfig
from .models import (
    DevOpsModulePermission,
    DevOpsRole,
    IntegrationHealthEvent,
)
from .services import probe_configured_integrations


class IntegrationHealthProbeTests(TestCase):
    def test_orchestration_records_only_safe_events(self):
        with mock.patch('monitor.services.probe_monitor_integrations', return_value={
            'prometheus': [{'source_id': 1, 'source_name': 'metrics', 'ok': True, 'category': 'ok'}],
            'alertmanager': [{'source_id': 2, 'source_name': 'alerts', 'ok': False, 'category': 'timeout'}],
            'wecom': [{'source_id': 3, 'source_name': 'monitor-bot', 'ok': True, 'category': 'ok'}],
        }):
            result = probe_configured_integrations()

        self.assertEqual(result, {'checked': 3, 'success': 2, 'failed': 1, 'skipped': 0})
        self.assertEqual(IntegrationHealthEvent.objects.count(), 3)
        self.assertNotIn('private', json.dumps(list(IntegrationHealthEvent.objects.values()), default=str))

    def test_health_api_exposes_safe_monitor_notification_section(self):
        user = User.objects.create(user='integration-admin', email='integration@example.com', password='pwd', confirm_pwd='pwd')
        DevOpsRole.objects.create(user=user, role=DevOpsRole.ROLE_ADMIN)
        DevOpsModulePermission.objects.create(
            user=user, module=DevOpsModulePermission.MODULE_SECURITY, role=DevOpsRole.ROLE_ADMIN,
        )
        AlertNotificationConfig.objects.create(
            name='monitor-bot', provider=AlertNotificationConfig.PROVIDER_WECOM,
            webhook_url='https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=private', enabled=True,
        )
        IntegrationHealthEvent.objects.create(
            integration_type=IntegrationHealthEvent.TYPE_NOTIFICATION,
            source_id=1, source_name='monitor-monitor-bot',
            status=IntegrationHealthEvent.STATUS_SUCCESS,
            category=IntegrationHealthEvent.CATEGORY_OK,
        )
        session = self.client.session
        session.update({'is_login': True, 'user_id': user.id, 'user_name': user.user})
        session.save()

        response = self.client.get(reverse('devops:api_integration_health'))

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()['monitor_notifications'][0]['current_status'], 'success')
        self.assertNotIn('webhook', json.dumps(response.json()).lower())
        self.assertNotIn('private', json.dumps(response.json()).lower())
