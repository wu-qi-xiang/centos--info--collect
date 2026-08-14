from datetime import timedelta
from unittest import mock

from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from RemoteLinux.models import User
from .models import (
    DevOpsModulePermission,
    DevOpsRole,
    IntegrationHealthEscalationPolicy,
    IntegrationHealthEvent,
    NotificationChannel,
    NotificationLog,
)
from .services import process_integration_health_escalations


class IntegrationHealthEscalationTests(TestCase):
    def setUp(self):
        self.channel = NotificationChannel.objects.create(
            name='health-channel', channel_type=NotificationChannel.TYPE_WECOM,
            webhook_url='https://example.test/wecom', enabled=True,
        )
        self.policy = IntegrationHealthEscalationPolicy.objects.create(
            enabled=True, consecutive_failures=2, cooldown_minutes=60,
            notify_recovery=True, channel=self.channel,
        )

    @mock.patch('devops.services.send_notification_channel')
    def test_failure_threshold_and_cooldown_are_bounded(self, send):
        def persist(*args, **kwargs):
            return NotificationLog.objects.create(
                channel=self.channel, event_type=args[1], title=args[2], content=args[3],
                status=NotificationLog.STATUS_SUCCESS,
            )
        send.side_effect = persist
        now = timezone.now()
        for index in range(2):
            IntegrationHealthEvent.objects.create(
                integration_type=IntegrationHealthEvent.TYPE_PROMETHEUS,
                source_id=1, source_name='metrics', status=IntegrationHealthEvent.STATUS_FAILED,
                category=IntegrationHealthEvent.CATEGORY_TIMEOUT,
                occurred_at=now + timedelta(seconds=index),
            )
        first = process_integration_health_escalations(now=now + timedelta(minutes=2))
        second = process_integration_health_escalations(now=now + timedelta(minutes=3))
        self.assertEqual(first['notified'], 1)
        self.assertEqual(second['skipped'], 1)
        self.assertEqual(send.call_count, 1)
        title, content = send.call_args[0][2:4]
        self.assertNotIn('https://', title + content)

    @mock.patch('devops.services.send_notification_channel')
    def test_recovery_is_not_repeated(self, send):
        def persist(*args, **kwargs):
            return NotificationLog.objects.create(
                channel=self.channel, event_type=args[1], title=args[2], content=args[3],
                status=NotificationLog.STATUS_SUCCESS,
            )
        send.side_effect = persist
        now = timezone.now()
        IntegrationHealthEvent.objects.create(
            integration_type=IntegrationHealthEvent.TYPE_ALERTMANAGER,
            source_id=2, source_name='alerts', status=IntegrationHealthEvent.STATUS_SUCCESS,
            category=IntegrationHealthEvent.CATEGORY_OK, occurred_at=now,
        )
        self.assertEqual(process_integration_health_escalations(now=now)['recovered'], 1)
        self.assertEqual(process_integration_health_escalations(now=now + timedelta(minutes=1))['recovered'], 0)

    def test_policy_api_requires_security_admin(self):
        user = User.objects.create(user='policy-admin', email='policy@example.com', password='pwd', confirm_pwd='pwd')
        DevOpsRole.objects.create(user=user, role=DevOpsRole.ROLE_ADMIN)
        DevOpsModulePermission.objects.create(user=user, module=DevOpsModulePermission.MODULE_SECURITY, role=DevOpsRole.ROLE_ADMIN)
        session = self.client.session
        session.update({'is_login': True, 'user_id': user.id, 'user_name': user.user})
        session.save()
        response = self.client.post(
            reverse('devops:api_integration_health_policy'),
            data='{"enabled":true,"channel_id":%s,"consecutive_failures":2,"cooldown_minutes":30,"notify_recovery":true}' % self.channel.id,
            content_type='application/json',
        )
        self.assertEqual(response.status_code, 200)
        self.policy.refresh_from_db()
        self.assertTrue(self.policy.enabled)
        self.assertEqual(self.policy.cooldown_minutes, 30)
