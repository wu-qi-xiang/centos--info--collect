import json
from datetime import timedelta

from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from RemoteLinux.models import User
from .models import (
    DevOpsModulePermission,
    DevOpsRole,
    NotificationChannel,
    NotificationLog,
    ScheduledTaskRun,
)


class PlatformReliabilityApiTests(TestCase):
    def setUp(self):
        self.user = User.objects.create(
            user='reliability-admin', email='reliability@example.com',
            password='plain-password', confirm_pwd='plain-password',
        )
        DevOpsRole.objects.create(user=self.user, role=DevOpsRole.ROLE_ADMIN)
        DevOpsModulePermission.objects.create(
            user=self.user, module=DevOpsModulePermission.MODULE_SECURITY,
            role=DevOpsRole.ROLE_ADMIN,
        )
        session = self.client.session
        session.update({'is_login': True, 'user_id': self.user.id, 'user_name': self.user.user})
        session.save()

    def url(self):
        return reverse('devops:api_platform_reliability')

    def test_requires_login_and_security_admin(self):
        session = self.client.session
        session.clear()
        session.save()
        response = self.client.get(self.url())
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json()['code'], 'unauthorized')

        session = self.client.session
        session.update({'is_login': True, 'user_id': self.user.id, 'user_name': self.user.user})
        session.save()
        DevOpsRole.objects.filter(user=self.user).update(role=DevOpsRole.ROLE_VIEWER)
        DevOpsModulePermission.objects.filter(user=self.user).update(role=DevOpsRole.ROLE_VIEWER)
        response = self.client.get(self.url())
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.json()['code'], 'forbidden')

    def test_no_records_are_reported_as_absent(self):
        response = self.client.get(self.url())
        self.assertEqual(response.status_code, 200)
        payload = response.json()['reliability']
        self.assertTrue(payload['scheduler'])
        self.assertTrue(all(item['freshness'] == 'absent' for item in payload['scheduler']))
        self.assertEqual(payload['notifications'], [])

    def test_failed_and_stale_records_include_only_safe_fields(self):
        old = timezone.now() - timedelta(hours=3)
        ScheduledTaskRun.objects.create(
            task_name='monitor', status=ScheduledTaskRun.STATUS_FAILED,
            last_summary='failed: private command https://secret.example/token',
            last_finished_at=old, next_run_at=old,
        )
        channel = NotificationChannel.objects.create(
            name='private channel', channel_type=NotificationChannel.TYPE_WECOM,
            webhook_url='https://secret.example/webhook', secret='private-secret',
        )
        log = NotificationLog.objects.create(
            channel=channel, event_type=NotificationLog.EVENT_ALERT,
            title='private title', content='private body', response='https://private.example',
            status=NotificationLog.STATUS_FAILED,
        )
        NotificationLog.objects.filter(pk=log.pk).update(created_at=old)

        response = self.client.get(self.url())
        self.assertEqual(response.status_code, 200)
        payload = response.json()['reliability']
        task = next(item for item in payload['scheduler'] if item['task_name'] == 'monitor')
        self.assertEqual(task['freshness'], 'failed')
        notification = payload['notifications'][0]
        self.assertEqual(notification['channel_type'], NotificationChannel.TYPE_WECOM)
        self.assertEqual(notification['freshness'], 'failed')
        self.assertNotIn('private-secret', json.dumps(payload))
        self.assertNotIn('private body', json.dumps(payload))
        self.assertNotIn('https://secret.example', json.dumps(payload))
        self.assertNotIn('private channel', json.dumps(payload))
