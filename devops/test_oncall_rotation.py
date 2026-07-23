from datetime import datetime, timezone as datetime_timezone
try:
    from unittest import mock
except ImportError:
    import mock

from django.test import TestCase

from RemoteLinux.models import NewLinux, User
from .models import (
    AlertEvent,
    NotificationChannel,
    NotificationLog,
    ServiceCatalog,
    ServiceOnCallPolicy,
    ServiceOnCallRotationMember,
)
from .services import notify_alert, resolve_oncall_primary_route


class ServiceOnCallRotationTests(TestCase):
    def setUp(self):
        self.static_user = self.create_user('static')
        self.backup_user = self.create_user('backup')
        self.static_channel = self.create_channel('static')
        self.backup_channel = self.create_channel('backup')
        self.service = ServiceCatalog.objects.create(name='rotation-api')
        self.policy = ServiceOnCallPolicy.objects.create(
            service=self.service,
            primary_user=self.static_user,
            primary_channel=self.static_channel,
            backup_user=self.backup_user,
            backup_channel=self.backup_channel,
        )
        self.members = []
        for position, name in enumerate(('alpha', 'bravo', 'charlie'), start=1):
            member = ServiceOnCallRotationMember.objects.create(
                policy=self.policy,
                user=self.create_user(name),
                channel=self.create_channel(name),
                position=position,
            )
            self.members.append(member)

    def create_user(self, name):
        return User.objects.create(
            user='rotation-%s' % name,
            email='%s@example.com' % name,
            password='plain', confirm_pwd='plain',
        )

    def create_channel(self, name):
        return NotificationChannel.objects.create(
            name='rotation-%s' % name,
            channel_type=NotificationChannel.TYPE_WEBHOOK,
            webhook_url='https://example.invalid/%s' % name,
            notify_alert=False,
        )

    def test_rotation_uses_shanghai_monday_boundary_for_aware_utc_datetimes(self):
        pre_boundary = datetime(2023, 12, 31, 15, 59, 59, tzinfo=datetime_timezone.utc)
        boundary = datetime(2023, 12, 31, 16, 0, 0, tzinfo=datetime_timezone.utc)
        next_week = datetime(2024, 1, 7, 16, 0, 0, tzinfo=datetime_timezone.utc)
        third_week = datetime(2024, 1, 14, 16, 0, 0, tzinfo=datetime_timezone.utc)

        self.assertEqual(resolve_oncall_primary_route(self.policy, pre_boundary)['member'], self.members[2])
        self.assertEqual(resolve_oncall_primary_route(self.policy, boundary)['member'], self.members[0])
        self.assertEqual(resolve_oncall_primary_route(self.policy, next_week)['member'], self.members[1])
        self.assertEqual(resolve_oncall_primary_route(self.policy, third_week)['member'], self.members[2])

    def test_no_enabled_valid_member_preserves_static_primary_route(self):
        for member in self.members:
            member.enabled = False
            member.save(update_fields=['enabled'])

        route = resolve_oncall_primary_route(
            self.policy, datetime(2024, 1, 1, tzinfo=datetime_timezone.utc),
        )

        self.assertIsNone(route['member'])
        self.assertEqual(route['user'], self.static_user)
        self.assertEqual(route['channel'], self.static_channel)

    def test_disabled_rotation_channel_is_skipped(self):
        self.members[0].channel.enabled = False
        self.members[0].channel.save(update_fields=['enabled'])

        route = resolve_oncall_primary_route(
            self.policy, datetime(2023, 12, 31, 16, 0, 0, tzinfo=datetime_timezone.utc),
        )

        self.assertEqual(route['member'], self.members[1])
        self.assertEqual(route['channel'], self.members[1].channel)

    def test_new_alert_uses_rotation_primary_channel_without_changing_backup_policy(self):
        host = NewLinux.objects.create(
            linux_name='rotation-host', linux_ip='192.0.2.41', linux_port='22',
            linux_user='ops', linux_passwd='not-used',
        )
        self.service.hosts.add(host)
        alert = AlertEvent.objects.create(host=host, metric='cpu', message='cpu high')
        boundary = datetime(2023, 12, 31, 16, 0, 0, tzinfo=datetime_timezone.utc)
        success = mock.Mock(status=NotificationLog.STATUS_SUCCESS, failure_category='')

        with mock.patch('devops.services.timezone.now', return_value=boundary), \
                mock.patch('devops.services.send_notification_channel', return_value=success) as sender:
            notify_alert(alert)

        sender.assert_called_once()
        self.assertEqual(sender.call_args[0][0], self.members[0].channel)
        self.policy.refresh_from_db()
        self.assertEqual(self.policy.backup_user, self.backup_user)
        self.assertEqual(self.policy.backup_channel, self.backup_channel)

    def test_empty_rotation_still_uses_fixed_primary_without_global_notifications(self):
        ServiceOnCallRotationMember.objects.filter(policy=self.policy).delete()
        host = NewLinux.objects.create(
            linux_name='static-rotation-host', linux_ip='192.0.2.42', linux_port='22',
            linux_user='ops', linux_passwd='not-used',
        )
        self.service.hosts.add(host)
        alert = AlertEvent.objects.create(host=host, metric='memory', message='memory high')
        success = mock.Mock(status=NotificationLog.STATUS_SUCCESS, failure_category='')

        with mock.patch('devops.services.send_notification_channel', return_value=success) as sender, \
                mock.patch('devops.services.send_notifications') as global_sender:
            notify_alert(alert)

        sender.assert_called_once()
        self.assertEqual(sender.call_args[0][0], self.static_channel)
        global_sender.assert_not_called()
