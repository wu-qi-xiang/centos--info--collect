from datetime import timedelta
try:
    from unittest import mock
except ImportError:
    import mock

from django.test import TestCase
from django.utils import timezone

from RemoteLinux.models import NewLinux, User
from .models import (
    AlertEvent,
    AlertSilence,
    AlertOnCallEscalation,
    NotificationChannel,
    NotificationLog,
    ServiceCatalog,
    ServiceOnCallPolicy,
)
from .services import notify_alert, process_due_oncall_escalations, record_alert, update_alert_status


class ServiceOnCallEscalationTests(TestCase):
    def setUp(self):
        self.host = NewLinux.objects.create(
            linux_name='oncall-host', linux_ip='192.0.2.11', linux_port='22',
            linux_user='ops', linux_passwd='not-used',
        )
        self.primary_user = User.objects.create(
            user='primary-oncall', email='primary@example.com', password='plain', confirm_pwd='plain',
        )
        self.backup_user = User.objects.create(
            user='backup-oncall', email='backup@example.com', password='plain', confirm_pwd='plain',
        )
        self.primary_channel = NotificationChannel.objects.create(
            name='primary-channel', channel_type=NotificationChannel.TYPE_WEBHOOK,
            webhook_url='https://example.invalid/primary', notify_alert=False,
        )
        self.backup_channel = NotificationChannel.objects.create(
            name='backup-channel', channel_type=NotificationChannel.TYPE_WEBHOOK,
            webhook_url='https://example.invalid/backup', notify_alert=False,
        )
        self.global_channel = NotificationChannel.objects.create(
            name='global-channel', channel_type=NotificationChannel.TYPE_WEBHOOK,
            webhook_url='https://example.invalid/global', notify_alert=True,
        )
        self.service = ServiceCatalog.objects.create(name='orders-oncall')
        self.service.hosts.add(self.host)
        self.policy = ServiceOnCallPolicy.objects.create(
            service=self.service,
            primary_user=self.primary_user,
            primary_channel=self.primary_channel,
            backup_user=self.backup_user,
            backup_channel=self.backup_channel,
        )

    def _alert(self, status=AlertEvent.STATUS_OPEN):
        return AlertEvent.objects.create(
            host=self.host, metric='cpu', message='cpu high', status=status,
        )

    def _success_log(self):
        return mock.Mock(status=NotificationLog.STATUS_SUCCESS, failure_category='')

    def test_matched_service_alert_routes_only_to_primary_and_creates_escalation(self):
        alert = self._alert()
        with mock.patch('devops.services.send_notification_channel', return_value=self._success_log()) as sender, \
                mock.patch('devops.services.send_notifications') as global_sender:
            logs = notify_alert(alert)

        self.assertEqual(len(logs), 1)
        sender.assert_called_once()
        self.assertEqual(sender.call_args[0][0], self.primary_channel)
        global_sender.assert_not_called()
        escalation = AlertOnCallEscalation.objects.get(alert=alert, service=self.service)
        self.assertEqual(escalation.status, AlertOnCallEscalation.STATUS_ACTIVE)
        self.assertEqual(escalation.policy_id, self.policy.id)
        self.assertIsNotNone(escalation.primary_notified_at)

    def test_unmatched_alert_keeps_existing_global_route(self):
        other_host = NewLinux.objects.create(
            linux_name='unmatched', linux_ip='192.0.2.12', linux_port='22',
            linux_user='ops', linux_passwd='not-used',
        )
        alert = AlertEvent.objects.create(host=other_host, metric='cpu', message='cpu high')
        with mock.patch('devops.services.send_notifications', return_value=[]) as global_sender, \
                mock.patch('devops.services.send_notification_channel') as sender, \
                mock.patch('monitor.services.send_alert_event_notifications'):
            notify_alert(alert)

        global_sender.assert_called_once()
        sender.assert_not_called()
        self.assertFalse(AlertOnCallEscalation.objects.filter(alert=alert).exists())

    def test_due_open_alert_escalates_once_to_backup(self):
        alert = self._alert()
        now = timezone.now()
        with mock.patch('devops.services.send_notification_channel', return_value=self._success_log()):
            notify_alert(alert)
        escalation = AlertOnCallEscalation.objects.get(alert=alert)
        escalation.primary_notified_at = now - timedelta(minutes=15)
        escalation.save(update_fields=['primary_notified_at'])

        with mock.patch('devops.services.send_notification_channel', return_value=self._success_log()) as sender:
            first = process_due_oncall_escalations(now=now)
            second = process_due_oncall_escalations(now=now + timedelta(minutes=1))

        self.assertEqual(first, {'scanned': 1, 'escalated': 1, 'cancelled': 0, 'errors': 0})
        self.assertEqual(second, {'scanned': 0, 'escalated': 0, 'cancelled': 0, 'errors': 0})
        sender.assert_called_once()
        self.assertEqual(sender.call_args[0][0], self.backup_channel)
        escalation.refresh_from_db()
        self.assertEqual(escalation.status, AlertOnCallEscalation.STATUS_ESCALATED)
        self.assertIsNotNone(escalation.backup_claimed_at)
        self.assertIsNotNone(escalation.backup_notified_at)

    def test_processing_acknowledges_and_prevents_backup_escalation(self):
        alert = self._alert()
        with mock.patch('devops.services.send_notification_channel', return_value=self._success_log()):
            notify_alert(alert)
        update_alert_status(alert, AlertEvent.STATUS_PROCESSING, handler='operator')

        escalation = AlertOnCallEscalation.objects.get(alert=alert)
        self.assertEqual(escalation.status, AlertOnCallEscalation.STATUS_ACKNOWLEDGED)
        self.assertIsNotNone(escalation.acknowledged_at)
        with mock.patch('devops.services.send_notification_channel') as sender:
            result = process_due_oncall_escalations(now=timezone.now() + timedelta(minutes=16))
        self.assertEqual(result['escalated'], 0)
        sender.assert_not_called()

    def test_terminal_alert_states_cancel_active_escalation(self):
        for status in (
                AlertEvent.STATUS_SILENCED,
                AlertEvent.STATUS_RESOLVED,
                AlertEvent.STATUS_CLOSED,
        ):
            with self.subTest(status=status):
                alert = self._alert()
                with mock.patch('devops.services.send_notification_channel', return_value=self._success_log()):
                    notify_alert(alert)
                update_alert_status(alert, status)
                escalation = AlertOnCallEscalation.objects.get(alert=alert)
                self.assertEqual(escalation.status, AlertOnCallEscalation.STATUS_CANCELLED)
                self.assertIsNotNone(escalation.cancelled_at)

    def test_silence_match_cancels_an_existing_active_escalation(self):
        with mock.patch('devops.services.notify_alert'):
            alert, created = record_alert(self.host, 'memory', 'memory high')
        self.assertTrue(created)
        with mock.patch('devops.services.send_notification_channel', return_value=self._success_log()):
            notify_alert(alert)
        now = timezone.now()
        AlertSilence.objects.create(
            host=self.host,
            metric='memory',
            reason='maintenance',
            starts_at=now - timedelta(minutes=1),
            ends_at=now + timedelta(minutes=30),
        )
        with mock.patch('devops.services.notify_alert'):
            record_alert(self.host, 'memory', 'memory high again')

        escalation = AlertOnCallEscalation.objects.get(alert=alert)
        self.assertEqual(escalation.status, AlertOnCallEscalation.STATUS_CANCELLED)
