from django.test import TestCase

from RemoteLinux.models import User
from .models import (
    NotificationChannel,
    ServiceCatalog,
    ServiceOnCallPolicy,
    ServiceOnCallRotationMember,
)
from .services import inspect_oncall_coverage


class OnCallCoverageInspectionTests(TestCase):
    def setUp(self):
        self.primary_user = self.create_user('primary')
        self.backup_user = self.create_user('backup')
        self.primary_channel = self.create_channel('primary')
        self.backup_channel = self.create_channel('backup')

    def create_user(self, name):
        return User.objects.create(
            user='coverage-%s' % name,
            email='%s@example.com' % name,
            password='plain', confirm_pwd='plain',
        )

    def create_channel(self, name, enabled=True):
        return NotificationChannel.objects.create(
            name='coverage-%s' % name,
            channel_type=NotificationChannel.TYPE_WEBHOOK,
            webhook_url='https://secret.example/%s' % name,
            secret='coverage-secret-%s' % name,
            enabled=enabled,
            notify_alert=False,
        )

    def create_policy(self, service, **overrides):
        values = {
            'service': service,
            'primary_user': self.primary_user,
            'primary_channel': self.primary_channel,
            'backup_user': self.backup_user,
            'backup_channel': self.backup_channel,
        }
        values.update(overrides)
        return ServiceOnCallPolicy.objects.create(**values)

    def inspection_by_service(self):
        return {item['service_name']: item for item in inspect_oncall_coverage()}

    def issue_codes(self, service_name):
        return [item['code'] for item in self.inspection_by_service()[service_name]['issues']]

    def test_missing_and_disabled_policy_are_risks(self):
        missing = ServiceCatalog.objects.create(name='coverage-missing')
        disabled = ServiceCatalog.objects.create(name='coverage-disabled')
        self.create_policy(disabled, enabled=False)

        results = self.inspection_by_service()

        self.assertEqual(results[missing.name]['status'], 'risk')
        self.assertEqual(self.issue_codes(missing.name), ['missing_policy'])
        self.assertEqual(results[disabled.name]['status'], 'risk')
        self.assertEqual(self.issue_codes(disabled.name), ['policy_disabled'])

    def test_disabled_primary_and_backup_channels_are_risks(self):
        service = ServiceCatalog.objects.create(name='coverage-disabled-channels')
        primary = self.create_channel('disabled-primary', enabled=False)
        backup = self.create_channel('disabled-backup', enabled=False)
        self.create_policy(service, primary_channel=primary, backup_channel=backup)

        self.assertEqual(
            self.issue_codes(service.name),
            ['primary_channel_disabled', 'backup_channel_disabled'],
        )

    def test_empty_roster_is_healthy_static_primary_fallback(self):
        service = ServiceCatalog.objects.create(name='coverage-static-fallback')
        self.create_policy(service)

        result = self.inspection_by_service()[service.name]

        self.assertEqual(result['status'], 'healthy')
        self.assertEqual(result['issues'], [])

    def test_nonempty_roster_without_enabled_usable_member_is_a_risk(self):
        service = ServiceCatalog.objects.create(name='coverage-unusable-roster')
        policy = self.create_policy(service)
        ServiceOnCallRotationMember.objects.create(
            policy=policy,
            user=self.create_user('disabled-member'),
            channel=self.create_channel('disabled-member', enabled=False),
            position=1,
            enabled=True,
        )

        self.assertEqual(self.issue_codes(service.name), ['rotation_unavailable'])

    def test_non_contiguous_enabled_rotation_positions_are_a_risk(self):
        service = ServiceCatalog.objects.create(name='coverage-position-gap')
        policy = self.create_policy(service)
        ServiceOnCallRotationMember.objects.create(
            policy=policy,
            user=self.create_user('one'), channel=self.create_channel('one'), position=1,
        )
        ServiceOnCallRotationMember.objects.create(
            policy=policy,
            user=self.create_user('three'), channel=self.create_channel('three'), position=3,
        )

        self.assertEqual(self.issue_codes(service.name), ['rotation_positions_non_contiguous'])

    def test_healthy_rotation_and_output_are_safe_and_read_only(self):
        service = ServiceCatalog.objects.create(name='coverage-healthy')
        policy = self.create_policy(service)
        ServiceOnCallRotationMember.objects.create(
            policy=policy,
            user=self.create_user('first'), channel=self.create_channel('first'), position=1,
        )
        ServiceOnCallRotationMember.objects.create(
            policy=policy,
            user=self.create_user('second'), channel=self.create_channel('second'), position=2,
        )
        before = {
            'services': ServiceCatalog.objects.count(),
            'policies': ServiceOnCallPolicy.objects.count(),
            'members': ServiceOnCallRotationMember.objects.count(),
            'channels': NotificationChannel.objects.count(),
        }

        result = self.inspection_by_service()[service.name]

        self.assertEqual(result, {
            'service_id': service.id,
            'service_name': service.name,
            'status': 'healthy',
            'issues': [],
        })
        self.assertEqual(before, {
            'services': ServiceCatalog.objects.count(),
            'policies': ServiceOnCallPolicy.objects.count(),
            'members': ServiceOnCallRotationMember.objects.count(),
            'channels': NotificationChannel.objects.count(),
        })
        rendered = str(inspect_oncall_coverage())
        self.assertNotIn('secret.example', rendered)
        self.assertNotIn('coverage-secret', rendered)
        self.assertNotIn('@example.com', rendered)

