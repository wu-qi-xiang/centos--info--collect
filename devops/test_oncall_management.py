from django.test import TestCase
from django.urls import reverse

from RemoteLinux.models import User

from .models import AuditLog, DevOpsRole, NotificationChannel, ServiceCatalog, ServiceOnCallPolicy


class ServiceOnCallPolicyManagementTests(TestCase):
    def setUp(self):
        self.admin = User.objects.create(
            user='security-admin', email='security-admin@example.com',
            password='plain-password', confirm_pwd='plain-password',
        )
        self.primary = User.objects.create(
            user='primary-user', email='primary@example.com',
            password='plain-password', confirm_pwd='plain-password',
        )
        self.backup = User.objects.create(
            user='backup-user', email='backup@example.com',
            password='plain-password', confirm_pwd='plain-password',
        )
        self.service = ServiceCatalog.objects.create(name='payments')
        self.primary_channel = NotificationChannel.objects.create(
            name='primary-channel', channel_type=NotificationChannel.TYPE_WEBHOOK,
            webhook_url='https://example.com/primary-secret-url', secret='primary-secret',
        )
        self.backup_channel = NotificationChannel.objects.create(
            name='backup-channel', channel_type=NotificationChannel.TYPE_WEBHOOK,
            webhook_url='https://example.com/backup-secret-url', secret='backup-secret',
        )
        session = self.client.session
        session['is_login'] = True
        session['user_id'] = self.admin.id
        session['user_name'] = self.admin.user
        session.save()

    def set_security_admin(self):
        DevOpsRole.objects.update_or_create(
            user=self.admin, defaults={'role': DevOpsRole.ROLE_ADMIN},
        )

    def policy_payload(self, **overrides):
        payload = {
            'service': self.service.id,
            'primary_user': self.primary.id,
            'primary_channel': self.primary_channel.id,
            'backup_user': self.backup.id,
            'backup_channel': self.backup_channel.id,
            'enabled': 'on',
        }
        payload.update(overrides)
        return payload

    def test_page_requires_security_administrator(self):
        response = self.client.get(reverse('devops:oncall_policies'))

        self.assertEqual(response.status_code, 403)

    def test_security_admin_can_create_policy_without_rendering_channel_secrets(self):
        self.set_security_admin()

        response = self.client.post(reverse('devops:oncall_policy_create'), self.policy_payload())

        self.assertRedirects(response, reverse('devops:oncall_policies'))
        policy = ServiceOnCallPolicy.objects.get(service=self.service)
        self.assertEqual(policy.primary_user, self.primary)
        self.assertEqual(policy.backup_channel, self.backup_channel)
        audit = AuditLog.objects.get(action='创建服务值班策略')
        self.assertIn('服务=payments', audit.detail)
        self.assertIn('主渠道=primary-channel', audit.detail)
        self.assertNotIn('primary-secret-url', audit.detail)
        self.assertNotIn('primary-secret', audit.detail)

        page = self.client.get(reverse('devops:oncall_policies'))
        self.assertContains(page, 'payments')
        self.assertContains(page, 'primary-channel')
        self.assertNotContains(page, 'primary-secret-url')
        self.assertNotContains(page, 'primary-secret')

    def test_policy_rejects_duplicate_primary_and_backup_routes(self):
        self.set_security_admin()

        response = self.client.post(reverse('devops:oncall_policy_create'), self.policy_payload(
            backup_user=self.primary.id,
            backup_channel=self.primary_channel.id,
        ))

        self.assertEqual(response.status_code, 400)
        self.assertFalse(ServiceOnCallPolicy.objects.exists())
        self.assertContains(response, '主值班人与备值班人不能是同一用户', status_code=400)

    def test_security_admin_can_update_and_delete_policy(self):
        self.set_security_admin()
        policy = ServiceOnCallPolicy.objects.create(
            service=self.service,
            primary_user=self.primary,
            primary_channel=self.primary_channel,
            backup_user=self.backup,
            backup_channel=self.backup_channel,
            enabled=True,
        )

        update = self.client.post(
            reverse('devops:oncall_policy_update', args=[policy.id]),
            self.policy_payload(enabled=''),
        )
        self.assertRedirects(update, reverse('devops:oncall_policies'))
        policy.refresh_from_db()
        self.assertFalse(policy.enabled)
        self.assertTrue(AuditLog.objects.filter(action='更新服务值班策略').exists())

        deleted = self.client.post(reverse('devops:oncall_policy_delete', args=[policy.id]))
        self.assertRedirects(deleted, reverse('devops:oncall_policies'))
        self.assertFalse(ServiceOnCallPolicy.objects.exists())
        self.assertTrue(AuditLog.objects.filter(action='删除服务值班策略').exists())
