from django.test import TestCase
from django.urls import reverse

from RemoteLinux.models import User

from .models import (
    AuditLog, DevOpsRole, NotificationChannel, ServiceCatalog,
    ServiceOnCallPolicy, ServiceOnCallRotationMember,
)


class ServiceOnCallRotationManagementTests(TestCase):
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
        self.rotation_user = User.objects.create(
            user='rotation-user', email='rotation@example.com',
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
        self.rotation_channel = NotificationChannel.objects.create(
            name='rotation-channel', channel_type=NotificationChannel.TYPE_WEBHOOK,
            webhook_url='https://example.com/rotation-secret-url', secret='rotation-secret',
        )
        self.policy = ServiceOnCallPolicy.objects.create(
            service=self.service, primary_user=self.primary, primary_channel=self.primary_channel,
            backup_user=self.backup, backup_channel=self.backup_channel,
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

    def payload(self, **overrides):
        value = {
            'user': self.primary.id,
            'channel': self.primary_channel.id,
            'position': 1,
            'enabled': 'on',
        }
        value.update(overrides)
        return value

    def test_rotation_page_requires_security_administrator(self):
        response = self.client.get(reverse('devops:oncall_rotation_members', args=[self.policy.id]))

        self.assertEqual(response.status_code, 403)

    def test_security_admin_can_add_member_without_exposing_channel_secrets(self):
        self.set_security_admin()

        response = self.client.post(
            reverse('devops:oncall_rotation_member_create', args=[self.policy.id]), self.payload(),
        )

        self.assertRedirects(response, reverse('devops:oncall_rotation_members', args=[self.policy.id]))
        member = ServiceOnCallRotationMember.objects.get(policy=self.policy)
        self.assertEqual(member.position, 1)
        audit = AuditLog.objects.get(action='创建服务值班轮换成员')
        self.assertIn('服务=payments', audit.detail)
        self.assertIn('渠道=primary-channel', audit.detail)
        self.assertNotIn('primary-secret', audit.detail)
        self.assertNotIn('primary-secret-url', audit.detail)

        page = self.client.get(reverse('devops:oncall_rotation_members', args=[self.policy.id]))
        self.assertContains(page, 'primary-channel')
        self.assertNotContains(page, 'primary-secret')
        self.assertNotContains(page, 'primary-secret-url')

    def test_rotation_rejects_duplicate_position_and_disabled_channel(self):
        self.set_security_admin()
        ServiceOnCallRotationMember.objects.create(
            policy=self.policy, user=self.primary, channel=self.primary_channel, position=1,
        )

        duplicate = self.client.post(
            reverse('devops:oncall_rotation_member_create', args=[self.policy.id]),
            self.payload(user=self.backup.id, channel=self.backup_channel.id, position=1),
        )
        self.assertEqual(duplicate.status_code, 400)
        self.assertContains(duplicate, '该轮换顺序已被占用', status_code=400)

        self.backup_channel.enabled = False
        self.backup_channel.save(update_fields=['enabled'])
        disabled = self.client.post(
            reverse('devops:oncall_rotation_member_create', args=[self.policy.id]),
            self.payload(user=self.backup.id, channel=self.backup_channel.id, position=2),
        )
        self.assertEqual(disabled.status_code, 400)
        self.assertEqual(ServiceOnCallRotationMember.objects.count(), 1)

    def test_rotation_rejects_fixed_backup_user_and_channel(self):
        self.set_security_admin()

        backup_user = self.client.post(
            reverse('devops:oncall_rotation_member_create', args=[self.policy.id]),
            self.payload(user=self.backup.id, channel=self.primary_channel.id, position=1),
        )
        self.assertEqual(backup_user.status_code, 400)
        self.assertContains(backup_user, '轮换成员不能使用固定备值班用户', status_code=400)

        backup_channel = self.client.post(
            reverse('devops:oncall_rotation_member_create', args=[self.policy.id]),
            self.payload(user=self.primary.id, channel=self.backup_channel.id, position=2),
        )
        self.assertEqual(backup_channel.status_code, 400)
        self.assertContains(backup_channel, '轮换成员不能使用固定备值班通知渠道', status_code=400)
        self.assertFalse(ServiceOnCallRotationMember.objects.exists())
        self.assertFalse(AuditLog.objects.filter(action='创建服务值班轮换成员').exists())

    def test_security_admin_can_update_and_delete_member(self):
        self.set_security_admin()
        member = ServiceOnCallRotationMember.objects.create(
            policy=self.policy, user=self.primary, channel=self.primary_channel, position=1,
        )

        update = self.client.post(
            reverse('devops:oncall_rotation_member_update', args=[member.id]),
            self.payload(user=self.rotation_user.id, channel=self.rotation_channel.id, position=2, enabled=''),
        )
        self.assertRedirects(update, reverse('devops:oncall_rotation_members', args=[self.policy.id]))
        member.refresh_from_db()
        self.assertEqual(member.position, 2)
        self.assertFalse(member.enabled)
        self.assertTrue(AuditLog.objects.filter(action='更新服务值班轮换成员').exists())

        deleted = self.client.post(reverse('devops:oncall_rotation_member_delete', args=[member.id]))
        self.assertRedirects(deleted, reverse('devops:oncall_rotation_members', args=[self.policy.id]))
        self.assertFalse(ServiceOnCallRotationMember.objects.exists())
        self.assertTrue(AuditLog.objects.filter(action='删除服务值班轮换成员').exists())
