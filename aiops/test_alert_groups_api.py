from django.test import TestCase
from django.urls import reverse

from RemoteLinux.models import NewLinux, User
from devops.models import AlertEvent, DevOpsHostScope, DevOpsModulePermission, DevOpsRole, HostGroup


class AlertGroupApiTests(TestCase):
    def setUp(self):
        self.user = User.objects.create(user='group-viewer', email='group@example.com', password='pwd', confirm_pwd='pwd')
        DevOpsRole.objects.create(user=self.user, role=DevOpsRole.ROLE_VIEWER)
        DevOpsModulePermission.objects.create(user=self.user, module=DevOpsModulePermission.MODULE_ALERT, role=DevOpsRole.ROLE_VIEWER)
        self.host = NewLinux.objects.create(linux_name='api-group-visible', linux_ip='127.0.0.254', linux_hostname='api-group-visible')
        self.hidden = NewLinux.objects.create(linux_name='api-group-hidden', linux_ip='127.0.0.255', linux_hostname='api-group-hidden')
        group = HostGroup.objects.create(name='api-alert-group-scope')
        group.hosts.add(self.host)
        scope = DevOpsHostScope.objects.create(user=self.user)
        scope.groups.add(group)
        session = self.client.session
        session['is_login'] = True
        session['user_id'] = self.user.id
        session['user_name'] = self.user.user
        session.save()

    def test_visible_alert_groups_are_scoped_and_safe(self):
        AlertEvent.objects.create(host=self.host, metric='cpu', level='critical', message='private visible')
        AlertEvent.objects.create(host=self.hidden, metric='cpu', level='critical', message='private hidden')

        response = self.client.get(reverse('aiops:api_alert_groups'), {'window': '24h'})

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload['results'][0]['host_count'], 1)
        self.assertNotIn('private', repr(payload))

    def test_requires_session_alert_permission_and_valid_window(self):
        self.client.logout()
        self.assertEqual(self.client.get(reverse('aiops:api_alert_groups')).status_code, 401)
        session = self.client.session
        session['is_login'] = True
        session['user_id'] = self.user.id
        session['user_name'] = self.user.user
        session.save()
        DevOpsModulePermission.objects.filter(user=self.user).update(role=DevOpsModulePermission.ROLE_NONE)
        self.assertEqual(self.client.get(reverse('aiops:api_alert_groups')).status_code, 403)
        DevOpsModulePermission.objects.filter(user=self.user).update(role=DevOpsRole.ROLE_VIEWER)
        invalid = self.client.get(reverse('aiops:api_alert_groups'), {'window': '7d'})
        self.assertEqual(invalid.status_code, 400)
        self.assertEqual(invalid.json()['code'], 'validation_error')

    def test_is_get_only_and_does_not_change_alerts(self):
        alert = AlertEvent.objects.create(
            host=self.host, metric='cpu', level='critical', status=AlertEvent.STATUS_PROCESSING,
            repeat_count=4, message='private alert', remark='private remark',
        )
        before_count = AlertEvent.objects.count()
        before_status = alert.status
        before_repeats = alert.repeat_count

        response = self.client.post(reverse('aiops:api_alert_groups'))

        self.assertEqual(response.status_code, 405)
        self.assertEqual(response.json()['code'], 'method_not_allowed')
        self.assertEqual(AlertEvent.objects.count(), before_count)
        alert.refresh_from_db()
        self.assertEqual(alert.status, before_status)
        self.assertEqual(alert.repeat_count, before_repeats)
