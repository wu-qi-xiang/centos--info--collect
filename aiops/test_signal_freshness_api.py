from datetime import timedelta

from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from RemoteLinux.models import NewLinux, User
from devops.models import DevOpsHostScope, DevOpsModulePermission, DevOpsRole, HostGroup, MetricSample


class SignalFreshnessApiTests(TestCase):
    def setUp(self):
        self.user = User.objects.create(
            user='freshness-viewer', email='freshness@example.com',
            password='plain-password', confirm_pwd='plain-password',
        )
        DevOpsRole.objects.create(user=self.user, role=DevOpsRole.ROLE_VIEWER)
        DevOpsModulePermission.objects.create(
            user=self.user, module=DevOpsModulePermission.MODULE_METRIC,
            role=DevOpsRole.ROLE_VIEWER,
        )
        self.host = self.make_host('freshness-visible', '127.0.42.1')
        self.hidden_host = self.make_host('freshness-hidden', '127.0.42.2')
        group = HostGroup.objects.create(name='freshness-visible-group')
        group.hosts.add(self.host)
        scope = DevOpsHostScope.objects.create(user=self.user)
        scope.groups.add(group)
        self.login()

    def make_host(self, name, ip):
        return NewLinux.objects.create(
            linux_name=name, linux_ip=ip, linux_hostname=name,
            linux_user='root', linux_passwd='hidden-password',
        )

    def login(self):
        session = self.client.session
        session['is_login'] = True
        session['user_id'] = self.user.id
        session['user_name'] = self.user.user
        session.save()

    def test_visible_results_are_scoped_safe_and_read_only(self):
        now = timezone.now()
        MetricSample.objects.create(
            host=self.host, metric=MetricSample.METRIC_CPU, value=91.23456,
            collected_at=now - timedelta(minutes=10),
        )
        MetricSample.objects.create(
            host=self.hidden_host, metric=MetricSample.METRIC_CPU, value=99.99999,
            collected_at=now - timedelta(minutes=10),
        )
        before = MetricSample.objects.count()

        response = self.client.get(reverse('aiops:api_signal_freshness'), {'window': '24h'})

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertTrue(payload['ok'])
        self.assertEqual(payload['window'], '24h')
        self.assertEqual([item['host_name'] for item in payload['results']], ['freshness-visible'])
        rendered = repr(payload)
        for private_value in ('127.0.42.1', '127.0.42.2', 'hidden-password', '91.23456', '99.99999', 'freshness-hidden'):
            self.assertNotIn(private_value, rendered)
        self.assertEqual(MetricSample.objects.count(), before)

    def test_requires_session_metric_permission_and_valid_window(self):
        self.client.logout()
        unauthenticated = self.client.get(reverse('aiops:api_signal_freshness'))
        self.assertEqual(unauthenticated.status_code, 401)
        self.assertEqual(unauthenticated.json()['code'], 'unauthorized')

        self.login()
        DevOpsModulePermission.objects.filter(user=self.user).update(
            role=DevOpsModulePermission.ROLE_NONE,
        )
        forbidden = self.client.get(reverse('aiops:api_signal_freshness'))
        self.assertEqual(forbidden.status_code, 403)
        self.assertEqual(forbidden.json()['code'], 'forbidden')

        DevOpsModulePermission.objects.filter(user=self.user).update(role=DevOpsRole.ROLE_VIEWER)
        invalid = self.client.get(reverse('aiops:api_signal_freshness'), {'window': '7d'})
        self.assertEqual(invalid.status_code, 400)
        self.assertEqual(invalid.json()['code'], 'validation_error')

    def test_is_get_only_and_does_not_write_metric_samples(self):
        sample = MetricSample.objects.create(
            host=self.host, metric=MetricSample.METRIC_MEMORY, value=62.1,
            collected_at=timezone.now(),
        )
        before = MetricSample.objects.count()

        response = self.client.post(reverse('aiops:api_signal_freshness'))

        self.assertEqual(response.status_code, 405)
        self.assertEqual(response.json()['code'], 'method_not_allowed')
        self.assertEqual(MetricSample.objects.count(), before)
        sample.refresh_from_db()
        self.assertEqual(sample.value, 62.1)
