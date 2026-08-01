from datetime import timedelta

from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from RemoteLinux.models import NewLinux, User
from devops.models import (
    AlertEvent,
    CIDelivery,
    CommandExecution,
    DeploymentApp,
    DeploymentHealthEvaluation,
    DeploymentRelease,
    DevOpsHostScope,
    DevOpsModulePermission,
    DevOpsRole,
    HostGroup,
    Incident,
    MetricSample,
)


class DiagnosticEvidenceApiTests(TestCase):
    def setUp(self):
        self.user = User.objects.create(
            user='diagnostic-viewer', email='diagnostic-viewer@example.com',
            password='plain-password', confirm_pwd='plain-password',
        )
        DevOpsRole.objects.create(user=self.user, role=DevOpsRole.ROLE_VIEWER)
        for module in (
            DevOpsModulePermission.MODULE_ALERT,
            DevOpsModulePermission.MODULE_METRIC,
            DevOpsModulePermission.MODULE_COMMAND,
            DevOpsModulePermission.MODULE_DEPLOYMENT,
        ):
            DevOpsModulePermission.objects.create(
                user=self.user, module=module, role=DevOpsRole.ROLE_VIEWER,
            )
        self.host = self.make_host('diagnostic-visible', '127.0.31.1')
        self.hidden_host = self.make_host('diagnostic-hidden', '127.0.31.2')
        group = HostGroup.objects.create(name='diagnostic-visible-group')
        group.hosts.add(self.host)
        scope = DevOpsHostScope.objects.create(user=self.user)
        scope.groups.add(group)
        self.now = timezone.now()
        self.login()

    def make_host(self, name, ip):
        return NewLinux.objects.create(
            linux_name=name, linux_ip=ip, linux_hostname=name,
            linux_port='22', linux_user='root', linux_passwd='hidden-password', linux_app='',
        )

    def login(self):
        session = self.client.session
        session['is_login'] = True
        session['user_id'] = self.user.id
        session['user_name'] = self.user.user
        session.save()

    def url(self, host=None, window='24h'):
        host = self.host if host is None else host
        return '%s?host_id=%s&window=%s' % (
            reverse('aiops:api_diagnostic_evidence'), host.id, window,
        )

    def seed_evidence(self):
        alert = AlertEvent.objects.create(
            host=self.host, level=AlertEvent.LEVEL_CRITICAL, metric='cpu',
            message='private alert text', remark='private alert remark',
        )
        command = CommandExecution.objects.create(
            host=self.host, status=CommandExecution.STATUS_FAILED,
            command='private command', output='private output', error='private error',
            finished_at=self.now,
        )
        incident = Incident.objects.create(
            host=self.host, title='private incident', description='private description',
            status=Incident.STATUS_PROCESSING,
        )
        MetricSample.objects.create(
            host=self.host, metric=MetricSample.METRIC_CPU, value=95.5,
            collected_at=self.now,
        )
        app = DeploymentApp.objects.create(name='diagnostic-app')
        release = DeploymentRelease.objects.create(
            app=app, version='v1', deploy_script='private deploy script',
        )
        release.hosts.add(self.host)
        health = DeploymentHealthEvaluation.objects.create(
            release=release, batch_identity='host_ids=%s' % self.host.id,
            status=DeploymentHealthEvaluation.STATUS_UNHEALTHY,
            score=50, summary='critical_alert=1', evaluated_at=self.now,
        )
        delivery = CIDelivery.objects.create(
            provider=CIDelivery.PROVIDER_GITLAB, repository='safe/repository',
            delivery_id='diagnostic-pipeline', fingerprint='d' * 64,
            status='failed', summary='GitLab CI status failed.', release=release,
        )
        return alert, command, incident, health, delivery

    def test_visible_host_returns_all_authorized_safe_categories_without_writes(self):
        self.seed_evidence()
        before = {
            'alerts': AlertEvent.objects.count(),
            'commands': CommandExecution.objects.count(),
            'incidents': Incident.objects.count(),
            'metrics': MetricSample.objects.count(),
            'health': DeploymentHealthEvaluation.objects.count(),
            'ci': CIDelivery.objects.count(),
        }

        response = self.client.get(self.url())

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertTrue(payload['ok'])
        self.assertEqual(payload['host_id'], self.host.id)
        self.assertEqual(payload['window'], '24h')
        self.assertEqual({item['kind'] for item in payload['evidence']}, {
            'alert', 'metric_state', 'incident', 'failed_command',
            'deployment_health', 'ci_delivery',
        })
        rendered = repr(payload)
        for private_value in (
                'private alert text', 'private alert remark', 'private command',
                'private output', 'private error', 'private incident',
                'private description', '95.5', 'private deploy script',
                'hidden-password'):
            self.assertNotIn(private_value, rendered)
        self.assertEqual(before, {
            'alerts': AlertEvent.objects.count(),
            'commands': CommandExecution.objects.count(),
            'incidents': Incident.objects.count(),
            'metrics': MetricSample.objects.count(),
            'health': DeploymentHealthEvaluation.objects.count(),
            'ci': CIDelivery.objects.count(),
        })

    def test_omits_categories_without_their_module_viewer_permission(self):
        self.seed_evidence()
        DevOpsModulePermission.objects.filter(
            user=self.user, module=DevOpsModulePermission.MODULE_COMMAND,
        ).update(role=DevOpsModulePermission.ROLE_NONE)

        response = self.client.get(self.url(window='6h'))

        self.assertEqual(response.status_code, 200)
        self.assertNotIn('failed_command', [item['kind'] for item in response.json()['evidence']])
        self.assertIn('alert', [item['kind'] for item in response.json()['evidence']])

    def test_rejects_hidden_or_invalid_host_and_invalid_window(self):
        hidden = self.client.get(self.url(host=self.hidden_host))
        invalid_host = self.client.get(
            '%s?host_id=invalid&window=24h' % reverse('aiops:api_diagnostic_evidence'),
        )
        invalid_window = self.client.get(self.url(window='7d'))

        self.assertEqual(hidden.status_code, 404)
        self.assertEqual(hidden.json()['code'], 'not_found')
        self.assertEqual(invalid_host.status_code, 400)
        self.assertEqual(invalid_host.json()['code'], 'validation_error')
        self.assertEqual(invalid_window.status_code, 400)
        self.assertEqual(invalid_window.json()['code'], 'validation_error')

    def test_requires_session_and_at_least_one_evidence_module(self):
        self.client.logout()
        unauthenticated = self.client.get(self.url())
        self.assertEqual(unauthenticated.status_code, 401)
        self.assertEqual(unauthenticated.json()['code'], 'unauthorized')

        self.login()
        DevOpsModulePermission.objects.filter(user=self.user).update(
            role=DevOpsModulePermission.ROLE_NONE,
        )
        forbidden = self.client.get(self.url())
        self.assertEqual(forbidden.status_code, 403)
        self.assertEqual(forbidden.json()['code'], 'forbidden')
