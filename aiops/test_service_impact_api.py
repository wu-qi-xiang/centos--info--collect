from django.test import TestCase
from django.urls import reverse
from django.utils import timezone
from datetime import timedelta

from RemoteLinux.models import NewLinux, User
from devops.models import (
    AlertEvent,
    DeploymentApp,
    DeploymentHealthEvaluation,
    DeploymentRelease,
    DevOpsProject,
    DevOpsHostScope,
    DevOpsModulePermission,
    DevOpsRole,
    HostGroup,
    ServiceCatalog,
)


class ServiceImpactApiTests(TestCase):
    def setUp(self):
        self.user = User.objects.create(
            user='service-impact-user', email='service-impact@example.com',
            password='pwd', confirm_pwd='pwd',
        )
        self.visible_host = NewLinux.objects.create(
            linux_name='impact-api-visible', linux_ip='127.0.0.271',
            linux_hostname='impact-api-visible',
        )
        self.hidden_host = NewLinux.objects.create(
            linux_name='impact-api-hidden', linux_ip='127.0.0.272',
            linux_hostname='impact-api-hidden',
        )
        group = HostGroup.objects.create(name='service-impact-visible')
        group.hosts.add(self.visible_host)
        scope = DevOpsHostScope.objects.create(user=self.user)
        scope.groups.add(group)
        self.service = ServiceCatalog.objects.create(name='impact-api-service')
        self.service.hosts.add(self.visible_host, self.hidden_host)
        self.hidden_service = ServiceCatalog.objects.create(name='impact-api-private')
        self.hidden_service.hosts.add(self.hidden_host)
        AlertEvent.objects.create(
            host=self.visible_host, level=AlertEvent.LEVEL_CRITICAL,
            metric='availability', status=AlertEvent.STATUS_OPEN,
            message='private visible alert', remark='private visible remark',
        )
        AlertEvent.objects.create(
            host=self.hidden_host, level=AlertEvent.LEVEL_CRITICAL,
            metric='availability', status=AlertEvent.STATUS_OPEN,
            message='private hidden alert', remark='private hidden remark',
        )

    def _login(self):
        session = self.client.session
        session['is_login'] = True
        session['user_id'] = self.user.id
        session['user_name'] = self.user.user
        session.save()

    def _grant_service_view(self):
        DevOpsRole.objects.create(user=self.user, role=DevOpsRole.ROLE_VIEWER)
        DevOpsModulePermission.objects.create(
            user=self.user, module=DevOpsModulePermission.MODULE_SERVICE,
            role=DevOpsRole.ROLE_VIEWER,
        )

    def test_returns_only_visible_safe_service_impacts(self):
        self._login()
        self._grant_service_view()

        response = self.client.get(reverse('aiops:api_service_impacts'), {'window': '6h'})

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload['window'], '6h')
        self.assertEqual([item['service']['id'] for item in payload['results']], [self.service.id])
        self.assertEqual(payload['results'][0]['host_count'], 1)
        self.assertEqual(payload['results'][0]['evidence_counts']['active_alerts'], 1)
        rendered = repr(payload)
        for private_value in (
                'impact-api-visible', 'impact-api-hidden', 'private visible alert',
                'private visible remark', 'private hidden alert', 'private hidden remark',
                'impact-api-private'):
            self.assertNotIn(private_value, rendered)

    def test_rejects_unauthorized_invalid_and_non_get_requests(self):
        endpoint = reverse('aiops:api_service_impacts')
        self.assertEqual(self.client.get(endpoint).status_code, 401)

        self._login()
        DevOpsRole.objects.create(user=self.user, role=DevOpsRole.ROLE_VIEWER)
        DevOpsModulePermission.objects.create(
            user=self.user, module=DevOpsModulePermission.MODULE_SERVICE,
            role=DevOpsModulePermission.ROLE_NONE,
        )
        self.assertEqual(self.client.get(endpoint).status_code, 403)

        DevOpsModulePermission.objects.filter(user=self.user).update(role=DevOpsRole.ROLE_VIEWER)
        invalid = self.client.get(endpoint, {'window': '7d'})
        self.assertEqual(invalid.status_code, 400)
        self.assertEqual(invalid.json()['code'], 'validation_error')
        self.assertEqual(self.client.post(endpoint).status_code, 405)

    def test_window_excludes_old_alerts(self):
        self._login()
        self._grant_service_view()
        AlertEvent.objects.filter(host=self.visible_host).update(
            updated_at=timezone.now() - timedelta(hours=7),
        )

        response = self.client.get(reverse('aiops:api_service_impacts'), {'window': '6h'})

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()['results'][0]['evidence_counts']['active_alerts'], 0)

    def test_workbench_requires_visible_service_and_returns_safe_metadata(self):
        self._login()
        self._grant_service_view()
        app = DeploymentApp.objects.create(name='impact-api-workbench-app')
        project = DevOpsProject.objects.create(name='impact-api-workbench-project')
        project.services.add(self.service)
        project.deployment_apps.add(app)
        release = DeploymentRelease.objects.create(
            app=app, version='v1', status=DeploymentRelease.STATUS_FAILED,
            deploy_script='private script', summary='private release summary',
        )
        release.hosts.add(self.visible_host)
        DeploymentHealthEvaluation.objects.create(
            release=release, batch_identity='host_ids=%s' % self.visible_host.id,
            status=DeploymentHealthEvaluation.STATUS_UNHEALTHY, score=20,
            summary='private health summary', evaluated_at=timezone.now(),
        )

        endpoint = reverse('aiops:api_service_workbench', args=[self.service.id])
        response = self.client.get(endpoint, {'window': '6h'})

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload['service'], {'id': self.service.id, 'name': self.service.name})
        self.assertEqual(payload['releases'][0]['id'], release.id)
        self.assertEqual(payload['releases'][0]['health_state'], DeploymentHealthEvaluation.STATUS_UNHEALTHY)
        self.assertEqual(self.client.get(
            reverse('aiops:api_service_workbench', args=[self.hidden_service.id]), {'window': '6h'},
        ).status_code, 404)
        rendered = repr(payload)
        for private_value in ('private script', 'private release summary', 'private health summary'):
            self.assertNotIn(private_value, rendered)

    def test_workbench_rejects_unauthorized_invalid_and_non_get_requests(self):
        endpoint = reverse('aiops:api_service_workbench', args=[self.service.id])
        self.assertEqual(self.client.get(endpoint).status_code, 401)

        self._login()
        DevOpsRole.objects.create(user=self.user, role=DevOpsRole.ROLE_VIEWER)
        DevOpsModulePermission.objects.create(
            user=self.user, module=DevOpsModulePermission.MODULE_SERVICE,
            role=DevOpsModulePermission.ROLE_NONE,
        )
        self.assertEqual(self.client.get(endpoint).status_code, 403)
        DevOpsModulePermission.objects.filter(user=self.user).update(role=DevOpsRole.ROLE_VIEWER)
        invalid = self.client.get(endpoint, {'window': '7d'})
        self.assertEqual(invalid.status_code, 400)
        self.assertEqual(invalid.json()['code'], 'validation_error')
        self.assertEqual(self.client.post(endpoint).status_code, 405)
