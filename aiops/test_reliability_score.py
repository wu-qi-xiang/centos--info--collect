import json
from datetime import timedelta

from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from RemoteLinux.models import NewLinux, User
from devops.models import (
    AlertEvent,
    AuditLog,
    CIDelivery,
    CommandExecution,
    DeploymentApp,
    DeploymentHealthEvaluation,
    DeploymentRelease,
    DevOpsHostScope,
    DevOpsModulePermission,
    DevOpsRole,
    DevOpsProject,
    HostGroup,
    Incident,
    IncidentActionItem,
    ServiceCatalog,
    ServiceSlo,
    BackgroundJob,
)

from .reliability_score import MAX_RELIABILITY_SERVICES, build_service_reliability


class ServiceReliabilityScoreTests(TestCase):
    def setUp(self):
        self.user = User.objects.create(
            user='reliability-score-user', email='reliability-score@example.com',
            password='pwd', confirm_pwd='pwd',
        )
        self.visible_host = NewLinux.objects.create(
            linux_name='reliability-score-visible', linux_ip='127.0.0.281',
            linux_hostname='reliability-score-visible',
        )
        self.hidden_host = NewLinux.objects.create(
            linux_name='reliability-score-hidden', linux_ip='127.0.0.282',
            linux_hostname='reliability-score-hidden',
        )
        group = HostGroup.objects.create(name='reliability-score-visible-group')
        group.hosts.add(self.visible_host)
        scope = DevOpsHostScope.objects.create(user=self.user)
        scope.groups.add(group)
        self.service = ServiceCatalog.objects.create(name='reliability-score-payments')
        self.service.hosts.add(self.visible_host, self.hidden_host)
        self.hidden_service = ServiceCatalog.objects.create(name='reliability-score-private')
        self.hidden_service.hosts.add(self.hidden_host)
        self.now = timezone.now()

    def _login(self):
        session = self.client.session
        session.update({'is_login': True, 'user_id': self.user.id, 'user_name': self.user.user})
        session.save()

    def _grant_service_view(self):
        DevOpsRole.objects.create(user=self.user, role=DevOpsRole.ROLE_VIEWER)
        DevOpsModulePermission.objects.create(
            user=self.user, module=DevOpsModulePermission.MODULE_SERVICE,
            role=DevOpsRole.ROLE_VIEWER,
        )

    def _url(self):
        return reverse('aiops:api_service_reliability')

    def test_scores_visible_evidence_and_omits_sensitive_fields_without_writes(self):
        self._login()
        self._grant_service_view()
        AlertEvent.objects.create(
            host=self.visible_host, level=AlertEvent.LEVEL_CRITICAL,
            metric='availability', status=AlertEvent.STATUS_OPEN,
            message='private visible alert', remark='private visible remark',
        )
        AlertEvent.objects.create(
            host=self.hidden_host, level=AlertEvent.LEVEL_CRITICAL,
            metric='availability', status=AlertEvent.STATUS_OPEN,
            message='hidden private alert',
        )
        Incident.objects.create(
            host=self.visible_host, status=Incident.STATUS_OPEN,
            severity=Incident.SEVERITY_HIGH, title='private open incident',
            description='private incident description',
        )
        Incident.objects.create(
            host=self.visible_host, status=Incident.STATUS_CLOSED,
            title='private closed incident', root_cause='', resolution='', follow_up='',
        )
        hidden_incident = Incident.objects.create(
            host=self.hidden_host, status=Incident.STATUS_OPEN, title='hidden incident',
        )
        IncidentActionItem.objects.create(
            incident=Incident.objects.filter(host=self.visible_host, status=Incident.STATUS_OPEN).first(),
            title='private action item', description='private action description',
            status=IncidentActionItem.STATUS_IN_PROGRESS,
            due_at=self.now - timedelta(hours=1),
        )
        IncidentActionItem.objects.create(
            incident=hidden_incident, title='hidden action item', status=IncidentActionItem.STATUS_OPEN,
            due_at=self.now - timedelta(hours=1),
        )
        ServiceSlo.objects.create(
            service=self.service, metric_kind=ServiceSlo.KIND_AVAILABILITY,
            target=99, enabled=True, last_state=ServiceSlo.STATE_EXHAUSTED,
        )
        app = DeploymentApp.objects.create(name='reliability-score-app', repository='private/repository')
        project = DevOpsProject.objects.create(name='reliability-score-project')
        project.services.add(self.service)
        project.deployment_apps.add(app)
        release = DeploymentRelease.objects.create(
            app=app, version='private-version', deploy_script='private deploy script',
        )
        release.hosts.add(self.visible_host)
        DeploymentHealthEvaluation.objects.create(
            release=release, batch_identity='host_ids=%s' % self.visible_host.id,
            status=DeploymentHealthEvaluation.STATUS_UNHEALTHY, score=20,
            summary='private health summary', evaluated_at=self.now,
        )
        CIDelivery.objects.create(
            provider=CIDelivery.PROVIDER_GITLAB, repository='private/repository',
            delivery_id='private-delivery', fingerprint='c' * 64, status='failed',
            revision='private-revision', summary='private CI summary', release=release,
        )

        before = {model: model.objects.count() for model in (AuditLog, BackgroundJob, CommandExecution)}
        response = self.client.get(self._url(), {'window': '24h'})
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload['window'], '24h')
        self.assertEqual([row['service']['id'] for row in payload['results']], [self.service.id])
        row = payload['results'][0]
        self.assertEqual(row['evidence_counts'], {
            'active_alerts': 1, 'open_incidents': 1, 'exhausted_slos': 1,
            'unhealthy_deployments': 1, 'failed_ci_deliveries': 1,
        })
        self.assertEqual(row['incident_review'], {
            'open': 1, 'closed_without_postmortem': 1,
            'action_items_open': 1, 'action_items_overdue': 1,
        })
        self.assertTrue(0 <= row['score'] <= 100)
        self.assertEqual(row['state'], 'critical')
        rendered = json.dumps(payload, ensure_ascii=False)
        for private_value in (
            'private visible alert', 'private visible remark', 'hidden private alert',
            'private incident description', 'private action description',
            'private deploy script', 'private health summary', 'private/repository',
            'private-version', 'private CI summary', 'reliability-score-hidden',
            'reliability-score-private', 'description', 'message', 'command', 'host',
        ):
            self.assertNotIn(private_value, rendered)
        self.assertEqual(before, {model: model.objects.count() for model in (AuditLog, BackgroundJob, CommandExecution)})

    def test_endpoint_auth_window_method_and_stable_bounded_response(self):
        self.assertEqual(self.client.get(self._url()).status_code, 401)
        self._login()
        DevOpsRole.objects.create(user=self.user, role=DevOpsRole.ROLE_VIEWER)
        DevOpsModulePermission.objects.create(
            user=self.user, module=DevOpsModulePermission.MODULE_SERVICE,
            role=DevOpsModulePermission.ROLE_NONE,
        )
        self.assertEqual(self.client.get(self._url()).status_code, 403)
        DevOpsModulePermission.objects.filter(user=self.user).update(role=DevOpsRole.ROLE_VIEWER)
        self.assertEqual(self.client.post(self._url()).status_code, 405)
        self.assertEqual(self.client.get(self._url(), {'window': '7d'}).status_code, 200)
        self.assertEqual(self.client.get(self._url(), {'window': '30d'}).status_code, 200)
        self.assertEqual(self.client.get(self._url(), {'window': '6h'}).status_code, 400)
        for index in range(MAX_RELIABILITY_SERVICES + 3):
            service = ServiceCatalog.objects.create(name='reliability-limited-%02d' % index)
            service.hosts.add(self.visible_host)
        first = self.client.get(self._url()).json()
        second = self.client.get(self._url()).json()
        self.assertEqual(first, second)
        self.assertEqual(len(first['results']), MAX_RELIABILITY_SERVICES)

    def test_direct_builder_excludes_hidden_service_and_empty_scope(self):
        self.assertEqual(build_service_reliability(
            [self.service, self.hidden_service], [],
            self.now - timedelta(hours=24), self.now, now=self.now,
        ), [])
        result = build_service_reliability(
            [self.service, self.hidden_service], [self.visible_host],
            self.now - timedelta(hours=24), self.now, now=self.now,
        )
        self.assertEqual([row['service']['id'] for row in result], [self.service.id])
