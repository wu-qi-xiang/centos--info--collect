from unittest import mock

from django.test import TestCase
from django.urls import reverse

from RemoteLinux.models import NewLinux, User
from devops.models import (
    AlertEvent, ApprovalRequest, CIDelivery, DeploymentApp, DeploymentHealthEvaluation,
    DeploymentRelease, DevOpsHostScope, DevOpsModulePermission, DevOpsProject,
    DevOpsRole, HostGroup, Incident, ServiceCatalog, ServiceSlo, AuditLog,
)


class ReleaseImpactTests(TestCase):
    def setUp(self):
        self.host = NewLinux.objects.create(
            linux_name='release-impact-host', linux_ip='127.0.0.292', linux_hostname='release-impact-host',
        )
        self.service = ServiceCatalog.objects.create(name='release-impact-service')
        self.service.hosts.add(self.host)
        app = DeploymentApp.objects.create(name='release-impact-app')
        project = DevOpsProject.objects.create(name='release-impact-project')
        project.services.add(self.service)
        project.deployment_apps.add(app)
        self.release = DeploymentRelease.objects.create(app=app, version='v1', deploy_script='private script')
        self.release.hosts.add(self.host)

    def test_builds_safe_service_level_release_risk(self):
        from .release_impact import build_release_impact_preview

        AlertEvent.objects.create(
            host=self.host, metric='cpu', level=AlertEvent.LEVEL_CRITICAL,
            status=AlertEvent.STATUS_OPEN, message='private alert',
        )
        Incident.objects.create(host=self.host, status=Incident.STATUS_OPEN, title='private incident')
        Incident.objects.create(
            host=None, deployment_release=self.release,
            status=Incident.STATUS_PROCESSING, title='private release incident',
        )
        ServiceSlo.objects.create(
            service=self.service, metric_kind=ServiceSlo.KIND_AVAILABILITY,
            target=99, enabled=True, last_state=ServiceSlo.STATE_EXHAUSTED,
        )
        DeploymentHealthEvaluation.objects.create(
            release=self.release, batch_identity='host_ids=%s' % self.host.id,
            status=DeploymentHealthEvaluation.STATUS_UNHEALTHY, score=10,
            summary='private health', evaluated_at=self.release.created_at,
        )
        CIDelivery.objects.create(
            provider=CIDelivery.PROVIDER_GITLAB, repository='private/repo', delivery_id='delivery',
            fingerprint='b' * 64, status='failed', revision='private-rev', summary='private ci', release=self.release,
        )

        result = build_release_impact_preview(self.release, [self.service], [self.host], batch_size=1)

        self.assertEqual(result['risk'], 'critical')
        self.assertEqual(result['service_count'], 1)
        self.assertEqual(result['proposed_batch_count'], 1)
        self.assertEqual(result['evidence_counts'], {
            'critical_alerts': 1, 'open_incidents': 2, 'exhausted_slos': 1,
            'unhealthy_deployments': 1, 'failed_ci_deliveries': 1,
        })
        self.assertEqual(result['reasons'], [
            'critical_alerts', 'open_incidents', 'exhausted_slos',
            'unhealthy_deployments', 'failed_ci_deliveries',
        ])
        self.assertNotIn('private', repr(result))

    @mock.patch('devops.services.notify_approval')
    def test_critical_preview_creates_one_idempotent_risk_approval(self, notify):
        from .services import require_deployment_risk_approval

        AlertEvent.objects.create(
            host=self.host,
            level=AlertEvent.LEVEL_CRITICAL,
            status=AlertEvent.STATUS_OPEN,
            message='private alert text',
        )

        first = require_deployment_risk_approval(self.release, requester='operator')
        second = require_deployment_risk_approval(self.release, requester='operator')

        self.assertEqual(first.id, second.id)
        self.assertEqual(first.request_type, ApprovalRequest.TYPE_DEPLOYMENT)
        self.assertIn('高风险信号', first.reason)
        self.assertNotIn('private alert text', first.reason)
        self.assertEqual(ApprovalRequest.objects.filter(deployment_release=self.release).count(), 1)
        self.assertTrue(notify.called)

    @mock.patch('devops.services.notify_approval')
    def test_low_risk_preview_does_not_create_risk_approval(self, notify):
        from .services import require_deployment_risk_approval

        self.assertIsNone(require_deployment_risk_approval(self.release, requester='operator'))
        self.assertFalse(ApprovalRequest.objects.exists())
        notify.assert_not_called()


class ReleaseImpactApiScopeTests(TestCase):
    def setUp(self):
        self.user = User.objects.create(
            user='release-impact-api-user', email='release-impact-api@example.com',
            password='pwd', confirm_pwd='pwd',
        )
        self.visible_host = NewLinux.objects.create(
            linux_name='release-api-visible', linux_ip='127.0.0.293', linux_hostname='release-api-visible',
        )
        self.hidden_host = NewLinux.objects.create(
            linux_name='release-api-hidden', linux_ip='127.0.0.294', linux_hostname='release-api-hidden',
        )
        group = HostGroup.objects.create(name='release-impact-api-scope')
        group.hosts.add(self.visible_host)
        scope = DevOpsHostScope.objects.create(user=self.user)
        scope.groups.add(group)
        DevOpsRole.objects.create(user=self.user, role=DevOpsRole.ROLE_VIEWER)
        for module in (DevOpsModulePermission.MODULE_DEPLOYMENT, DevOpsModulePermission.MODULE_SERVICE,
                       DevOpsModulePermission.MODULE_APPROVAL):
            DevOpsModulePermission.objects.create(
                user=self.user, module=module, role=DevOpsRole.ROLE_VIEWER,
            )
        app = DeploymentApp.objects.create(name='release-api-app')
        self.service = ServiceCatalog.objects.create(name='release-api-service')
        self.service.hosts.add(self.visible_host)
        project = DevOpsProject.objects.create(name='release-api-project')
        project.services.add(self.service)
        project.deployment_apps.add(app)
        self.visible_release = DeploymentRelease.objects.create(
            app=app, version='visible', deploy_script='deploy',
        )
        self.visible_release.hosts.add(self.visible_host)
        self.hidden_release = DeploymentRelease.objects.create(
            app=app, version='hidden', deploy_script='deploy',
        )
        self.hidden_release.hosts.add(self.hidden_host)
        session = self.client.session
        session['is_login'] = True
        session['user_id'] = self.user.id
        session['user_name'] = self.user.user
        session.save()

    def test_release_preview_scopes_release_before_identifier_lookup(self):
        hidden = self.client.get(
            reverse('devops:api_release_impact_preview', args=[self.hidden_release.id]),
        )
        self.assertEqual(hidden.status_code, 404)
        self.assertEqual(hidden.json()['code'], 'not_found')

        visible = self.client.get(
            reverse('devops:api_release_impact_preview', args=[self.visible_release.id]),
        )
        self.assertEqual(visible.status_code, 200)

    def test_mixed_release_preview_and_approvals_exclude_hidden_scope(self):
        mixed = DeploymentRelease.objects.create(
            app=self.visible_release.app, version='mixed', deploy_script='deploy',
        )
        mixed.hosts.add(self.visible_host, self.hidden_host)
        AlertEvent.objects.create(
            host=self.hidden_host, level=AlertEvent.LEVEL_CRITICAL,
            status=AlertEvent.STATUS_OPEN, message='hidden alert',
        )
        approval = ApprovalRequest.objects.create(
            request_type=ApprovalRequest.TYPE_DEPLOYMENT,
            title='mixed approval', deployment_release=mixed,
        )

        preview = self.client.get(
            reverse('devops:api_release_impact_preview', args=[mixed.id]),
        )
        self.assertEqual(preview.status_code, 200)
        self.assertEqual(preview.json()['preview']['evidence_counts']['critical_alerts'], 0)

        approvals = self.client.get(reverse('devops:api_approvals'))
        self.assertEqual(approvals.status_code, 200)
        self.assertNotIn(approval.id, [item['id'] for item in approvals.json()['results']])

    def test_release_preview_is_stable_read_only_and_excludes_sensitive_fields(self):
        """The preview contract exposes only bounded risk metadata."""
        AlertEvent.objects.create(
            host=self.visible_host, level=AlertEvent.LEVEL_CRITICAL,
            status=AlertEvent.STATUS_OPEN, message='visible private alert',
        )
        AlertEvent.objects.create(
            host=self.hidden_host, level=AlertEvent.LEVEL_CRITICAL,
            status=AlertEvent.STATUS_OPEN, message='hidden private alert',
        )
        service = ServiceCatalog.objects.create(name='release-api-slo-service')
        service.hosts.add(self.visible_host)
        ServiceSlo.objects.create(
            service=service, metric_kind=ServiceSlo.KIND_AVAILABILITY,
            target=99, enabled=True, last_state=ServiceSlo.STATE_EXHAUSTED,
        )
        release_count = DeploymentRelease.objects.count()
        approval_count = ApprovalRequest.objects.count()
        audit_count = AuditLog.objects.count()

        url = reverse('devops:api_release_impact_preview', args=[self.visible_release.id])
        first = self.client.get(url, {'batch_size': '1'})
        second = self.client.get(url, {'batch_size': '1'})

        self.assertEqual(first.status_code, 200)
        self.assertEqual(second.status_code, 200)
        first_preview = first.json()['preview']
        second_preview = second.json()['preview']
        self.assertEqual(first_preview, second_preview)
        self.assertEqual(first_preview['risk'], 'critical')
        self.assertEqual(first_preview['reasons'], ['critical_alerts', 'exhausted_slos'])
        self.assertEqual(first_preview['evidence_counts']['critical_alerts'], 1)
        self.assertEqual(first_preview['evidence_counts']['exhausted_slos'], 1)
        self.assertEqual(first_preview['visible_host_count'], 1)
        self.assertEqual(first_preview['proposed_batch_size'], 1)
        self.assertEqual(
            set(first_preview),
            {'risk', 'service_count', 'visible_host_count', 'proposed_batch_size',
             'proposed_batch_count', 'evidence_counts', 'reasons', 'recommendation'},
        )
        self.assertNotIn('visible private alert', repr(first_preview))
        self.assertNotIn('hidden private alert', repr(first_preview))
        self.assertNotIn('deploy_script', repr(first_preview))
        self.assertEqual(DeploymentRelease.objects.count(), release_count)
        self.assertEqual(ApprovalRequest.objects.count(), approval_count)
        self.assertEqual(AuditLog.objects.count(), audit_count)

    def test_exhausted_slo_alone_requires_idempotent_risk_approval(self):
        from .services import require_deployment_risk_approval

        service = ServiceCatalog.objects.create(name='release-impact-exhausted-slo')
        service.hosts.add(self.visible_host)
        ServiceSlo.objects.create(
            service=service, metric_kind=ServiceSlo.KIND_AVAILABILITY,
            target=99, enabled=True, last_state=ServiceSlo.STATE_EXHAUSTED,
        )

        with mock.patch('devops.services.notify_approval') as notify:
            first = require_deployment_risk_approval(self.visible_release, requester='operator')
            second = require_deployment_risk_approval(self.visible_release, requester='operator')

        self.assertIsNotNone(first)
        self.assertEqual(first.id, second.id)
        self.assertEqual(first.status, ApprovalRequest.STATUS_PENDING)
        self.assertIn('高风险信号', first.reason)
        self.assertNotIn('release-impact-exhausted-slo', first.reason)
        self.assertEqual(ApprovalRequest.objects.filter(
            deployment_release=self.visible_release,
            request_type=ApprovalRequest.TYPE_DEPLOYMENT,
        ).count(), 1)
        self.assertTrue(notify.called)
