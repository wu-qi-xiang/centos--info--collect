from django.test import TestCase

from RemoteLinux.models import NewLinux
from devops.models import (
    AlertEvent, CIDelivery, DeploymentApp, DeploymentHealthEvaluation,
    DeploymentRelease, DevOpsProject, Incident, ServiceCatalog, ServiceSlo,
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
            'critical_alerts': 1, 'open_incidents': 1, 'exhausted_slos': 1,
            'unhealthy_deployments': 1, 'failed_ci_deliveries': 1,
        })
        self.assertNotIn('private', repr(result))
