from datetime import timedelta

from django.test import TestCase
from django.utils import timezone

from RemoteLinux.models import NewLinux
from devops.models import (
    DeploymentApp, DeploymentHealthEvaluation, DeploymentRelease, DevOpsProject,
    Incident, ServiceCatalog,
)

from .service_workbench import build_service_workbench


class ServiceWorkbenchTests(TestCase):
    def setUp(self):
        self.visible_host = NewLinux.objects.create(
            linux_name='workbench-visible', linux_ip='127.0.0.281', linux_hostname='workbench-visible',
        )
        self.hidden_host = NewLinux.objects.create(
            linux_name='workbench-hidden', linux_ip='127.0.0.282', linux_hostname='workbench-hidden',
        )
        self.service = ServiceCatalog.objects.create(name='checkout-service')
        self.service.hosts.add(self.visible_host, self.hidden_host)
        app = DeploymentApp.objects.create(name='checkout-app')
        project = DevOpsProject.objects.create(name='checkout-project')
        project.services.add(self.service)
        project.deployment_apps.add(app)
        self.release = DeploymentRelease.objects.create(
            app=app, version='v1', status=DeploymentRelease.STATUS_FAILED,
            deploy_script='private deploy script', summary='private release summary',
        )
        self.release.hosts.add(self.visible_host)
        self.now = timezone.now()

    def test_returns_scoped_safe_incident_and_release_metadata(self):
        visible_incident = Incident.objects.create(
            host=self.visible_host, deployment_release=self.release,
            status=Incident.STATUS_PROCESSING, title='private incident title',
            description='private incident description', owner='oncall-user',
            sla_due_at=self.now + timedelta(hours=1),
        )
        hidden_incident = Incident.objects.create(
            host=self.hidden_host, deployment_release=self.release,
            status=Incident.STATUS_OPEN, title='hidden incident title', owner='hidden-owner',
        )
        DeploymentHealthEvaluation.objects.create(
            release=self.release, batch_identity='host_ids=%s' % self.visible_host.id,
            status=DeploymentHealthEvaluation.STATUS_UNHEALTHY, score=20,
            summary='private health summary', evaluated_at=self.now,
        )
        DeploymentHealthEvaluation.objects.create(
            release=self.release, batch_identity='host_ids=%s' % self.hidden_host.id,
            status=DeploymentHealthEvaluation.STATUS_HEALTHY, score=90,
            summary='hidden health summary', evaluated_at=self.now,
        )

        result = build_service_workbench(
            self.service, [self.visible_host], self.now - timedelta(hours=6), self.now + timedelta(minutes=1),
        )

        self.assertEqual(result['service'], {'id': self.service.id, 'name': 'checkout-service'})
        self.assertEqual(result['incidents'], [{
            'id': visible_incident.id,
            'status': Incident.STATUS_PROCESSING,
            'owner': 'oncall-user',
            'sla_due_at': result['incidents'][0]['sla_due_at'],
        }])
        self.assertEqual(result['releases'], [{
            'id': self.release.id,
            'status': DeploymentRelease.STATUS_FAILED,
            'health_state': DeploymentHealthEvaluation.STATUS_UNHEALTHY,
            'observed_at': result['releases'][0]['observed_at'],
        }])
        self.assertEqual(result['counts']['open_incidents'], 1)
        rendered = repr(result)
        for private_value in (
                'private incident title', 'private incident description', 'hidden incident title',
                'hidden-owner', 'private deploy script', 'private release summary',
                'private health summary', 'hidden health summary', 'workbench-hidden'):
            self.assertNotIn(private_value, rendered)
        self.assertNotIn(hidden_incident.id, [item['id'] for item in result['incidents']])
