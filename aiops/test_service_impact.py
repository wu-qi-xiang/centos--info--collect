from django.test import TestCase
from django.utils import timezone
from datetime import timedelta

from RemoteLinux.models import NewLinux
from devops.models import (
    AlertEvent,
    CIDelivery,
    DeploymentApp,
    DeploymentHealthEvaluation,
    DeploymentRelease,
    DevOpsProject,
    Incident,
    ServiceCatalog,
    ServiceDependency,
    ServiceSlo,
)

from .service_impact import MAX_SERVICE_IMPACTS, build_service_impacts


class ServiceImpactTests(TestCase):
    def setUp(self):
        self.visible_host = NewLinux.objects.create(
            linux_name='impact-visible', linux_ip='127.0.0.261',
            linux_hostname='impact-visible',
        )
        self.hidden_host = NewLinux.objects.create(
            linux_name='impact-hidden', linux_ip='127.0.0.262',
            linux_hostname='impact-hidden',
        )
        self.service = ServiceCatalog.objects.create(
            name='payments-api', criticality=ServiceCatalog.CRITICALITY_CRITICAL,
        )
        self.service.hosts.add(self.visible_host, self.hidden_host)
        self.upstream = ServiceCatalog.objects.create(name='ledger-api')
        ServiceDependency.objects.create(
            service=self.service, upstream_service=self.upstream,
        )
        self.hidden_service = ServiceCatalog.objects.create(name='private-service')
        self.hidden_service.hosts.add(self.hidden_host)
        self.now = timezone.now()

    def test_aggregates_safe_visible_service_evidence_without_writes(self):
        AlertEvent.objects.create(
            host=self.visible_host, level=AlertEvent.LEVEL_CRITICAL,
            metric='availability', status=AlertEvent.STATUS_OPEN,
            message='private alert message', remark='private alert remark',
        )
        AlertEvent.objects.create(
            host=self.hidden_host, level=AlertEvent.LEVEL_CRITICAL,
            metric='availability', status=AlertEvent.STATUS_OPEN,
            message='hidden private alert',
        )
        Incident.objects.create(
            host=self.visible_host, status=Incident.STATUS_PROCESSING,
            title='private incident title', description='private incident description',
        )
        Incident.objects.create(
            host=self.hidden_host, status=Incident.STATUS_OPEN,
            title='hidden private incident',
        )
        ServiceSlo.objects.create(
            service=self.service, metric_kind=ServiceSlo.KIND_AVAILABILITY,
            target=99, enabled=True, last_state=ServiceSlo.STATE_EXHAUSTED,
        )
        app = DeploymentApp.objects.create(name='payments-app')
        project = DevOpsProject.objects.create(name='payments-project')
        project.services.add(self.service)
        project.deployment_apps.add(app)
        release = DeploymentRelease.objects.create(
            app=app, version='v1', deploy_script='private deploy script',
        )
        release.hosts.add(self.visible_host)
        DeploymentHealthEvaluation.objects.create(
            release=release, batch_identity='host_ids=%s' % self.visible_host.id,
            status=DeploymentHealthEvaluation.STATUS_UNHEALTHY,
            score=20, summary='private health summary', evaluated_at=self.now,
        )
        DeploymentHealthEvaluation.objects.create(
            release=release, batch_identity='host_ids=%s' % self.hidden_host.id,
            status=DeploymentHealthEvaluation.STATUS_UNHEALTHY,
            score=20, summary='hidden private health summary', evaluated_at=self.now,
        )
        CIDelivery.objects.create(
            provider=CIDelivery.PROVIDER_GITLAB, repository='private/repository',
            delivery_id='private-delivery', fingerprint='a' * 64, status='failed',
            revision='private-revision', summary='private CI summary', release=release,
        )

        before = {
            'alerts': AlertEvent.objects.count(),
            'incidents': Incident.objects.count(),
            'slos': ServiceSlo.objects.count(),
            'health': DeploymentHealthEvaluation.objects.count(),
            'ci': CIDelivery.objects.count(),
        }
        impacts = build_service_impacts([self.service, self.hidden_service], [self.visible_host], self.now)

        self.assertEqual(impacts, [{
            'service': {'id': self.service.id, 'name': 'payments-api'},
            'criticality': ServiceCatalog.CRITICALITY_CRITICAL,
            'host_count': 1,
            'affected_host_count': 1,
            'dependency_count': 1,
            'evidence_counts': {
                'active_alerts': 1,
                'open_incidents': 1,
                'exhausted_slos': 1,
                'unhealthy_deployments': 1,
                'failed_ci_deliveries': 1,
            },
            'state': 'critical',
            'recommendation': '优先协调服务负责人处理活动事件并核查发布健康状态',
        }])
        rendered = repr(impacts)
        for private_value in (
                'private alert message', 'private alert remark', 'hidden private alert',
                'private incident title', 'private incident description',
                'private deploy script', 'private health summary', 'hidden private health summary',
                'private/repository',
                'private-revision', 'private CI summary', 'impact-hidden', 'private-service'):
            self.assertNotIn(private_value, rendered)
        self.assertEqual(before, {
            'alerts': AlertEvent.objects.count(),
            'incidents': Incident.objects.count(),
            'slos': ServiceSlo.objects.count(),
            'health': DeploymentHealthEvaluation.objects.count(),
            'ci': CIDelivery.objects.count(),
        })

    def test_empty_scope_and_result_limit_are_deterministic(self):
        self.assertEqual(build_service_impacts([self.service], [], self.now), [])
        for index in range(MAX_SERVICE_IMPACTS + 2):
            service = ServiceCatalog.objects.create(name='limited-service-%02d' % index)
            service.hosts.add(self.visible_host)

        first = build_service_impacts(ServiceCatalog.objects.all(), [self.visible_host], self.now)
        second = build_service_impacts(ServiceCatalog.objects.all(), [self.visible_host], self.now)

        self.assertEqual(len(first), MAX_SERVICE_IMPACTS)
        self.assertEqual(first, second)
        self.assertEqual(
            [item['service']['name'] for item in first],
            sorted(item['service']['name'] for item in first),
        )

    def test_excludes_evidence_outside_requested_window(self):
        alert = AlertEvent.objects.create(
            host=self.visible_host, level=AlertEvent.LEVEL_CRITICAL,
            metric='availability', status=AlertEvent.STATUS_OPEN, message='old alert',
        )
        incident = Incident.objects.create(
            host=self.visible_host, status=Incident.STATUS_OPEN, title='old incident',
        )
        app = DeploymentApp.objects.create(name='window-app')
        project = DevOpsProject.objects.create(name='window-project')
        project.services.add(self.service)
        project.deployment_apps.add(app)
        release = DeploymentRelease.objects.create(app=app, version='v1', deploy_script='deploy')
        release.hosts.add(self.visible_host)
        old_time = self.now - timedelta(hours=7)
        AlertEvent.objects.filter(pk=alert.pk).update(updated_at=old_time)
        Incident.objects.filter(pk=incident.pk).update(updated_at=old_time)
        DeploymentHealthEvaluation.objects.create(
            release=release, batch_identity='host_ids=%s' % self.visible_host.id,
            status=DeploymentHealthEvaluation.STATUS_UNHEALTHY, score=10,
            summary='old health', evaluated_at=old_time,
        )
        delivery = CIDelivery.objects.create(
            provider=CIDelivery.PROVIDER_GITLAB, repository='private/repository',
            delivery_id='old-window-delivery', fingerprint='b' * 64, status='failed',
            revision='old', summary='old CI', release=release,
        )
        CIDelivery.objects.filter(pk=delivery.pk).update(received_at=old_time)

        impact = build_service_impacts(
            [self.service], [self.visible_host], now=self.now,
            window_start=self.now - timedelta(hours=6), window_end=self.now,
        )[0]

        self.assertEqual(impact['evidence_counts'], {
            'active_alerts': 0,
            'open_incidents': 0,
            'exhausted_slos': 0,
            'unhealthy_deployments': 0,
            'failed_ci_deliveries': 0,
        })

    def test_counts_hostless_incident_linked_to_visible_release(self):
        app = DeploymentApp.objects.create(name='context-app')
        project = DevOpsProject.objects.create(name='context-project')
        project.services.add(self.service)
        project.deployment_apps.add(app)
        release = DeploymentRelease.objects.create(
            app=app, version='v-context', deploy_script='deploy',
        )
        release.hosts.add(self.visible_host)
        Incident.objects.create(
            deployment_release=release, status=Incident.STATUS_OPEN,
            title='private release incident',
        )

        impact = build_service_impacts(
            [self.service], [self.visible_host], now=self.now,
            window_start=self.now - timedelta(hours=1), window_end=self.now + timedelta(minutes=1),
        )[0]

        self.assertEqual(impact['evidence_counts']['open_incidents'], 1)
        self.assertEqual(impact['affected_host_count'], 0)
        self.assertEqual(impact['state'], 'degraded')
        self.assertNotIn('private release incident', repr(impact))
