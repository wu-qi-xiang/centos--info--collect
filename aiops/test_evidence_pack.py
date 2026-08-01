from datetime import timedelta

from django.test import TestCase
from django.utils import timezone

from RemoteLinux.models import NewLinux
from devops.models import (
    AlertEvent,
    CIDelivery,
    CommandExecution,
    DeploymentApp,
    DeploymentHealthEvaluation,
    DeploymentRelease,
    Incident,
    MetricSample,
)

from .evidence_pack import MAX_EVIDENCE, build_evidence_pack


class EvidencePackTests(TestCase):
    def setUp(self):
        self.host = NewLinux.objects.create(
            linux_name='evidence-host', linux_ip='127.0.0.241',
            linux_hostname='evidence-host',
        )
        self.hidden_host = NewLinux.objects.create(
            linux_name='evidence-hidden', linux_ip='127.0.0.242',
            linux_hostname='evidence-hidden',
        )
        self.end = timezone.now()
        self.start = self.end - timedelta(hours=24)
        self.observed = self.end - timedelta(hours=1)

    def in_window(self, model, item):
        timestamp_field = {
            AlertEvent: 'updated_at',
            CommandExecution: 'finished_at',
            Incident: 'updated_at',
            CIDelivery: 'received_at',
        }.get(model, 'created_at')
        model.objects.filter(pk=item.pk).update(**{timestamp_field: self.observed})

    def test_host_window_pack_is_safe_complete_and_read_only(self):
        alert = AlertEvent.objects.create(
            host=self.host, level=AlertEvent.LEVEL_CRITICAL, metric='cpu',
            message='private alert message', remark='private alert remark',
        )
        command = CommandExecution.objects.create(
            host=self.host, status=CommandExecution.STATUS_FAILED,
            command='private command', output='private output', error='private error',
        )
        incident = Incident.objects.create(
            host=self.host, title='private incident title', description='private incident description',
            status=Incident.STATUS_PROCESSING,
        )
        MetricSample.objects.create(
            host=self.host, metric=MetricSample.METRIC_CPU, value=91.2345,
            collected_at=self.observed,
        )
        app = DeploymentApp.objects.create(name='evidence-app')
        release = DeploymentRelease.objects.create(
            app=app, version='v1', deploy_script='private deploy script',
        )
        release.hosts.add(self.host)
        health = DeploymentHealthEvaluation.objects.create(
            release=release, batch_identity='host_ids=%s' % self.host.id,
            status=DeploymentHealthEvaluation.STATUS_UNHEALTHY, score=50,
            summary='critical_alert=1', evaluated_at=self.observed,
        )
        delivery = CIDelivery.objects.create(
            provider=CIDelivery.PROVIDER_GITLAB, repository='safe/repository',
            delivery_id='pipeline-1', fingerprint='a' * 64, status='failed',
            summary='GitLab CI status failed for safe/repository.', release=release,
        )
        for model, item in (
                (AlertEvent, alert), (CommandExecution, command),
                (Incident, incident), (CIDelivery, delivery)):
            self.in_window(model, item)

        before = {
            'alerts': AlertEvent.objects.count(),
            'commands': CommandExecution.objects.count(),
            'incidents': Incident.objects.count(),
            'metrics': MetricSample.objects.count(),
            'health': DeploymentHealthEvaluation.objects.count(),
            'ci': CIDelivery.objects.count(),
        }
        pack = build_evidence_pack(self.host, [self.host], self.start, self.end)

        self.assertEqual(pack['host_id'], self.host.id)
        self.assertEqual({item['kind'] for item in pack['evidence']}, {
            'alert', 'metric_state', 'incident', 'failed_command',
            'deployment_health', 'ci_delivery',
        })
        health_item = next(item for item in pack['evidence'] if item['kind'] == 'deployment_health')
        self.assertEqual(health_item['id'], health.id)
        self.assertEqual(health_item['status'], 'unhealthy')
        self.assertEqual(health_item['score'], 50)
        self.assertEqual(health_item['summary'], 'critical_alert=1')
        rendered = repr(pack)
        for private_value in (
                'private alert message', 'private alert remark', 'private command',
                'private output', 'private error', 'private incident title',
                'private incident description', '91.2345', 'host_ids=',
                'private deploy script'):
            self.assertNotIn(private_value, rendered)
        self.assertEqual(before, {
            'alerts': AlertEvent.objects.count(),
            'commands': CommandExecution.objects.count(),
            'incidents': Incident.objects.count(),
            'metrics': MetricSample.objects.count(),
            'health': DeploymentHealthEvaluation.objects.count(),
            'ci': CIDelivery.objects.count(),
        })

    def test_old_hidden_and_unselected_host_data_are_excluded(self):
        hidden = AlertEvent.objects.create(
            host=self.hidden_host, level=AlertEvent.LEVEL_CRITICAL,
            metric='hidden', message='hidden private message',
        )
        old = CommandExecution.objects.create(
            host=self.host, status=CommandExecution.STATUS_FAILED,
            command='old private command',
        )
        self.in_window(AlertEvent, hidden)
        CommandExecution.objects.filter(pk=old.pk).update(
            finished_at=self.start - timedelta(seconds=1),
        )

        pack = build_evidence_pack(self.host, [self.host], self.start, self.end)

        self.assertEqual(pack['evidence'], [])
        with self.assertRaises(ValueError):
            build_evidence_pack(self.hidden_host, [self.host], self.start, self.end)

    def test_output_is_deterministically_bounded(self):
        for index in range(MAX_EVIDENCE + 10):
            item = CommandExecution.objects.create(
                host=self.host, status=CommandExecution.STATUS_FAILED,
                command='private command %s' % index,
            )
            CommandExecution.objects.filter(pk=item.pk).update(
                finished_at=self.observed - timedelta(seconds=index),
            )

        first = build_evidence_pack(self.host, [self.host], self.start, self.end)
        second = build_evidence_pack(self.host, [self.host], self.start, self.end)

        self.assertEqual(len(first['evidence']), MAX_EVIDENCE)
        self.assertEqual(first, second)
