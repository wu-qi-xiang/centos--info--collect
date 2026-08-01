from django.test import TestCase
from django.utils import timezone

from RemoteLinux.models import NewLinux
from devops.models import AlertEvent, AlertQualityFeedback, CommandExecution, DeploymentApp, DeploymentHealthEvaluation, DeploymentRelease, Incident

from .investigation_timeline import build_investigation_timelines


class InvestigationTimelineTests(TestCase):
    def test_timeline_aggregates_safe_host_scoped_evidence(self):
        host = NewLinux.objects.create(linux_name='timeline-host', linux_ip='127.0.0.251', linux_hostname='timeline-host')
        alert = AlertEvent.objects.create(host=host, level='critical', metric='cpu', message='private alert')
        AlertQualityFeedback.objects.create(alert=alert, classification='noise', note='private feedback')
        CommandExecution.objects.create(host=host, command='private command', output='private output', status='failed')
        Incident.objects.create(host=host, title='private incident title', status='processing')
        release = DeploymentRelease.objects.create(app=DeploymentApp.objects.create(name='timeline-app'), version='v1', deploy_script='private deploy')
        release.hosts.add(host)
        DeploymentHealthEvaluation.objects.create(release=release, batch_identity='host_ids=%s' % host.id, status='unhealthy', score=50, summary='critical_alert=1', evaluated_at=timezone.now())

        timelines = build_investigation_timelines([host], now=timezone.now())

        rendered = repr(timelines)
        self.assertEqual(timelines[0]['host'], 'timeline-host')
        self.assertEqual({item['kind'] for item in timelines[0]['entries']}, {
            'incident', 'alert', 'alert_quality_feedback', 'failed_command', 'deployment_health',
        })
        for value in ('private alert', 'private feedback', 'private command', 'private output', 'private incident title'):
            self.assertNotIn(value, rendered)
