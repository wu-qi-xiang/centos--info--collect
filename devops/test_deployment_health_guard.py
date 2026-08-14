from datetime import timedelta
from unittest import mock

from django.test import TestCase
from django.utils import timezone

from RemoteLinux.models import NewLinux
from .models import (
    AlertEvent,
    ApprovalRequest,
    CommandExecution,
    DeploymentApp,
    DeploymentHealthEvaluation,
    DeploymentRelease,
    DeploymentResult,
    ServiceCatalog,
    ServiceSlo,
)
from .services import evaluate_deployment_health, execute_deployment_release
from .forms import DeploymentReleaseForm
from .api import serialize_release


class DeploymentHealthGuardTests(TestCase):
    def setUp(self):
        self.host = NewLinux.objects.create(
            linux_name='health-guard-host',
            linux_ip='127.0.0.221',
            linux_hostname='health-guard-host',
        )
        self.other_host = NewLinux.objects.create(
            linux_name='health-guard-other',
            linux_ip='127.0.0.222',
            linux_hostname='health-guard-other',
        )
        self.app = DeploymentApp.objects.create(name='health-guard-app')
        self.release = DeploymentRelease.objects.create(
            app=self.app,
            version='health-guard-v1',
            deploy_script='echo deploy',
        )
        self.release.hosts.add(self.host, self.other_host)
        self.now = timezone.now()
        DeploymentRelease.objects.filter(pk=self.release.pk).update(
            created_at=self.now - timedelta(minutes=5),
        )
        self.release.refresh_from_db()

    def test_critical_post_release_signal_is_unhealthy_without_raw_alert_text(self):
        alert = AlertEvent.objects.create(
            host=self.host,
            level=AlertEvent.LEVEL_CRITICAL,
            metric='availability',
            message='private alert message must never be persisted',
        )
        AlertEvent.objects.filter(pk=alert.pk).update(created_at=self.now)

        evaluation = evaluate_deployment_health(
            self.release, batch_hosts=[self.host], now=self.now,
        )

        self.assertEqual(evaluation.status, DeploymentHealthEvaluation.STATUS_UNHEALTHY)
        self.assertIn('critical_alert=1', evaluation.summary)
        self.assertNotIn(alert.message, evaluation.summary)
        self.assertEqual(evaluation.score, 50)
        self.assertEqual(evaluation.batch_identity, 'host_ids=%s' % self.host.id)

    def test_no_post_release_signal_is_healthy_and_out_of_batch_data_is_ignored(self):
        ignored_alert = AlertEvent.objects.create(
            host=self.other_host,
            level=AlertEvent.LEVEL_CRITICAL,
            metric='availability',
            message='other batch alert',
        )
        failed_command = CommandExecution.objects.create(
            host=self.other_host,
            command='private command',
            status=CommandExecution.STATUS_FAILED,
        )
        AlertEvent.objects.filter(pk=ignored_alert.pk).update(created_at=self.now)
        CommandExecution.objects.filter(pk=failed_command.pk).update(created_at=self.now)

        evaluation = evaluate_deployment_health(
            self.release, batch_hosts=[self.host], now=self.now,
        )

        self.assertEqual(evaluation.status, DeploymentHealthEvaluation.STATUS_HEALTHY)
        self.assertEqual(evaluation.score, 100)
        self.assertEqual(evaluation.summary, 'critical_alert=0, failed_command=0, exhausted_slo=0')

    def test_failed_command_and_exhausted_enabled_slo_are_unhealthy(self):
        command = CommandExecution.objects.create(
            host=self.host,
            command='private command',
            status=CommandExecution.STATUS_FAILED,
        )
        CommandExecution.objects.filter(pk=command.pk).update(created_at=self.now)
        service = ServiceCatalog.objects.create(name='health-guard-service')
        service.hosts.add(self.host)
        ServiceSlo.objects.create(
            service=service,
            metric_kind=ServiceSlo.KIND_AVAILABILITY,
            target=99,
            enabled=True,
            last_state=ServiceSlo.STATE_EXHAUSTED,
            last_evaluated_at=self.now,
        )

        evaluation = evaluate_deployment_health(
            self.release, batch_hosts=[self.host], now=self.now,
        )

        self.assertEqual(evaluation.status, DeploymentHealthEvaluation.STATUS_UNHEALTHY)
        self.assertEqual(evaluation.score, 50)
        self.assertEqual(
            evaluation.summary,
            'critical_alert=0, failed_command=1, exhausted_slo=1',
        )

    def test_empty_or_out_of_scope_batch_does_not_persist_an_evaluation(self):
        for batch_hosts in ([], [NewLinux.objects.create(
                linux_name='health-guard-unrelated',
                linux_ip='127.0.0.223',
                linux_hostname='health-guard-unrelated',
        )]):
            with self.assertRaises(ValueError):
                evaluate_deployment_health(self.release, batch_hosts=batch_hosts, now=self.now)
        self.assertFalse(DeploymentHealthEvaluation.objects.exists())

    def test_pre_release_signals_and_stale_or_unrelated_slos_are_ignored(self):
        pre_release = self.release.created_at - timedelta(seconds=1)
        alert = AlertEvent.objects.create(
            host=self.host,
            level=AlertEvent.LEVEL_CRITICAL,
            metric='availability',
            message='pre-release alert',
        )
        command = CommandExecution.objects.create(
            host=self.host,
            command='pre-release command',
            status=CommandExecution.STATUS_FAILED,
        )
        AlertEvent.objects.filter(pk=alert.pk).update(created_at=pre_release)
        CommandExecution.objects.filter(pk=command.pk).update(created_at=pre_release)
        batch_service = ServiceCatalog.objects.create(name='health-guard-batch-service')
        batch_service.hosts.add(self.host)
        ServiceSlo.objects.create(
            service=batch_service,
            metric_kind=ServiceSlo.KIND_AVAILABILITY,
            target=99,
            enabled=True,
            last_state=ServiceSlo.STATE_EXHAUSTED,
            last_evaluated_at=pre_release,
        )
        unrelated_service = ServiceCatalog.objects.create(name='health-guard-unrelated-service')
        ServiceSlo.objects.create(
            service=unrelated_service,
            metric_kind=ServiceSlo.KIND_LATENCY,
            target=300,
            enabled=True,
            last_state=ServiceSlo.STATE_EXHAUSTED,
            last_evaluated_at=self.now,
        )

        evaluation = evaluate_deployment_health(
            self.release, batch_hosts=[self.host], now=self.now,
        )

        self.assertEqual(evaluation.status, DeploymentHealthEvaluation.STATUS_HEALTHY)
        self.assertEqual(evaluation.score, 100)
        self.assertEqual(evaluation.summary, 'critical_alert=0, failed_command=0, exhausted_slo=0')

    def test_resolved_closed_alerts_and_future_slo_do_not_block_health(self):
        for status in (AlertEvent.STATUS_RESOLVED, AlertEvent.STATUS_CLOSED):
            alert = AlertEvent.objects.create(
                host=self.host,
                level=AlertEvent.LEVEL_CRITICAL,
                metric='availability',
                status=status,
                message='historical alert',
            )
            AlertEvent.objects.filter(pk=alert.pk).update(created_at=self.now)
        service = ServiceCatalog.objects.create(name='health-guard-future-slo')
        service.hosts.add(self.host)
        ServiceSlo.objects.create(
            service=service,
            metric_kind=ServiceSlo.KIND_AVAILABILITY,
            target=99,
            enabled=True,
            last_state=ServiceSlo.STATE_EXHAUSTED,
            last_evaluated_at=self.now + timedelta(minutes=5),
        )

        evaluation = evaluate_deployment_health(
            self.release, batch_hosts=[self.host], now=self.now,
        )

        self.assertEqual(evaluation.status, DeploymentHealthEvaluation.STATUS_HEALTHY)
        self.assertEqual(evaluation.summary, 'critical_alert=0, failed_command=0, exhausted_slo=0')

    @mock.patch('devops.services.execute_command_record')
    def test_unhealthy_batch_blocks_following_hosts_and_creates_rollback_approval(self, execute_command):
        self.release.rollout_batch_size = 1
        self.release.save(update_fields=['rollout_batch_size'])

        def successful_first_batch(record, role):
            record.status = CommandExecution.STATUS_SUCCESS
            record.finished_at = timezone.now()
            record.save(update_fields=['status', 'finished_at'])
            if record.host_id == self.host.id:
                AlertEvent.objects.create(
                    host=self.host,
                    level=AlertEvent.LEVEL_CRITICAL,
                    metric='availability',
                    message='private post-release failure',
                )

        execute_command.side_effect = successful_first_batch

        execute_deployment_release(self.release)
        self.release.refresh_from_db()

        self.assertEqual(self.release.status, DeploymentRelease.STATUS_BLOCKED)
        self.assertEqual(DeploymentResult.objects.filter(release=self.release).count(), 1)
        self.assertFalse(DeploymentResult.objects.filter(
            release=self.release, host=self.other_host,
        ).exists())
        self.assertTrue(DeploymentHealthEvaluation.objects.filter(
            release=self.release,
            status=DeploymentHealthEvaluation.STATUS_UNHEALTHY,
        ).exists())
        self.assertTrue(ApprovalRequest.objects.filter(
            deployment_release=self.release,
            request_type=ApprovalRequest.TYPE_ROLLBACK,
            status=ApprovalRequest.STATUS_PENDING,
        ).exists())

    @mock.patch('devops.services.execute_command_record')
    def test_zero_rollout_batch_size_preserves_all_hosts_execution(self, execute_command):
        def successful_command(record, role):
            record.status = CommandExecution.STATUS_SUCCESS
            record.finished_at = timezone.now()
            record.save(update_fields=['status', 'finished_at'])

        execute_command.side_effect = successful_command

        execute_deployment_release(self.release)
        self.release.refresh_from_db()

        self.assertEqual(self.release.status, DeploymentRelease.STATUS_SUCCESS)
        self.assertEqual(DeploymentResult.objects.filter(release=self.release).count(), 2)
        self.assertFalse(DeploymentHealthEvaluation.objects.filter(release=self.release).exists())

    def test_release_form_accepts_bounded_rollout_batch_size(self):
        form = DeploymentReleaseForm(data={
            'app': self.app.id, 'version': 'form-v1', 'deploy_script': 'echo deploy',
            'rollback_script': '', 'hosts': [self.host.id], 'rollout_batch_size': 1,
        })

        self.assertTrue(form.is_valid(), form.errors)
        self.assertEqual(form.cleaned_data['rollout_batch_size'], 1)

    def test_release_form_defaults_missing_rollout_batch_size_to_zero(self):
        form = DeploymentReleaseForm(data={
            'app': self.app.id, 'version': 'form-default-v1', 'deploy_script': 'echo deploy',
            'rollback_script': '', 'hosts': [self.host.id],
        })

        self.assertTrue(form.is_valid(), form.errors)
        self.assertEqual(form.cleaned_data['rollout_batch_size'], 0)

    def test_release_summary_contains_only_safe_latest_health_evaluation(self):
        evaluation = DeploymentHealthEvaluation.objects.create(
            release=self.release, batch_identity='host_ids=%s' % self.host.id,
            status=DeploymentHealthEvaluation.STATUS_UNHEALTHY, score=50,
            summary='critical_alert=1, failed_command=0, exhausted_slo=0',
            evaluated_at=self.now,
        )

        result = serialize_release(self.release)

        self.assertEqual(result['rollout_batch_size'], 0)
        self.assertEqual(result['health_evaluation']['id'], evaluation.id)
        self.assertEqual(result['health_evaluation']['status'], 'unhealthy')
        self.assertNotIn('private', repr(result['health_evaluation']))
