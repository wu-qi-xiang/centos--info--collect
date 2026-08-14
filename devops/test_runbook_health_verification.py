from django.test import TestCase

from RemoteLinux.models import NewLinux
from .models import AlertEvent, ApprovalRequest, CommandExecution, RunbookTemplate
from .services import finalize_command_approval


class RunbookHealthVerificationTests(TestCase):
    def setUp(self):
        self.host = NewLinux.objects.create(
            linux_name='runbook-health-host', linux_ip='127.0.0.251',
            linux_hostname='runbook-health-host',
        )
        self.rollback_runbook = RunbookTemplate.objects.create(
            name='runbook-health-rollback', version=1,
            command_template='systemctl restart nginx', requires_approval=True,
        )
        self.rollback_runbook.allowed_hosts.add(self.host)
        self.runbook = RunbookTemplate.objects.create(
            name='runbook-health-primary', version=1,
            command_template='systemctl reload nginx', requires_approval=True,
            rollback_runbook=self.rollback_runbook,
        )
        self.runbook.allowed_hosts.add(self.host)

    def approved_execution(self):
        record = CommandExecution.objects.create(
            host=self.host, runbook_template=self.runbook,
            command=self.runbook.command_template,
            status=CommandExecution.STATUS_SUCCESS,
        )
        ApprovalRequest.objects.create(
            request_type=ApprovalRequest.TYPE_COMMAND,
            status=ApprovalRequest.STATUS_APPROVED,
            title='approved runbook', command_execution=record,
        )
        return record

    def test_unhealthy_approved_runbook_creates_pending_fixed_rollback_approval(self):
        record = self.approved_execution()
        AlertEvent.objects.create(
            host=self.host, level=AlertEvent.LEVEL_CRITICAL,
            metric='availability', message='private alert body',
            status=AlertEvent.STATUS_OPEN,
        )

        finalize_command_approval(record)

        verification = record.health_verification
        self.assertEqual(verification.status, verification.STATUS_UNHEALTHY)
        self.assertEqual(verification.active_critical_alert_count, 1)
        self.assertNotIn('private alert body', verification.summary)
        rollback_approval = verification.rollback_approval
        self.assertEqual(rollback_approval.status, ApprovalRequest.STATUS_PENDING)
        self.assertEqual(rollback_approval.command_execution.runbook_template, self.rollback_runbook)
        self.assertEqual(rollback_approval.command_execution.status, CommandExecution.STATUS_PENDING)

    def test_unhealthy_runbook_without_eligible_rollback_waits_for_manual_disposition(self):
        self.runbook.rollback_runbook = None
        self.runbook.save(update_fields=['rollback_runbook'])
        record = self.approved_execution()
        AlertEvent.objects.create(
            host=self.host, level=AlertEvent.LEVEL_CRITICAL,
            metric='availability', status=AlertEvent.STATUS_PROCESSING,
        )

        finalize_command_approval(record)

        verification = record.health_verification
        self.assertEqual(verification.status, verification.STATUS_UNHEALTHY)
        self.assertIsNone(verification.rollback_approval)
        self.assertEqual(
            ApprovalRequest.objects.filter(
                command_execution__runbook_template=self.rollback_runbook,
            ).count(), 0,
        )

    def test_repeated_completion_is_idempotent(self):
        record = self.approved_execution()
        AlertEvent.objects.create(
            host=self.host, level=AlertEvent.LEVEL_CRITICAL,
            metric='availability', status=AlertEvent.STATUS_OPEN,
        )

        finalize_command_approval(record)
        finalize_command_approval(record)

        self.assertEqual(record.health_verification.active_critical_alert_count, 1)
        self.assertEqual(ApprovalRequest.objects.count(), 2)
