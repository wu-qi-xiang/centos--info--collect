from django.test import TestCase

from RemoteLinux.models import NewLinux
from devops.models import (
    ApprovalRequest,
    CommandExecution,
    RunbookEffectivenessFeedback,
    RunbookTemplate,
)

from .runbook_effectiveness import build_runbook_effectiveness_suggestions


class RunbookEffectivenessSuggestionTests(TestCase):
    def setUp(self):
        self.host = NewLinux.objects.create(
            linux_name='runbook-effectiveness-host',
            linux_ip='127.0.0.241',
            linux_hostname='runbook-effectiveness-host',
        )
        self.hidden_host = NewLinux.objects.create(
            linux_name='runbook-effectiveness-hidden',
            linux_ip='127.0.0.242',
            linux_hostname='runbook-effectiveness-hidden',
        )
        self.effective = self.make_runbook('effective-runbook', self.host)
        self.ineffective = self.make_runbook('ineffective-runbook', self.host)
        self.hidden = self.make_runbook('hidden-runbook', self.hidden_host)

    def make_runbook(self, name, host):
        runbook = RunbookTemplate.objects.create(
            name=name, version=1, command_template='systemctl reload nginx',
        )
        runbook.allowed_hosts.add(host)
        record = CommandExecution.objects.create(
            host=host, runbook_template=runbook,
            command='systemctl reload nginx', status=CommandExecution.STATUS_SUCCESS,
        )
        ApprovalRequest.objects.create(
            request_type=ApprovalRequest.TYPE_COMMAND,
            status=ApprovalRequest.STATUS_EXECUTED,
            title='approved runbook', command_execution=record,
        )
        return runbook

    def feedback(self, runbook, classification, note='private command result'):
        record = runbook.command_executions.get()
        return RunbookEffectivenessFeedback.objects.create(
            command_execution=record, classification=classification,
            note=note, created_by='operator',
        )

    def test_ranked_suggestions_are_scoped_and_safe(self):
        self.feedback(self.effective, RunbookEffectivenessFeedback.CLASSIFICATION_EFFECTIVE)
        self.feedback(self.effective, RunbookEffectivenessFeedback.CLASSIFICATION_EFFECTIVE)
        self.feedback(self.ineffective, RunbookEffectivenessFeedback.CLASSIFICATION_INEFFECTIVE)
        self.feedback(self.hidden, RunbookEffectivenessFeedback.CLASSIFICATION_EFFECTIVE, 'hidden output')

        results = build_runbook_effectiveness_suggestions([self.host])

        self.assertEqual([item['id'] for item in results], [self.effective.id, self.ineffective.id])
        self.assertEqual(results[0]['effective_count'], 2)
        self.assertEqual(results[0]['effectiveness_score'], 100)
        self.assertEqual(results[1]['ineffective_count'], 1)
        self.assertEqual(results[1]['effectiveness_score'], 0)
        rendered = repr(results)
        self.assertNotIn('systemctl reload nginx', rendered)
        self.assertNotIn('private command result', rendered)
        self.assertNotIn('hidden output', rendered)

    def test_empty_visible_scope_returns_no_suggestions(self):
        self.assertEqual(build_runbook_effectiveness_suggestions([]), [])
