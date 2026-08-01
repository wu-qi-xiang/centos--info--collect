import json

from django.test import TestCase
from django.urls import reverse

from RemoteLinux.models import NewLinux, User
from .models import (
    ApprovalRequest,
    CommandExecution,
    DevOpsModulePermission,
    DevOpsRole,
    HostGroup,
    DevOpsHostScope,
    RunbookEffectivenessFeedback,
    RunbookTemplate,
)


class RunbookEffectivenessFeedbackApiTests(TestCase):
    def setUp(self):
        self.operator = User.objects.create(
            user='feedback-operator', email='feedback-operator@example.com',
            password='plain-password', confirm_pwd='plain-password',
        )
        self.viewer = User.objects.create(
            user='feedback-viewer', email='feedback-viewer@example.com',
            password='plain-password', confirm_pwd='plain-password',
        )
        self.host = NewLinux.objects.create(
            linux_name='feedback-host', linux_ip='127.0.0.231',
            linux_hostname='feedback-host',
        )
        self.hidden_host = NewLinux.objects.create(
            linux_name='feedback-hidden', linux_ip='127.0.0.232',
            linux_hostname='feedback-hidden',
        )
        for user, role in (
                (self.operator, DevOpsRole.ROLE_OPERATOR),
                (self.viewer, DevOpsRole.ROLE_VIEWER)):
            DevOpsRole.objects.create(user=user, role=role)
            DevOpsModulePermission.objects.create(
                user=user,
                module=DevOpsModulePermission.MODULE_COMMAND,
                role=role,
            )
        group = HostGroup.objects.create(name='feedback-scope')
        group.hosts.add(self.host)
        for user in (self.operator, self.viewer):
            scope = DevOpsHostScope.objects.create(user=user)
            scope.groups.add(group)
        self.runbook = RunbookTemplate.objects.create(
            name='feedback-runbook', version=1,
            command_template='systemctl reload nginx', requires_approval=True,
        )
        self.runbook.allowed_hosts.add(self.host, self.hidden_host)
        self.record = self.make_approved_record(self.host)
        self.login(self.operator)

    def login(self, user):
        session = self.client.session
        session['is_login'] = True
        session['user_id'] = user.id
        session['user_name'] = user.user
        session.save()

    def make_approved_record(self, host):
        record = CommandExecution.objects.create(
            host=host,
            runbook_template=self.runbook,
            command='systemctl reload nginx',
            output='private execution output',
            error='private execution error',
            status=CommandExecution.STATUS_SUCCESS,
        )
        ApprovalRequest.objects.create(
            request_type=ApprovalRequest.TYPE_COMMAND,
            status=ApprovalRequest.STATUS_EXECUTED,
            title='runbook approval',
            command_execution=record,
        )
        return record

    def endpoint(self, record=None):
        return reverse('devops:api_runbook_effectiveness_feedback', args=[(record or self.record).id])

    def test_operator_can_submit_safe_feedback_without_exposing_execution_data(self):
        response = self.client.post(
            self.endpoint(),
            data=json.dumps({
                'classification': RunbookEffectivenessFeedback.CLASSIFICATION_EFFECTIVE,
                'note': 'password=do-not-store https://private.example.test/path',
            }),
            content_type='application/json',
        )

        self.assertEqual(response.status_code, 201)
        feedback = RunbookEffectivenessFeedback.objects.get()
        self.assertEqual(feedback.command_execution, self.record)
        self.assertEqual(feedback.created_by, self.operator.user)
        self.assertNotIn('do-not-store', feedback.note)
        self.assertNotIn('private.example.test', feedback.note)
        item = response.json()['feedback']
        self.assertEqual(item['runbook']['name'], self.runbook.name)
        self.assertNotIn('systemctl reload nginx', repr(item))
        self.assertNotIn('private execution output', repr(item))
        self.assertNotIn('private execution error', repr(item))

    def test_viewer_can_list_but_cannot_submit_feedback(self):
        RunbookEffectivenessFeedback.objects.create(
            command_execution=self.record,
            classification=RunbookEffectivenessFeedback.CLASSIFICATION_PARTIAL,
            note='safe note', created_by=self.operator.user,
        )
        self.login(self.viewer)

        listed = self.client.get(self.endpoint())
        denied = self.client.post(
            self.endpoint(), data=json.dumps({
                'classification': RunbookEffectivenessFeedback.CLASSIFICATION_EFFECTIVE,
            }), content_type='application/json',
        )

        self.assertEqual(listed.status_code, 200)
        self.assertEqual(listed.json()['results'][0]['classification'], 'partial')
        self.assertEqual(denied.status_code, 403)
        self.assertEqual(denied.json()['code'], 'forbidden')

    def test_feedback_requires_approved_runbook_and_visible_host(self):
        pending = CommandExecution.objects.create(
            host=self.host, runbook_template=self.runbook, command='systemctl reload nginx',
        )
        hidden = self.make_approved_record(self.hidden_host)

        pending_response = self.client.post(
            self.endpoint(pending), data=json.dumps({
                'classification': RunbookEffectivenessFeedback.CLASSIFICATION_INEFFECTIVE,
            }), content_type='application/json',
        )
        hidden_response = self.client.get(self.endpoint(hidden))

        self.assertEqual(pending_response.status_code, 400)
        self.assertEqual(pending_response.json()['code'], 'validation_error')
        self.assertEqual(hidden_response.status_code, 403)
        self.assertEqual(hidden_response.json()['code'], 'host_forbidden')

    def test_feedback_rejects_approved_but_not_completed_runbook_execution(self):
        record = CommandExecution.objects.create(
            host=self.host, runbook_template=self.runbook,
            command='systemctl reload nginx', status=CommandExecution.STATUS_PENDING,
        )
        ApprovalRequest.objects.create(
            request_type=ApprovalRequest.TYPE_COMMAND,
            status=ApprovalRequest.STATUS_APPROVED,
            title='approved but pending runbook', command_execution=record,
        )

        response = self.client.post(
            self.endpoint(record), data=json.dumps({
                'classification': RunbookEffectivenessFeedback.CLASSIFICATION_EFFECTIVE,
            }), content_type='application/json',
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()['code'], 'validation_error')
