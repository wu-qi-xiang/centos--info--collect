import json
from datetime import timedelta
from unittest import mock

from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from RemoteLinux.models import NewLinux, User
from .models import (
    AlertEvent,
    ComplianceBaseline,
    ComplianceResult,
    DevOpsModulePermission,
    DevOpsRole,
    HostGroup,
    RunbookTemplate,
)
from .services import record_alert


class IncidentCommandCenterTests(TestCase):
    def setUp(self):
        self.user = User.objects.create(
            user='incident-operator', email='incident@example.com',
            password='plain-password', confirm_pwd='plain-password',
        )
        self.host = NewLinux.objects.create(
            linux_name='incident-host', linux_ip='127.0.0.1', linux_hostname='localhost',
            linux_port='22', linux_user='root', linux_passwd='not-used', linux_app='',
        )
        DevOpsRole.objects.create(user=self.user, role=DevOpsRole.ROLE_OPERATOR)
        for module in (
            DevOpsModulePermission.MODULE_ALERT,
            DevOpsModulePermission.MODULE_SECURITY,
            DevOpsModulePermission.MODULE_COMMAND,
        ):
            DevOpsModulePermission.objects.create(
                user=self.user, module=module, role=DevOpsRole.ROLE_OPERATOR,
            )
        group = HostGroup.objects.create(name='incident-command-center')
        group.hosts.add(self.host)
        from .models import DevOpsHostScope
        scope = DevOpsHostScope.objects.create(user=self.user)
        scope.groups.add(group)
        session = self.client.session
        session['is_login'] = True
        session['user_id'] = self.user.id
        session['user_name'] = self.user.user
        session.save()

    def test_critical_alert_creates_one_open_incident_and_updates_repeat(self):
        with mock.patch('devops.services.notify_alert'):
            alert, created = record_alert(
                self.host, 'collector', 'collector unavailable', AlertEvent.LEVEL_CRITICAL,
            )
            self.assertTrue(created)
            repeat, created = record_alert(
                self.host, 'collector', 'collector still unavailable', AlertEvent.LEVEL_CRITICAL,
            )

        self.assertFalse(created)
        self.assertEqual(alert.id, repeat.id)
        incidents = alert.incident_set.filter(status__in=['open', 'processing'])
        self.assertEqual(incidents.count(), 1)
        self.assertEqual(incidents.first().severity, 'critical')

    def test_operator_can_assign_incident_with_sla_and_append_safe_timeline(self):
        with mock.patch('devops.services.notify_alert'):
            alert, _ = record_alert(
                self.host, 'collector', 'collector unavailable', AlertEvent.LEVEL_CRITICAL,
            )
        incident = alert.incident_set.get()
        due_at = timezone.now() + timedelta(hours=2)

        response = self.client.post(
            reverse('devops:api_incident_assignment', args=[incident.id]),
            data=json.dumps({'owner': 'oncall-user', 'sla_due_at': due_at.isoformat()}),
            content_type='application/json',
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()['incident']['owner'], 'oncall-user')
        self.assertIsNotNone(response.json()['incident']['sla_due_at'])
        timeline = self.client.post(
            reverse('devops:api_incident_timeline', args=[incident.id]),
            data=json.dumps({'note': 'triage started'}), content_type='application/json',
        )
        self.assertEqual(timeline.status_code, 201)
        self.assertEqual(timeline.json()['timeline']['note'], 'triage started')

    def test_inspection_recommendation_requires_approved_runbook_and_creates_only_approval(self):
        baseline = ComplianceBaseline.objects.create(
            name='incident-baseline', baseline_type=ComplianceBaseline.TYPE_SERVICE_ACTIVE,
            service_name='sshd',
        )
        result = ComplianceResult.objects.create(
            baseline=baseline, host=self.host, state=ComplianceResult.STATE_DRIFT,
        )
        unsafe = RunbookTemplate.objects.create(
            name='unsafe', version=1, trigger_kind=RunbookTemplate.TRIGGER_ALERT,
            command_template='systemctl restart sshd', enabled=True, requires_approval=False,
        )
        unsafe.allowed_hosts.add(self.host)
        rejected = self.client.post(
            reverse('devops:api_inspection_recommendations'),
            data=json.dumps({'compliance_result_id': result.id, 'runbook_id': unsafe.id}),
            content_type='application/json',
        )
        self.assertEqual(rejected.status_code, 400)

        runbook = RunbookTemplate.objects.create(
            name='restart-sshd', version=1, trigger_kind=RunbookTemplate.TRIGGER_ALERT,
            command_template='systemctl restart sshd', enabled=True, requires_approval=True,
        )
        runbook.allowed_hosts.add(self.host)
        created = self.client.post(
            reverse('devops:api_inspection_recommendations'),
            data=json.dumps({'compliance_result_id': result.id, 'runbook_id': runbook.id, 'summary': 'restart service'}),
            content_type='application/json',
        )
        self.assertEqual(created.status_code, 201)
        recommendation = created.json()['recommendation']
        self.assertNotIn('command_template', recommendation)
        with mock.patch('devops.services.execute_command_record') as execute:
            initiated = self.client.post(
                reverse('devops:api_inspection_recommendation_initiate', args=[recommendation['id']]),
                data=json.dumps({}), content_type='application/json',
            )
        self.assertEqual(initiated.status_code, 202)
        self.assertTrue(initiated.json()['requires_approval'])
        execute.assert_not_called()
