import json
from datetime import timedelta
from unittest import mock

from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from RemoteLinux.models import NewLinux, User
from .models import (
    AlertEvent,
    ApprovalRequest,
    AuditLog,
    BackgroundJob,
    CIDelivery,
    CommandExecution,
    ComplianceBaseline,
    ComplianceResult,
    DeploymentApp,
    DeploymentHealthEvaluation,
    DeploymentRelease,
    DevOpsModulePermission,
    DevOpsRole,
    HostGroup,
    Incident,
    IncidentActionItem,
    RunbookTemplate,
    ServiceCatalog,
    ServiceSlo,
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

    def test_command_center_returns_only_scoped_safe_aggregates(self):
        hidden_host = NewLinux.objects.create(
            linux_name='hidden-command-center', linux_ip='127.0.0.8',
            linux_hostname='hidden-command-center', linux_port='22', linux_user='root',
        )
        service = ServiceCatalog.objects.create(name='command-center-service')
        service.hosts.add(self.host)
        ServiceSlo.objects.create(
            service=service, metric_kind=ServiceSlo.KIND_AVAILABILITY,
            target=99, last_state=ServiceSlo.STATE_EXHAUSTED,
        )
        visible_alert = AlertEvent.objects.create(
            host=self.host, metric='cpu', level=AlertEvent.LEVEL_CRITICAL,
            status=AlertEvent.STATUS_OPEN, message='private visible alert body',
        )
        AlertEvent.objects.create(
            host=hidden_host, metric='memory', level=AlertEvent.LEVEL_CRITICAL,
            status=AlertEvent.STATUS_OPEN, message='private hidden alert body',
        )
        incident = Incident.objects.create(
            host=self.host, alert=visible_alert, title='private incident title',
            severity=Incident.SEVERITY_CRITICAL, status=Incident.STATUS_OPEN,
        )
        IncidentActionItem.objects.create(
            incident=incident, title='private action item',
            status=IncidentActionItem.STATUS_OPEN, due_at=timezone.now() - timedelta(minutes=1),
        )
        app = DeploymentApp.objects.create(name='command-center-app')
        visible_release = DeploymentRelease.objects.create(
            app=app, version='private-version', deploy_script='private script',
            status=DeploymentRelease.STATUS_RUNNING,
        )
        visible_release.hosts.add(self.host)
        DeploymentHealthEvaluation.objects.create(
            release=visible_release, batch_identity='host_ids=%s' % self.host.id,
            status=DeploymentHealthEvaluation.STATUS_UNHEALTHY, score=0,
            summary='private health summary', evaluated_at=timezone.now(),
        )
        CIDelivery.objects.create(
            provider=CIDelivery.PROVIDER_JENKINS, repository='private/repository',
            delivery_id='private-delivery', fingerprint='c' * 64, status='failed',
            revision='private-revision', summary='private CI summary', release=visible_release,
        )
        mixed_release = DeploymentRelease.objects.create(
            app=app, version='private-hidden-version', deploy_script='private script',
        )
        mixed_release.hosts.add(self.host, hidden_host)
        DeploymentHealthEvaluation.objects.create(
            release=mixed_release, batch_identity='host_ids=%s,%s' % (self.host.id, hidden_host.id),
            status=DeploymentHealthEvaluation.STATUS_UNHEALTHY, score=0,
            summary='private mixed health summary', evaluated_at=timezone.now(),
        )
        ApprovalRequest.objects.create(
            request_type=ApprovalRequest.TYPE_DEPLOYMENT,
            status=ApprovalRequest.STATUS_PENDING,
            title='private visible approval', deployment_release=visible_release,
        )
        ApprovalRequest.objects.create(
            request_type=ApprovalRequest.TYPE_DEPLOYMENT,
            status=ApprovalRequest.STATUS_PENDING,
            title='private mixed approval', deployment_release=mixed_release,
        )

        response = self.client.get(reverse('devops:api_incident_command_center'))

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload['counts'], {
            'active_alerts': 1,
            'open_incidents': 1,
            'critical_incidents': 1,
            'unhealthy_releases': 1,
            'exhausted_slos': 1,
            'pending_approvals': 1,
            'failed_ci_deliveries': 1,
        })
        self.assertEqual(payload['action_items'], {'open': 1, 'in_progress': 0, 'overdue': 1})
        self.assertTrue(payload['timeline'])
        self.assertNotIn('private', repr(payload))
        self.assertEqual(
            set(payload['timeline'][0]),
            {'kind', 'id', 'status', 'severity', 'occurred_at'},
        )

    def test_command_center_timeline_is_bounded_chronological_and_repeatable(self):
        now = timezone.now().replace(microsecond=0)
        expected_alert_ids = []
        for offset in range(14):
            alert = AlertEvent.objects.create(
                host=self.host,
                metric='timeline-%s' % offset,
                level=AlertEvent.LEVEL_WARNING,
                status=AlertEvent.STATUS_OPEN,
                message='timeline sentinel',
            )
            AlertEvent.objects.filter(id=alert.id).update(
                updated_at=now - timedelta(minutes=offset),
            )
            expected_alert_ids.append(alert.id)

        first = self.client.get(reverse('devops:api_incident_command_center'))
        second = self.client.get(reverse('devops:api_incident_command_center'))

        self.assertEqual(first.status_code, 200)
        self.assertEqual(second.status_code, 200)
        first_timeline = first.json()['timeline']
        self.assertLessEqual(len(first_timeline), 12)
        self.assertEqual(first_timeline, second.json()['timeline'])
        self.assertEqual(
            [item['id'] for item in first_timeline], expected_alert_ids[:12],
        )
        self.assertEqual(
            [item['occurred_at'] for item in first_timeline],
            sorted((item['occurred_at'] for item in first_timeline), reverse=True),
        )

    def test_command_center_get_does_not_create_audit_jobs_or_commands(self):
        before = {
            'audit': AuditLog.objects.count(),
            'jobs': BackgroundJob.objects.count(),
            'commands': CommandExecution.objects.count(),
        }

        response = self.client.get(reverse('devops:api_incident_command_center'))

        self.assertEqual(response.status_code, 200)
        self.assertEqual(before, {
            'audit': AuditLog.objects.count(),
            'jobs': BackgroundJob.objects.count(),
            'commands': CommandExecution.objects.count(),
        })

    def test_command_center_excludes_unscoped_release_and_standalone_approval(self):
        app = DeploymentApp.objects.create(name='unscoped-command-center-app')
        release = DeploymentRelease.objects.create(
            app=app,
            version='unscoped-version',
            deploy_script='unscoped script',
            status=DeploymentRelease.STATUS_FAILED,
        )
        DeploymentHealthEvaluation.objects.create(
            release=release,
            batch_identity='unscoped',
            status=DeploymentHealthEvaluation.STATUS_UNHEALTHY,
            score=0,
            summary='unscoped health summary',
            evaluated_at=timezone.now(),
        )
        delivery = CIDelivery.objects.create(
            provider=CIDelivery.PROVIDER_JENKINS,
            repository='unscoped/repository',
            delivery_id='unscoped-delivery',
            fingerprint='d' * 64,
            status='failed',
            revision='unscoped-revision',
            summary='unscoped CI summary',
            release=release,
        )
        approval = ApprovalRequest.objects.create(
            request_type=ApprovalRequest.TYPE_DEPLOYMENT,
            status=ApprovalRequest.STATUS_PENDING,
            title='unscoped standalone approval',
        )

        response = self.client.get(reverse('devops:api_incident_command_center'))

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload['counts']['unhealthy_releases'], 0)
        self.assertEqual(payload['counts']['failed_ci_deliveries'], 0)
        self.assertEqual(payload['counts']['pending_approvals'], 0)
        self.assertNotIn(release.id, [item['id'] for item in payload['timeline']])
        self.assertNotIn(delivery.id, [item['id'] for item in payload['timeline']])
        self.assertNotIn(approval.id, [item['id'] for item in payload['timeline']])

    def test_command_center_requires_alert_viewer_permission_and_session(self):
        self.client.logout()
        unauthenticated = self.client.get(reverse('devops:api_incident_command_center'))
        self.assertEqual(unauthenticated.status_code, 401)
        self.assertEqual(unauthenticated.json()['code'], 'unauthorized')

        session = self.client.session
        session['is_login'] = True
        session['user_id'] = self.user.id
        session['user_name'] = self.user.user
        session.save()
        DevOpsModulePermission.objects.filter(
            user=self.user, module=DevOpsModulePermission.MODULE_ALERT,
        ).update(role=DevOpsModulePermission.ROLE_NONE)

        forbidden = self.client.get(reverse('devops:api_incident_command_center'))
        self.assertEqual(forbidden.status_code, 403)
        self.assertEqual(forbidden.json()['code'], 'forbidden')
