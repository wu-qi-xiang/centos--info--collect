from django.test import TestCase
from unittest import mock
from RemoteLinux.models import User, NewLinux
from devops.models import DevOpsRole, DevOpsModulePermission, AlertEvent, RunbookTemplate
from .models import AiopsRunbookRecommendation


class RunbookOutcomeApiTests(TestCase):
    def setUp(self):
        self.user = User.objects.create(user='outcome-user', email='outcome@example.com', password='pwd', confirm_pwd='pwd')
        DevOpsRole.objects.create(user=self.user, role=DevOpsRole.ROLE_ADMIN)
        DevOpsModulePermission.objects.create(user=self.user, module=DevOpsModulePermission.MODULE_COMMAND, role=DevOpsRole.ROLE_VIEWER)
        self.host = NewLinux.objects.create(linux_name='outcome-host', linux_ip='192.0.2.50', linux_port='22', linux_user='ops')
        alert = AlertEvent.objects.create(host=self.host, metric='cpu', message='private alert')
        runbook = RunbookTemplate.objects.create(name='safe-book', version=1, command_template='private command', requires_approval=True, enabled=True)
        runbook.allowed_hosts.add(self.host)
        self.item = AiopsRunbookRecommendation.objects.create(alert=alert, host=self.host, runbook=runbook)
        session = self.client.session; session.update({'is_login': True, 'user_id': self.user.id}); session.save()

    def test_unsubmitted_is_empty_and_safe(self):
        response = self.client.get('/aiops/api/runbook-recommendations/%s/outcome/' % self.item.id)
        self.assertEqual(response.status_code, 200)
        payload = response.json()['outcome']
        self.assertIsNone(payload['approval']); self.assertEqual(payload['effectiveness_feedback'], [])
        self.assertNotIn('private', repr(payload))

    def test_hidden_recommendation_is_not_found(self):
        with mock.patch('aiops.views.visible_hosts_for_request', return_value=NewLinux.objects.none()):
            response = self.client.get('/aiops/api/runbook-recommendations/%s/outcome/' % self.item.id)
        self.assertEqual(response.status_code, 404)
