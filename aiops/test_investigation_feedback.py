import json
from unittest.mock import patch
from datetime import timedelta
from django.test import TestCase
from django.utils import timezone
from RemoteLinux.models import User, NewLinux
from devops.models import DevOpsRole, DevOpsModulePermission, ServiceCatalog
from .models import AiopsInvestigation, AiopsInvestigationFeedback

class InvestigationFeedbackApiTests(TestCase):
    def setUp(self):
        self.user = User.objects.create(user='feedback-user', email='feedback@example.com', password='pwd', confirm_pwd='pwd')
        DevOpsRole.objects.create(user=self.user, role=DevOpsRole.ROLE_ADMIN)
        for module in (DevOpsModulePermission.MODULE_ALERT, DevOpsModulePermission.MODULE_METRIC, DevOpsModulePermission.MODULE_DEPLOYMENT, DevOpsModulePermission.MODULE_SERVICE):
            DevOpsModulePermission.objects.create(user=self.user, module=module, role=DevOpsRole.ROLE_VIEWER)
        self.host = NewLinux.objects.create(linux_name='feedback-host', linux_ip='192.0.2.60', linux_port='22', linux_user='ops')
        service = ServiceCatalog.objects.create(name='feedback-service')
        self.item = AiopsInvestigation.objects.create(title='feedback', window_key='1h', window_start=timezone.now()-timedelta(minutes=30), window_end=timezone.now())
        self.item.hosts.add(self.host); self.item.services.add(service)
        session = self.client.session; session.update({'is_login': True, 'user_id': self.user.id}); session.save()
    def test_append_post_get_and_redact(self):
        response = self.client.post('/aiops/api/investigations/%s/feedback/' % self.item.id, data=json.dumps({'classification':'effective','note':'token=secret https://private.example'}), content_type='application/json')
        self.assertEqual(response.status_code, 201); self.assertTrue(response.json()['feedback']['note_present'])
        self.item.refresh_from_db(); self.assertEqual(self.item.status, AiopsInvestigation.STATUS_OPEN); self.assertEqual(AiopsInvestigationFeedback.objects.count(), 1); self.assertNotIn('private.example', AiopsInvestigationFeedback.objects.first().note)
        self.assertEqual(self.client.get('/aiops/api/investigations/%s/feedback/' % self.item.id).status_code, 200)
    def test_hidden_scope_is_404(self):
        other = NewLinux.objects.create(linux_name='hidden', linux_ip='192.0.2.61', linux_port='22', linux_user='ops')
        self.item.hosts.set([other])
        with patch('aiops.views.visible_hosts_for_request', return_value=NewLinux.objects.filter(id=self.host.id)):
            self.assertEqual(self.client.get('/aiops/api/investigations/%s/feedback/' % self.item.id).status_code, 404)
