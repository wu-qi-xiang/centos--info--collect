from unittest.mock import patch
from django.test import TestCase
from RemoteLinux.models import User, NewLinux
from devops.models import DevOpsRole, DevOpsModulePermission, ServiceCatalog, ServiceSlo, DeploymentApp, DeploymentRelease, DeploymentHealthEvaluation
from django.utils import timezone
from datetime import timedelta
from aiops.operator_mode import build_operator_scan


class OperatorScanApiTests(TestCase):
    def setUp(self):
        self.user = User.objects.create(user='operator-scan', email='scan@example.com', password='pwd', confirm_pwd='pwd')
        DevOpsRole.objects.create(user=self.user, role=DevOpsRole.ROLE_ADMIN)
        for module in (DevOpsModulePermission.MODULE_ALERT, DevOpsModulePermission.MODULE_METRIC, DevOpsModulePermission.MODULE_DEPLOYMENT, DevOpsModulePermission.MODULE_SERVICE):
            DevOpsModulePermission.objects.create(user=self.user, module=module, role=DevOpsRole.ROLE_VIEWER)
        self.host = NewLinux.objects.create(linux_name='scan-host', linux_ip='192.0.2.40', linux_port='22', linux_user='ops')
        ServiceCatalog.objects.create(name='scan-service')
        session = self.client.session
        session.update({'is_login': True, 'user_id': self.user.id})
        session.save()

    def test_auth_permission_and_safe_partial(self):
        session = self.client.session
        session.clear(); session.save()
        self.assertEqual(self.client.get('/aiops/api/operator-scan/').status_code, 401)
        session = self.client.session; session.update({'is_login': True, 'user_id': self.user.id}); session.save()
        with patch('aiops.views.build_operator_scan', return_value={'findings': [], 'counts': {}, 'partial': True, 'errors': [{'source': 'x', 'code': 'source_unavailable'}], 'recommendation': 'safe'}):
            response = self.client.get('/aiops/api/operator-scan/')
        self.assertEqual(response.status_code, 200)
        self.assertNotIn('password', repr(response.json()))

    def test_hidden_host_is_excluded_by_visible_queryset(self):
        with patch('aiops.views.visible_hosts_for_request', return_value=NewLinux.objects.none()):
            self.assertEqual(self.client.get('/aiops/api/operator-scan/').status_code, 403)

    def test_window_excludes_old_and_future_slo(self):
        service = ServiceCatalog.objects.first()
        now = timezone.now()
        ServiceSlo.objects.create(service=service, metric_kind=ServiceSlo.KIND_AVAILABILITY, target=99,
            last_state=ServiceSlo.STATE_EXHAUSTED, last_evaluated_at=now - timedelta(hours=12))
        ServiceSlo.objects.create(service=service, metric_kind=ServiceSlo.KIND_LATENCY, target=99,
            last_state=ServiceSlo.STATE_EXHAUSTED, last_evaluated_at=now + timedelta(hours=1))
        result = build_operator_scan([self.host], [service], window='6h', now=now)
        self.assertFalse(any(item['kind'] == 'slo' for item in result['findings']))

    def test_window_includes_current_slo_and_excludes_future_deployment(self):
        service = ServiceCatalog.objects.first()
        now = timezone.now()
        ServiceSlo.objects.create(service=service, metric_kind=ServiceSlo.KIND_AVAILABILITY, target=99,
            last_state=ServiceSlo.STATE_EXHAUSTED, last_evaluated_at=now - timedelta(hours=1))
        app = DeploymentApp.objects.create(name='scan-app')
        release = DeploymentRelease.objects.create(app=app, version='v1', deploy_script='private command')
        release.hosts.add(self.host)
        DeploymentHealthEvaluation.objects.create(release=release, batch_identity='scan',
            status=DeploymentHealthEvaluation.STATUS_UNHEALTHY, summary='private health', evaluated_at=now - timedelta(hours=1))
        DeploymentHealthEvaluation.objects.create(release=release, batch_identity='future',
            status=DeploymentHealthEvaluation.STATUS_UNHEALTHY, summary='future health', evaluated_at=now + timedelta(hours=1))
        result = build_operator_scan([self.host], [service], window='6h', now=now)
        kinds = [item['kind'] for item in result['findings']]
        self.assertIn('slo', kinds)
        self.assertEqual(kinds.count('deployment'), 1)
