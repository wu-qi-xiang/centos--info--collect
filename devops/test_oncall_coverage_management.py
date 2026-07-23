from unittest import mock

from django.test import TestCase
from django.urls import reverse

from RemoteLinux.models import User

from .models import AuditLog, DevOpsRole


class OnCallCoverageManagementTests(TestCase):
    def setUp(self):
        self.user = User.objects.create(
            user='coverage-user', email='coverage@example.com',
            password='plain-password', confirm_pwd='plain-password',
        )
        session = self.client.session
        session['is_login'] = True
        session['user_id'] = self.user.id
        session['user_name'] = self.user.user
        session.save()

    def set_security_role(self, role):
        DevOpsRole.objects.update_or_create(user=self.user, defaults={'role': role})

    def test_unauthenticated_request_is_redirected_to_login(self):
        self.client.session.flush()

        response = self.client.get(reverse('devops:oncall_coverage'))

        self.assertEqual(response.status_code, 302)
        self.assertIn('/login/', response['Location'])

    def test_viewer_and_operator_cannot_load_coverage(self):
        for role in (DevOpsRole.ROLE_VIEWER, DevOpsRole.ROLE_OPERATOR):
            self.set_security_role(role)
            response = self.client.get(reverse('devops:oncall_coverage'))
            self.assertEqual(response.status_code, 403)

    @mock.patch('devops.views.inspect_oncall_coverage')
    def test_security_admin_sees_missing_policy_risk_without_sensitive_fields(self, inspect_coverage):
        self.set_security_role(DevOpsRole.ROLE_ADMIN)
        inspect_coverage.return_value = [{
            'service_id': 1,
            'service_name': 'payments',
            'status': 'risk',
            'issues': [{'code': 'missing_policy', 'message': '缺少服务值班策略'}],
            'channel_url': 'https://example.com/private-hook',
            'secret': 'coverage-secret',
            'email': 'private@example.com',
        }]

        response = self.client.get(reverse('devops:oncall_coverage'))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'payments')
        self.assertContains(response, '缺少服务值班策略')
        self.assertNotContains(response, 'private-hook')
        self.assertNotContains(response, 'coverage-secret')
        self.assertNotContains(response, 'private@example.com')
        self.assertFalse(AuditLog.objects.exists())
        inspect_coverage.assert_called_once_with()

    @mock.patch('devops.views.inspect_oncall_coverage')
    def test_coverage_endpoint_is_get_only(self, inspect_coverage):
        self.set_security_role(DevOpsRole.ROLE_ADMIN)

        response = self.client.post(reverse('devops:oncall_coverage'))

        self.assertEqual(response.status_code, 405)
        inspect_coverage.assert_not_called()
