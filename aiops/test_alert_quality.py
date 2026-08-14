from django.test import TestCase

from RemoteLinux.models import NewLinux
from devops.models import AlertEvent, AlertQualityFeedback
from devops.models import DevOpsModulePermission, DevOpsRole, DevOpsHostScope, HostGroup
from RemoteLinux.models import User

from .alert_quality import build_alert_quality_suggestions, build_alert_quality_governance


class AlertQualitySuggestionTests(TestCase):
    def test_repeated_noise_feedback_produces_safe_threshold_suggestion(self):
        host = NewLinux.objects.create(linux_name='quality-host', linux_ip='127.0.0.241', linux_hostname='quality-host')
        for index in range(2):
            alert = AlertEvent.objects.create(host=host, metric='cpu', message='private alert %s' % index)
            AlertQualityFeedback.objects.create(alert=alert, classification=AlertQualityFeedback.CLASSIFICATION_NOISE)

        suggestions = build_alert_quality_suggestions([host])

        self.assertEqual(suggestions[0]['metric'], 'cpu')
        self.assertEqual(suggestions[0]['action'], 'review_threshold')
        self.assertEqual(suggestions[0]['feedback_count'], 2)
        self.assertNotIn('private alert', repr(suggestions))

    def test_governance_prioritizes_repeated_feedback_without_sensitive_fields(self):
        host = NewLinux.objects.create(linux_name='governance-host', linux_ip='127.0.0.242', linux_hostname='governance-host')
        for index in range(5):
            alert = AlertEvent.objects.create(host=host, metric='latency', message='private %s' % index)
            AlertQualityFeedback.objects.create(alert=alert, classification=AlertQualityFeedback.CLASSIFICATION_NOISE)
        result = build_alert_quality_governance([host])
        self.assertEqual(result['summary']['suggestion_count'], 1)
        self.assertEqual(result['suggestions'][0]['priority'], 'critical')
        self.assertTrue(result['suggestions'][0]['review_only'])
        self.assertNotIn('private', repr(result))


class AlertQualityGovernanceApiTests(TestCase):
    def setUp(self):
        self.user = User.objects.create(user='quality-viewer', email='quality-viewer@example.com', password='pwd', confirm_pwd='pwd')
        self.host = NewLinux.objects.create(linux_name='quality-api-host', linux_ip='127.0.0.243', linux_hostname='quality-api-host')
        group = HostGroup.objects.create(name='quality-api-group')
        group.hosts.add(self.host)
        scope = DevOpsHostScope.objects.create(user=self.user)
        scope.groups.add(group)
        session = self.client.session
        session.update({'is_login': True, 'user_id': self.user.id, 'user_name': self.user.user})
        session.save()

    def test_viewer_can_read_scoped_governance(self):
        DevOpsRole.objects.create(user=self.user, role=DevOpsRole.ROLE_VIEWER)
        DevOpsModulePermission.objects.create(user=self.user, module=DevOpsModulePermission.MODULE_ALERT, role=DevOpsRole.ROLE_VIEWER)
        alert = AlertEvent.objects.create(host=self.host, metric='cpu', message='private alert')
        AlertQualityFeedback.objects.create(alert=alert, classification=AlertQualityFeedback.CLASSIFICATION_THRESHOLD)
        response = self.client.get('/aiops/api/alert-quality-governance/')
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload['summary']['threshold_count'], 1)
        self.assertNotIn('private alert', repr(payload))

    def test_without_alert_permission_is_forbidden(self):
        DevOpsModulePermission.objects.create(user=self.user, module=DevOpsModulePermission.MODULE_ALERT, role=DevOpsModulePermission.ROLE_NONE)
        response = self.client.get('/aiops/api/alert-quality-governance/')
        self.assertEqual(response.status_code, 403)
