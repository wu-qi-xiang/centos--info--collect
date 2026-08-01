import json

from django.core.exceptions import ValidationError
from django.test import TestCase
from django.urls import reverse

from RemoteLinux.models import NewLinux, User
from .models import AlertEvent, AlertQualityFeedback, DevOpsHostScope, DevOpsModulePermission, DevOpsRole, HostGroup


class AlertQualityFeedbackTests(TestCase):
    def test_feedback_uses_bounded_classification_and_note(self):
        host = NewLinux.objects.create(
            linux_name='feedback-host', linux_ip='127.0.0.231',
            linux_hostname='feedback-host',
        )
        alert = AlertEvent.objects.create(
            host=host, metric='cpu', message='private alert message',
        )
        feedback = AlertQualityFeedback(
            alert=alert,
            classification=AlertQualityFeedback.CLASSIFICATION_NOISE,
            note='阈值过于敏感',
            created_by='operator',
        )

        feedback.full_clean()
        feedback.save()

        self.assertEqual(alert.quality_feedbacks.count(), 1)
        self.assertNotIn(alert.message, feedback.note)

    def test_feedback_rejects_unknown_classification(self):
        feedback = AlertQualityFeedback(classification='unknown', note='x')

        with self.assertRaises(ValidationError):
            feedback.full_clean()


class AlertQualityFeedbackApiTests(TestCase):
    def setUp(self):
        self.user = User.objects.create(user='feedback-operator', email='feedback@example.com', password='pwd', confirm_pwd='pwd')
        self.host = NewLinux.objects.create(linux_name='feedback-api-host', linux_ip='127.0.0.232', linux_hostname='feedback-api-host')
        self.alert = AlertEvent.objects.create(host=self.host, metric='cpu', message='private alert message')
        group = HostGroup.objects.create(name='feedback-api-hosts')
        group.hosts.add(self.host)
        scope = DevOpsHostScope.objects.create(user=self.user)
        scope.groups.add(group)
        session = self.client.session
        session.update({'is_login': True, 'user_id': self.user.id, 'user_name': self.user.user})
        session.save()

    def _url(self):
        return reverse('devops:api_alert_quality_feedback', args=[self.alert.id])

    def test_operator_can_submit_and_view_safe_feedback(self):
        DevOpsRole.objects.create(user=self.user, role=DevOpsRole.ROLE_OPERATOR)
        DevOpsModulePermission.objects.create(user=self.user, module=DevOpsModulePermission.MODULE_ALERT, role=DevOpsRole.ROLE_OPERATOR)

        response = self.client.post(self._url(), data=json.dumps({
            'classification': 'noise', 'note': '阈值过于敏感',
        }), content_type='application/json')

        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.json()['feedback']['classification'], 'noise')
        self.assertNotIn(self.alert.message, json.dumps(response.json()))
        listing = self.client.get(self._url())
        self.assertEqual(listing.status_code, 200)
        self.assertEqual(len(listing.json()['results']), 1)

    def test_viewer_cannot_submit_feedback(self):
        DevOpsRole.objects.create(user=self.user, role=DevOpsRole.ROLE_VIEWER)
        DevOpsModulePermission.objects.create(user=self.user, module=DevOpsModulePermission.MODULE_ALERT, role=DevOpsRole.ROLE_VIEWER)

        response = self.client.post(self._url(), data=json.dumps({'classification': 'valid'}), content_type='application/json')

        self.assertEqual(response.status_code, 403)
        self.assertEqual(AlertQualityFeedback.objects.count(), 0)
