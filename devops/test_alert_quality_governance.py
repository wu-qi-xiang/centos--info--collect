import json

from django.test import TestCase
from django.urls import reverse

from RemoteLinux.models import NewLinux, User
from aiops.alert_quality import alert_quality_suggestion_key
from .models import (
    AlertEvent,
    AlertQualityFeedback,
    AlertQualityGovernanceReview,
    DevOpsHostScope,
    DevOpsModulePermission,
    DevOpsRole,
    HostGroup,
)


class AlertQualityGovernanceReviewApiTests(TestCase):
    def setUp(self):
        self.user = User.objects.create(
            user='governance-operator', email='governance@example.com',
            password='pwd', confirm_pwd='pwd',
        )
        self.host = NewLinux.objects.create(
            linux_name='governance-host', linux_ip='127.0.0.244',
            linux_hostname='governance-host',
        )
        group = HostGroup.objects.create(name='governance-hosts')
        group.hosts.add(self.host)
        scope = DevOpsHostScope.objects.create(user=self.user)
        scope.groups.add(group)
        session = self.client.session
        session.update({'is_login': True, 'user_id': self.user.id, 'user_name': self.user.user})
        session.save()

    def _grant(self, role):
        DevOpsRole.objects.create(user=self.user, role=role)
        DevOpsModulePermission.objects.create(
            user=self.user,
            module=DevOpsModulePermission.MODULE_ALERT,
            role=role,
        )

    def _suggestion_key(self):
        alert = AlertEvent.objects.create(host=self.host, metric='cpu', message='private alert')
        AlertQualityFeedback.objects.create(
            alert=alert, classification=AlertQualityFeedback.CLASSIFICATION_THRESHOLD,
        )
        return alert_quality_suggestion_key('cpu', 'threshold', 'review_threshold')

    def _review_url(self, suggestion_key):
        return reverse('devops:api_alert_quality_governance_review', args=[suggestion_key])

    def test_viewer_can_list_scoped_review_without_private_note(self):
        self._grant(DevOpsRole.ROLE_VIEWER)
        suggestion_key = self._suggestion_key()
        AlertQualityGovernanceReview.objects.create(
            suggestion_key=suggestion_key,
            metric='cpu', classification='threshold', action='review_threshold',
            review_note='private reviewer note',
        )

        response = self.client.get(reverse('devops:api_alert_quality_governance_reviews'))

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(len(payload['results']), 1)
        self.assertEqual(payload['results'][0]['review']['status'], 'open')
        self.assertTrue(payload['results'][0]['review']['review_note_present'])
        self.assertNotIn('private reviewer note', json.dumps(payload))
        self.assertNotIn('private alert', json.dumps(payload))

    def test_aiops_governance_payload_includes_safe_review_state(self):
        self._grant(DevOpsRole.ROLE_VIEWER)
        suggestion_key = self._suggestion_key()
        AlertQualityGovernanceReview.objects.create(
            suggestion_key=suggestion_key,
            metric='cpu', classification='threshold', action='review_threshold',
            review_note='private reviewer note',
        )

        response = self.client.get('/aiops/api/alert-quality-governance/')

        self.assertEqual(response.status_code, 200)
        suggestion = response.json()['suggestions'][0]
        self.assertEqual(suggestion['review']['status'], 'open')
        self.assertTrue(suggestion['review']['review_note_present'])
        self.assertNotIn('private reviewer note', json.dumps(response.json()))

    def test_read_only_list_does_not_create_review_record(self):
        self._grant(DevOpsRole.ROLE_VIEWER)
        self._suggestion_key()

        response = self.client.get(reverse('devops:api_alert_quality_governance_reviews'))

        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.json()['results']), 1)
        self.assertEqual(AlertQualityGovernanceReview.objects.count(), 0)

    def test_operator_can_review_visible_suggestion_idempotently(self):
        self._grant(DevOpsRole.ROLE_OPERATOR)
        suggestion_key = self._suggestion_key()

        response = self.client.post(
            self._review_url(suggestion_key),
            data=json.dumps({'status': 'accepted', 'review_note': 'ready for rule review'}),
            content_type='application/json',
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()['review']['status'], 'accepted')
        self.assertTrue(response.json()['review']['review_note_present'])
        self.assertEqual(AlertQualityGovernanceReview.objects.count(), 1)

        repeated = self.client.post(
            self._review_url(suggestion_key),
            data=json.dumps({'status': 'accepted'}), content_type='application/json',
        )
        self.assertEqual(repeated.status_code, 200)
        self.assertEqual(repeated.json()['code'], 'idempotent')

    def test_viewer_cannot_review_and_out_of_scope_key_is_hidden(self):
        self._grant(DevOpsRole.ROLE_VIEWER)
        suggestion_key = self._suggestion_key()

        response = self.client.post(
            self._review_url(suggestion_key), data=json.dumps({'status': 'rejected'}),
            content_type='application/json',
        )
        self.assertEqual(response.status_code, 403)

        DevOpsModulePermission.objects.filter(user=self.user).update(role=DevOpsRole.ROLE_OPERATOR)
        response = self.client.post(
            self._review_url('0' * 64), data=json.dumps({'status': 'accepted'}),
            content_type='application/json',
        )
        self.assertEqual(response.status_code, 404)
