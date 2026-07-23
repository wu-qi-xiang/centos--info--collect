import json
from unittest import mock

from django.test import TestCase
from django.urls import reverse

from RemoteLinux.models import User
from .models import DevOpsModulePermission, DevOpsRole, K8sCluster, PrometheusRuleRevision


class PrometheusRuleGovernanceTests(TestCase):
    rule_yaml = '''apiVersion: monitoring.coreos.com/v1
kind: PrometheusRule
metadata:
  name: api-errors
  namespace: monitoring
  resourceVersion: "42"
spec:
  groups: []
'''

    def setUp(self):
        self.creator = User.objects.create(user='creator', email='creator@example.com', password='x', confirm_pwd='x')
        self.reviewer = User.objects.create(user='reviewer', email='reviewer@example.com', password='x', confirm_pwd='x')
        self.publisher = User.objects.create(user='publisher', email='publisher@example.com', password='x', confirm_pwd='x')
        for user in (self.creator, self.reviewer, self.publisher):
            DevOpsRole.objects.create(user=user, role=DevOpsRole.ROLE_ADMIN)
            DevOpsModulePermission.objects.create(user=user, module=DevOpsModulePermission.MODULE_CLUSTER,
                                                   role=DevOpsRole.ROLE_ADMIN)
        self.cluster = K8sCluster.objects.create(
            name='governance-cluster', api_server='https://kubernetes.example.com:6443',
            kubeconfig='apiVersion: v1\nclusters: []\ncontexts: []\nusers: []\n',
        )

    def login(self, user):
        session = self.client.session
        session['is_login'] = True
        session['user_id'] = user.id
        session['user_name'] = user.user
        session.save()

    def update_url(self):
        return reverse('devops:api_prometheus_rule_update', args=[self.cluster.id, 'monitoring', 'api-errors'])

    def create_draft(self):
        self.login(self.creator)
        response = self.client.post(self.update_url(), data=json.dumps({'yaml': self.rule_yaml}),
                                    content_type='application/json')
        self.assertEqual(response.status_code, 202)
        return PrometheusRuleRevision.objects.get(id=response.json()['revision']['id'])

    def test_direct_update_creates_only_safe_draft(self):
        self.login(self.creator)
        with mock.patch('devops.api.replace_prometheus_rule') as replace_rule:
            response = self.client.post(self.update_url(), data=json.dumps({'yaml': self.rule_yaml}),
                                        content_type='application/json')
        self.assertEqual(response.status_code, 202)
        self.assertEqual(response.json()['revision']['status'], 'draft')
        self.assertNotIn('spec:', json.dumps(response.json()))
        replace_rule.assert_not_called()
        revision = PrometheusRuleRevision.objects.get()
        self.assertEqual(revision.desired_yaml, self.rule_yaml)

    def test_two_person_review_and_separate_publish(self):
        revision = self.create_draft()
        submit_url = reverse('devops:prometheus_rule_revision_submit', args=[revision.id])
        review_url = reverse('devops:prometheus_rule_revision_review', args=[revision.id])
        publish_url = reverse('devops:prometheus_rule_revision_publish', args=[revision.id])
        self.assertEqual(self.client.post(submit_url).status_code, 200)
        self.assertEqual(self.client.post(review_url, data=json.dumps({'decision': 'approve'}),
                                          content_type='application/json').status_code, 400)
        self.login(self.reviewer)
        with mock.patch('devops.config_governance.get_prometheus_rule') as get_rule:
            approved = self.client.post(review_url, data=json.dumps({'decision': 'approve'}),
                                        content_type='application/json')
        self.assertEqual(approved.status_code, 200)
        get_rule.assert_not_called()
        with mock.patch('devops.config_governance.get_prometheus_rule', return_value={
            'ok': True, 'rule': {'metadata': {'resourceVersion': '42'}},
        }), mock.patch('devops.config_governance.replace_prometheus_rule', return_value={'ok': True}):
            published = self.client.post(publish_url)
        self.assertEqual(published.status_code, 200)
        revision.refresh_from_db()
        self.assertEqual(revision.status, PrometheusRuleRevision.STATUS_PUBLISHED)

    def test_publish_marks_failed_when_resource_version_drifted(self):
        revision = self.create_draft()
        self.client.post(reverse('devops:prometheus_rule_revision_submit', args=[revision.id]))
        self.login(self.reviewer)
        self.client.post(reverse('devops:prometheus_rule_revision_review', args=[revision.id]),
                         data=json.dumps({'decision': 'approve'}), content_type='application/json')
        self.login(self.publisher)
        with mock.patch('devops.config_governance.get_prometheus_rule', return_value={
            'ok': True, 'rule': {'metadata': {'resourceVersion': '99'}},
        }), mock.patch('devops.config_governance.replace_prometheus_rule') as replace_rule:
            response = self.client.post(reverse('devops:prometheus_rule_revision_publish', args=[revision.id]))
        self.assertEqual(response.status_code, 409)
        replace_rule.assert_not_called()
        revision.refresh_from_db()
        self.assertEqual(revision.status, PrometheusRuleRevision.STATUS_FAILED)
        self.assertEqual(revision.failure_code, 'conflict')

    def test_delete_snapshot_restores_as_new_draft(self):
        self.login(self.creator)
        delete_url = reverse('devops:api_prometheus_rule_delete', args=[
            self.cluster.id, 'monitoring', 'api-errors',
        ])
        with mock.patch('devops.config_governance.get_prometheus_rule', return_value={
            'ok': True,
            'rule': {'metadata': {'resourceVersion': '42'}},
            'yaml': self.rule_yaml,
        }):
            response = self.client.post(delete_url, data=json.dumps({
                'confirmation': 'DELETE', 'resource_version': '42',
            }), content_type='application/json')
        self.assertEqual(response.status_code, 202)
        deleted = PrometheusRuleRevision.objects.get(id=response.json()['revision']['id'])
        self.assertEqual(deleted.action, PrometheusRuleRevision.ACTION_DELETE)
        self.assertEqual(deleted.desired_yaml, self.rule_yaml)
        deleted.status = PrometheusRuleRevision.STATUS_PUBLISHED
        deleted.save(update_fields=['status'])

        self.login(self.reviewer)
        with mock.patch('devops.config_governance.get_prometheus_rule', return_value={
            'ok': True,
            'rule': {'metadata': {'resourceVersion': '77'}},
        }):
            restored = self.client.post(reverse('devops:prometheus_rule_revision_restore', args=[deleted.id]))
        self.assertEqual(restored.status_code, 202)
        draft = PrometheusRuleRevision.objects.get(id=restored.json()['revision']['id'])
        self.assertNotEqual(draft.id, deleted.id)
        self.assertEqual(draft.status, PrometheusRuleRevision.STATUS_DRAFT)
        self.assertEqual(draft.baseline_resource_version, '77')
        self.assertIn('resourceVersion: \'77\'', draft.desired_yaml)
