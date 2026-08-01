import json
from unittest import mock

from django.test import TestCase
from django.urls import reverse

from RemoteLinux.models import User
from .config_governance import create_prometheus_rule_draft
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

    def test_three_person_review_and_publish_separation(self):
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

        with mock.patch('devops.config_governance.get_prometheus_rule') as get_rule, \
                mock.patch('devops.config_governance.replace_prometheus_rule') as replace_rule:
            reviewer_publish = self.client.post(publish_url)
        self.assertEqual(reviewer_publish.status_code, 400)
        self.assertEqual(reviewer_publish.json()['code'], 'validation_error')
        get_rule.assert_not_called()
        replace_rule.assert_not_called()

        self.login(self.publisher)
        with mock.patch('devops.config_governance.get_prometheus_rule', return_value={
            'ok': True, 'rule': {'metadata': {'resourceVersion': '42'}},
        }), mock.patch('devops.config_governance.replace_prometheus_rule', return_value={'ok': True}):
            published = self.client.post(publish_url)
        self.assertEqual(published.status_code, 200)
        revision.refresh_from_db()
        self.assertEqual(revision.status, PrometheusRuleRevision.STATUS_PUBLISHED)

    def test_new_rule_create_revision_publishes_once_after_three_person_flow(self):
        create_yaml = self.rule_yaml.replace('  resourceVersion: "42"\n', '')
        draft = create_prometheus_rule_draft(
            None, self.cluster, create_yaml,
            action=PrometheusRuleRevision.ACTION_CREATE, actor=self.creator,
        )
        self.assertTrue(draft['ok'])
        revision = PrometheusRuleRevision.objects.get(id=draft['revision']['id'])

        self.login(self.creator)
        self.assertEqual(
            self.client.post(reverse('devops:prometheus_rule_revision_submit', args=[revision.id])).status_code,
            200,
        )
        self.login(self.reviewer)
        self.assertEqual(
            self.client.post(
                reverse('devops:prometheus_rule_revision_review', args=[revision.id]),
                data=json.dumps({'decision': 'approve'}), content_type='application/json',
            ).status_code,
            200,
        )
        self.login(self.publisher)
        with mock.patch('devops.config_governance.get_prometheus_rule', return_value={
            'ok': False, 'code': 'crd_not_found',
        }), mock.patch('devops.config_governance.create_prometheus_rule', return_value={'ok': True}) as create_rule:
            published = self.client.post(
                reverse('devops:prometheus_rule_revision_publish', args=[revision.id]),
            )

        self.assertEqual(published.status_code, 200)
        create_rule.assert_called_once_with(self.cluster, create_yaml)
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

    def test_revision_page_hides_publish_action_from_reviewer(self):
        revision = self.create_draft()
        self.client.post(reverse('devops:prometheus_rule_revision_submit', args=[revision.id]))
        self.login(self.reviewer)
        self.client.post(reverse('devops:prometheus_rule_revision_review', args=[revision.id]),
                         data=json.dumps({'decision': 'approve'}), content_type='application/json')

        revision_page = reverse('devops:prometheus_rule_revisions') + '?cluster={}'.format(self.cluster.id)
        reviewer_response = self.client.get(revision_page)
        self.assertEqual(reviewer_response.status_code, 200)
        self.assertNotContains(reviewer_response, 'data-action="publish"')

        self.login(self.publisher)
        publisher_response = self.client.get(revision_page)
        self.assertContains(publisher_response, 'data-action="publish"')

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
