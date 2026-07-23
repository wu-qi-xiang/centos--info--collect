"""HTTP integration contract for the critical operations workflow.

This suite deliberately crosses the DevOps governance API and the AIOps
dashboard.  It protects the operational boundary: the dashboard may explain
recent changes but must never execute, notify, publish, roll back, or start a
runbook.
"""
import json
from unittest import mock

from django.test import TestCase
from django.urls import reverse

from RemoteLinux.models import NewLinux, User
from devops.models import (
    AlertEvent,
    BackgroundJob,
    CommandExecution,
    DeploymentApp,
    DeploymentRelease,
    DevOpsHostScope,
    DevOpsModulePermission,
    DevOpsRole,
    HostGroup,
    K8sCluster,
    NotificationLog,
    PrometheusRuleRevision,
)


RULE_YAML = '''apiVersion: monitoring.coreos.com/v1
kind: PrometheusRule
metadata:
  name: payment-errors
  namespace: monitoring
  resourceVersion: "42"
spec:
  groups: []
'''


class CriticalOperationsFlowTests(TestCase):
    def setUp(self):
        self.author = self._user('critical-author')
        self.reviewer = self._user('critical-reviewer')
        self.scoped_user = self._user('critical-scoped')
        for user in (self.author, self.reviewer):
            DevOpsRole.objects.create(user=user, role=DevOpsRole.ROLE_ADMIN)
            DevOpsModulePermission.objects.create(
                user=user,
                module=DevOpsModulePermission.MODULE_CLUSTER,
                role=DevOpsRole.ROLE_ADMIN,
            )
        DevOpsRole.objects.create(user=self.scoped_user, role=DevOpsRole.ROLE_VIEWER)
        for module in (
            DevOpsModulePermission.MODULE_ALERT,
            DevOpsModulePermission.MODULE_COMMAND,
            DevOpsModulePermission.MODULE_DEPLOYMENT,
            DevOpsModulePermission.MODULE_CLUSTER,
        ):
            DevOpsModulePermission.objects.create(
                user=self.scoped_user, module=module, role=DevOpsRole.ROLE_VIEWER,
            )

        self.cluster = K8sCluster.objects.create(
            name='critical-operations-cluster',
            api_server='https://kubernetes.example.invalid:6443',
            kubeconfig='apiVersion: v1\nclusters: []\ncontexts: []\nusers: []\n',
        )
        self.visible_host = self._host('critical-visible', '127.0.0.71')
        self.hidden_host = self._host('critical-hidden', '127.0.0.72')
        group = HostGroup.objects.create(name='critical-operations-visible')
        group.hosts.add(self.visible_host)
        scope = DevOpsHostScope.objects.create(user=self.scoped_user)
        scope.groups.add(group)

    def _user(self, username):
        return User.objects.create(
            user=username,
            email='%s@example.com' % username,
            password='test-password',
            confirm_pwd='test-password',
        )

    def _host(self, name, ip):
        return NewLinux.objects.create(
            linux_name=name,
            linux_ip=ip,
            linux_hostname=name,
            linux_port='22',
            linux_user='ops',
            linux_passwd='encrypted-by-model',
            linux_app='payments',
        )

    def _login(self, user):
        session = self.client.session
        session['is_login'] = True
        session['user_id'] = user.id
        session['user_name'] = user.user
        session.save()

    def _json_post(self, url, payload=None):
        return self.client.post(
            url,
            data=json.dumps(payload or {}),
            content_type='application/json',
        )

    def _published_revision(self):
        self._login(self.author)
        update_url = reverse(
            'devops:api_prometheus_rule_update',
            args=[self.cluster.id, 'monitoring', 'payment-errors'],
        )
        draft_response = self._json_post(update_url, {'yaml': RULE_YAML})
        self.assertEqual(draft_response.status_code, 202)
        revision_id = draft_response.json()['revision']['id']
        self.assertEqual(
            self.client.post(reverse('devops:prometheus_rule_revision_submit', args=[revision_id])).status_code,
            200,
        )
        return revision_id

    def test_different_admin_reviews_and_publishes_governed_rule(self):
        revision_id = self._published_revision()
        review_url = reverse('devops:prometheus_rule_revision_review', args=[revision_id])
        publish_url = reverse('devops:prometheus_rule_revision_publish', args=[revision_id])

        # The author may submit a revision, but cannot approve it or publish it.
        self_review = self._json_post(review_url, {'decision': 'approve'})
        self.assertEqual(self_review.status_code, 400)
        self.assertEqual(self_review.json()['code'], 'validation_error')
        self.assertEqual(self.client.post(publish_url).status_code, 400)

        self._login(self.reviewer)
        approved = self._json_post(review_url, {'decision': 'approve', 'comment': 'reviewed'})
        self.assertEqual(approved.status_code, 200)
        self.assertEqual(approved.json()['revision']['status'], 'approved')

        with mock.patch(
            'devops.config_governance.get_prometheus_rule',
            return_value={'ok': True, 'rule': {'metadata': {'resourceVersion': '42'}}},
        ) as get_rule, mock.patch(
            'devops.config_governance.replace_prometheus_rule', return_value={'ok': True},
        ) as replace_rule:
            published = self.client.post(publish_url)

        self.assertEqual(published.status_code, 200)
        self.assertEqual(published.json()['revision']['status'], 'published')
        get_rule.assert_called_once()
        replace_rule.assert_called_once()
        revision = PrometheusRuleRevision.objects.get(id=revision_id)
        self.assertEqual(revision.status, PrometheusRuleRevision.STATUS_PUBLISHED)

    def test_change_impacts_are_host_scoped_and_read_only(self):
        revision_id = self._published_revision()
        self._login(self.reviewer)
        self._json_post(
            reverse('devops:prometheus_rule_revision_review', args=[revision_id]),
            {'decision': 'approve'},
        )
        with mock.patch(
            'devops.config_governance.get_prometheus_rule',
            return_value={'ok': True, 'rule': {'metadata': {'resourceVersion': '42'}}},
        ), mock.patch('devops.config_governance.replace_prometheus_rule', return_value={'ok': True}):
            self.assertEqual(
                self.client.post(reverse('devops:prometheus_rule_revision_publish', args=[revision_id])).status_code,
                200,
            )

        AlertEvent.objects.create(
            host=self.visible_host,
            level=AlertEvent.LEVEL_CRITICAL,
            metric='http_error_rate',
            message='visible payment error alert',
            status=AlertEvent.STATUS_OPEN,
        )
        CommandExecution.objects.create(
            host=self.visible_host,
            command='systemctl status payments',
            status=CommandExecution.STATUS_FAILED,
            error='visible command failed',
        )
        AlertEvent.objects.create(
            host=self.hidden_host,
            level=AlertEvent.LEVEL_CRITICAL,
            metric='http_error_rate',
            message='hidden payment error alert',
            status=AlertEvent.STATUS_OPEN,
        )
        CommandExecution.objects.create(
            host=self.hidden_host,
            command='systemctl status payments-hidden',
            status=CommandExecution.STATUS_FAILED,
            error='hidden command failed',
        )
        app = DeploymentApp.objects.create(name='critical-payments', created_by=self.author.user)
        release = DeploymentRelease.objects.create(
            app=app,
            version='2026.07.23',
            description='visible release',
            deploy_script='not-for-dashboard',
            rollback_script='not-for-dashboard',
            status=DeploymentRelease.STATUS_SUCCESS,
            created_by=self.author.user,
        )
        release.hosts.add(self.visible_host)

        before = {
            'commands': CommandExecution.objects.count(),
            'jobs': BackgroundJob.objects.count(),
            'notifications': NotificationLog.objects.count(),
            'revisions': PrometheusRuleRevision.objects.count(),
            'release_status': release.status,
        }
        self._login(self.scoped_user)
        with mock.patch('devops.services.enqueue_background_job') as enqueue, mock.patch(
            'devops.services.send_notification_channel'
        ) as notify, mock.patch('devops.services.execute_deployment_release') as deploy, mock.patch(
            'devops.services.execute_deployment_rollback'
        ) as rollback, mock.patch('devops.services.initiate_runbook') as runbook:
            response = self.client.get(reverse('aiops:dashboard'))

        self.assertEqual(response.status_code, 200)
        payload = response.context['aiops_payload']
        self.assertIsInstance(payload['change_impacts'], list)
        self.assertEqual(payload['counts']['change_impacts'], len(payload['change_impacts']))
        serialized = json.dumps(payload['change_impacts'], ensure_ascii=False)
        self.assertIn(self.visible_host.linux_name, serialized)
        self.assertNotIn(self.hidden_host.linux_name, serialized)
        self.assertNotIn('not-for-dashboard', serialized)
        self.assertNotIn('payments-hidden', serialized)

        for item in payload['change_impacts']:
            self.assertIsInstance(item, dict)
            self.assertNotIn('yaml', item)
            self.assertNotIn('command', item)
            self.assertNotIn('deploy_script', item)
            self.assertNotIn('rollback_script', item)
            self.assertNotIn('runbook', item)

        enqueue.assert_not_called()
        notify.assert_not_called()
        deploy.assert_not_called()
        rollback.assert_not_called()
        runbook.assert_not_called()
        release.refresh_from_db()
        self.assertEqual(CommandExecution.objects.count(), before['commands'])
        self.assertEqual(BackgroundJob.objects.count(), before['jobs'])
        self.assertEqual(NotificationLog.objects.count(), before['notifications'])
        self.assertEqual(PrometheusRuleRevision.objects.count(), before['revisions'])
        self.assertEqual(release.status, before['release_status'])
