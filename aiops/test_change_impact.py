from datetime import timedelta

from django.test import RequestFactory, TestCase
from django.urls import reverse
from django.utils import timezone

from RemoteLinux.models import NewLinux, User
from devops.models import (
    AlertEvent,
    AuditLog,
    CommandExecution,
    DeploymentApp,
    DeploymentHealthEvaluation,
    DeploymentRelease,
    DevOpsHostScope,
    DevOpsModulePermission,
    DevOpsRole,
    HostGroup,
    K8sCluster,
    PrometheusRuleRevision,
)

from .change_impact import build_change_impacts


class ChangeImpactTests(TestCase):
    def setUp(self):
        self.user = User.objects.create(user='impact-user', email='impact@example.com', password='pwd', confirm_pwd='pwd')
        self.host = NewLinux.objects.create(
            linux_name='impact-web', linux_ip='10.0.0.9', linux_hostname='impact-web',
            linux_port='22', linux_user='root', linux_passwd='secret', linux_app='web',
        )
        self.other_host = NewLinux.objects.create(
            linux_name='hidden-db', linux_ip='10.0.0.10', linux_hostname='hidden-db',
            linux_port='22', linux_user='root', linux_passwd='secret', linux_app='db',
        )
        session = self.client.session
        session['is_login'] = True
        session['user_id'] = self.user.id
        session['user_name'] = self.user.user
        session.save()

    def _request(self):
        request = RequestFactory().get('/aiops/')
        request.session = {
            'is_login': True,
            'user_id': self.user.id,
            'user_name': self.user.user,
        }
        return request

    def _release(self, host=None):
        app = DeploymentApp.objects.create(name='impact-app')
        release = DeploymentRelease.objects.create(
            app=app, version='2026.07.23', deploy_script='private deploy script', status=DeploymentRelease.STATUS_SUCCESS,
        )
        release.hosts.add(host or self.host)
        return release

    def _revision(self):
        cluster = K8sCluster.objects.create(name='impact-cluster', kubeconfig='private config')
        return PrometheusRuleRevision.objects.create(
            cluster=cluster, namespace='monitoring', name='impact-rule',
            action=PrometheusRuleRevision.ACTION_UPDATE, desired_yaml='private: yaml', desired_digest='a' * 64,
            status=PrometheusRuleRevision.STATUS_PUBLISHED, created_by=self.user,
            published_at=timezone.now(),
        )

    def test_builds_safe_host_scoped_evidence_without_sensitive_fields(self):
        release = self._release()
        revision = self._revision()
        AuditLog.objects.create(action='发布', target_type='DeploymentRelease', target_id=str(release.id), detail='private script')
        AuditLog.objects.create(action='发布规则', target_type='PrometheusRuleRevision', target_id=str(revision.id), detail='private yaml')
        alert = AlertEvent.objects.create(host=self.host, level='critical', metric='cpu', message='private alert message')
        command = CommandExecution.objects.create(
            host=self.host, command='private command', output='private output', error='private error',
            status=CommandExecution.STATUS_FAILED,
        )
        DevOpsRole.objects.create(user=self.user, role=DevOpsRole.ROLE_VIEWER)
        DevOpsModulePermission.objects.create(
            user=self.user, module=DevOpsModulePermission.MODULE_CLUSTER, role=DevOpsRole.ROLE_VIEWER,
        )

        before_counts = {
            'alerts': AlertEvent.objects.count(),
            'commands': CommandExecution.objects.count(),
            'deployments': DeploymentRelease.objects.count(),
            'revisions': PrometheusRuleRevision.objects.count(),
            'audits': AuditLog.objects.count(),
        }
        impacts = build_change_impacts(self._request(), [alert], [command], [self.host])

        self.assertEqual(len(impacts), 1)
        self.assertEqual(before_counts, {
            'alerts': AlertEvent.objects.count(),
            'commands': CommandExecution.objects.count(),
            'deployments': DeploymentRelease.objects.count(),
            'revisions': PrometheusRuleRevision.objects.count(),
            'audits': AuditLog.objects.count(),
        })
        rendered = repr(impacts)
        for secret in ('private deploy script', 'private yaml', 'private alert message', 'private command', 'private output', 'private error'):
            self.assertNotIn(secret, rendered)
        evidence_kinds = [item['kind'] for item in impacts[0]['evidence']]
        self.assertIn('deployment', evidence_kinds)
        self.assertIn('prometheus_rule_revision', evidence_kinds)
        self.assertIn('audit', evidence_kinds)

    def test_hides_cluster_revision_evidence_without_cluster_permission(self):
        self._release()
        self._revision()
        alert = AlertEvent.objects.create(host=self.host, metric='cpu', message='CPU')
        DevOpsRole.objects.create(user=self.user, role=DevOpsRole.ROLE_VIEWER)
        DevOpsModulePermission.objects.create(
            user=self.user, module=DevOpsModulePermission.MODULE_CLUSTER,
            role=DevOpsModulePermission.ROLE_NONE,
        )

        impacts = build_change_impacts(self._request(), [alert], [], [self.host])

        self.assertEqual(len(impacts), 1)
        self.assertNotIn('prometheus_rule_revision', [item['kind'] for item in impacts[0]['evidence']])

    def test_includes_only_safe_deployment_health_evidence(self):
        release = self._release()
        DeploymentHealthEvaluation.objects.create(
            release=release, batch_identity='host_ids=%s' % self.host.id,
            status=DeploymentHealthEvaluation.STATUS_UNHEALTHY,
            score=50,
            summary='critical_alert=1, failed_command=0, exhausted_slo=0',
            evaluated_at=timezone.now(),
        )
        alert = AlertEvent.objects.create(
            host=self.host, level='critical', metric='cpu',
            message='private alert message',
        )

        impacts = build_change_impacts(self._request(), [alert], [], [self.host])

        health = [item for item in impacts[0]['evidence'] if item['kind'] == 'deployment_health'][0]
        self.assertEqual(health['status'], DeploymentHealthEvaluation.STATUS_UNHEALTHY)
        self.assertEqual(health['score'], 50)
        self.assertNotIn('private alert message', repr(health))

    def test_uses_only_visible_hosts_and_ignores_old_changes(self):
        group = HostGroup.objects.create(name='impact-visible')
        group.hosts.add(self.host)
        scope = DevOpsHostScope.objects.create(user=self.user)
        scope.groups.add(group)
        release = self._release(self.other_host)
        old_time = timezone.now() - timedelta(hours=3)
        DeploymentRelease.objects.filter(id=release.id).update(created_at=old_time)
        hidden_alert = AlertEvent.objects.create(host=self.other_host, metric='disk', message='hidden')
        visible_alert = AlertEvent.objects.create(host=self.host, metric='cpu', message='visible')

        impacts = build_change_impacts(self._request(), [visible_alert, hidden_alert], [], [self.host])

        self.assertEqual(impacts, [])

    def test_dashboard_preserves_existing_payload_and_adds_change_impacts(self):
        self._release()
        AlertEvent.objects.create(host=self.host, metric='cpu', message='CPU')

        response = self.client.get(reverse('aiops:dashboard'))

        self.assertEqual(response.status_code, 200)
        self.assertIn('change_impacts', response.context['aiops_payload'])
        self.assertIn('change_impacts', response.context['aiops_payload']['counts'])
