from django.core.files.uploadedfile import SimpleUploadedFile
from django.core.files.base import ContentFile
from django.core.management import call_command
from django.core.cache import cache, caches
from django.core.cache.backends.filebased import FileBasedCache
from django.test import TestCase, override_settings
from django.urls import reverse
from io import StringIO
import json
import os
import shutil
import socket
import tempfile
import types
try:
    from unittest import mock
except ImportError:
    import mock

from RemoteLinux.models import NewLinux, User
from django.utils import timezone

from .models import (
    AlertEvent,
    AlertHistory,
    AlertSilence,
    ApprovalRequest,
    AuditLog,
    BatchTask,
    BatchTaskResult,
    CommandExecution,
    DeploymentApp,
    DeploymentRelease,
    DeploymentResult,
    DevOpsHostScope,
    DevOpsModulePermission,
    DevOpsSetting,
    DevOpsRole,
    FileDistribution,
    FileDistributionResult,
    HostGroup,
    HostTag,
    K8sCluster,
    MetricSample,
    NotificationChannel,
    NotificationLog,
    ServiceOperation,
    ComplianceBaseline,
    ComplianceResult,
)
from .services import cleanup_audit_logs, cleanup_metric_samples, deployment_risk_preview, enqueue_background_job, latest_metric_map, record_alert, record_metric_sample, run_background_job, send_notification_channel, validate_remote_path, scan_compliance_baseline
from .services import execute_batch_task, execute_command_record, execute_deployment_release, execute_deployment_rollback, execute_file_distribution
from .services import COMMAND_ALLOWED, COMMAND_BLOCKED, evaluate_command_policy
from .services import (
    build_k8s_resource_matches,
    k8s_detail_cache_key,
    load_cached_k8s_cluster_detail,
    load_cached_k8s_node_detail,
    load_k8s_node_detail,
    load_k8s_namespaces,
    summarize_k8s_nodes,
    test_k8s_cluster_connection,
)


def close_test_caches():
    for backend in caches.all():
        backend.close()


class K8sClusterTests(TestCase):
    secret = '''apiVersion: v1
clusters:
- name: secret-cluster
  cluster:
    server: https://kubernetes.example.com:6443
contexts:
- name: secret-context
  context:
    cluster: secret-cluster
    namespace: operations
current-context: secret-context
users:
- name: secret-user
  user:
    token: never-render-this
'''

    @classmethod
    def setUpClass(cls):
        cls.k8s_cache_dir = tempfile.mkdtemp(prefix='devops-k8s-test-cache-')
        cls.k8s_cache_override = override_settings(CACHES={
            'default': {
                'BACKEND': 'django.core.cache.backends.filebased.FileBasedCache',
                'LOCATION': cls.k8s_cache_dir,
                'TIMEOUT': 86400,
            },
        })
        cls.k8s_cache_override.enable()
        close_test_caches()
        try:
            super(K8sClusterTests, cls).setUpClass()
        except Exception:
            close_test_caches()
            cls.k8s_cache_override.disable()
            shutil.rmtree(cls.k8s_cache_dir, ignore_errors=True)
            raise

    @classmethod
    def tearDownClass(cls):
        try:
            super(K8sClusterTests, cls).tearDownClass()
        finally:
            close_test_caches()
            cls.k8s_cache_override.disable()
            shutil.rmtree(cls.k8s_cache_dir, ignore_errors=True)
            close_test_caches()

    def setUp(self):
        self.user = User.objects.create(
            user='cluster-admin',
            email='cluster-admin@example.com',
            password='plain-password',
            confirm_pwd='plain-password',
        )
        DevOpsRole.objects.create(user=self.user, role=DevOpsRole.ROLE_ADMIN)
        session = self.client.session
        session['is_login'] = True
        session['user_id'] = self.user.id
        session['user_name'] = self.user.user
        session.save()

    def create_cluster(self, name='cluster-one'):
        return K8sCluster.objects.create(
            name=name,
            api_server='https://kubernetes.example.com:6443',
            default_namespace='default',
            kubeconfig=self.secret,
            created_by=self.user.user,
        )

    def kubeconfig_upload(self, content=None, name='config'):
        if content is None:
            content = self.secret
        if isinstance(content, str):
            content = content.encode('utf-8')
        return SimpleUploadedFile(name, content, content_type='application/yaml')

    def test_model_encrypts_kubeconfig_without_double_encryption(self):
        cluster = self.create_cluster()
        stored = K8sCluster.objects.get(id=cluster.id)

        self.assertTrue(stored.kubeconfig.startswith('enc:'))
        self.assertNotEqual(stored.kubeconfig, self.secret)
        self.assertEqual(stored.decrypted_kubeconfig, self.secret)
        encrypted = stored.kubeconfig
        stored.save()
        stored.refresh_from_db()
        self.assertEqual(stored.kubeconfig, encrypted)

    def test_cluster_management_and_list_require_login_and_viewer_permission(self):
        cluster = self.create_cluster()
        DevOpsModulePermission.objects.create(
            user=self.user,
            module=DevOpsModulePermission.MODULE_CLUSTER,
            role=DevOpsRole.ROLE_VIEWER,
        )

        response = self.client.get(reverse('devops:clusters'))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'devops/cluster_management.html')
        self.assertEqual(response.context['cluster_count'], 1)
        self.assertEqual(response.context['online_count'], 0)
        self.assertEqual(response.context['offline_count'], 0)
        self.assertEqual(response.context['unknown_count'], 1)
        self.assertFalse(response.context['can_manage'])
        cluster_list = self.client.get(reverse('devops:cluster_list'))
        self.assertEqual(cluster_list.status_code, 200)
        self.assertTemplateUsed(cluster_list, 'devops/cluster_list.html')
        self.assertContains(cluster_list, cluster.name)
        self.assertNotContains(cluster_list, self.secret)
        self.assertNotContains(cluster_list, cluster.kubeconfig)
        self.assertNotContains(cluster_list, reverse('devops:cluster_create'))
        self.assertNotContains(cluster_list, reverse('devops:cluster_update', args=[cluster.id]))
        self.assertNotContains(cluster_list, reverse('devops:cluster_test', args=[cluster.id]))
        self.assertNotContains(cluster_list, reverse('devops:cluster_delete', args=[cluster.id]))
        self.assertNotContains(cluster_list, '<textarea')
        self.assertNotContains(response, self.secret)
        self.assertNotContains(response, cluster.kubeconfig)
        self.assertEqual(self.client.post(reverse('devops:clusters')).status_code, 405)

        connect_denied = self.client.get(reverse('devops:cluster_connect'))
        self.assertEqual(connect_denied.status_code, 403)

        denied = self.client.post(reverse('devops:cluster_create'), {
            'name': 'denied',
            'kubeconfig_file': self.kubeconfig_upload(),
        })
        self.assertEqual(denied.status_code, 403)
        self.client.session.flush()
        login = self.client.get(reverse('devops:clusters'))
        self.assertEqual(login.status_code, 302)
        self.assertEqual(self.client.get(reverse('devops:cluster_list')).status_code, 302)
        self.assertEqual(self.client.get(reverse('devops:cluster_connect')).status_code, 302)

    def test_cluster_connect_uses_blank_form_and_does_not_render_saved_secret(self):
        cluster = self.create_cluster()

        response = self.client.get(reverse('devops:cluster_connect'))

        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'devops/cluster_connection.html')
        self.assertFalse(response.context['form'].instance.pk)
        self.assertEqual(
            [field.name for field in response.context['form'].visible_fields()],
            ['name', 'kubeconfig_file'],
        )
        self.assertTrue(response.context['can_manage'])
        self.assertNotContains(response, self.secret)
        self.assertNotContains(response, cluster.kubeconfig)
        self.assertEqual(self.client.post(reverse('devops:cluster_connect')).status_code, 405)
        self.assertEqual(self.client.post(reverse('devops:cluster_list')).status_code, 405)

    def test_legacy_cluster_list_route_renders_actual_list(self):
        cluster = self.create_cluster()

        response = self.client.get(reverse('devops:k8s_cluster_list'))

        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'devops/cluster_list.html')
        self.assertContains(response, cluster.name)
        self.assertNotContains(response, self.secret)

    def test_initial_admin_has_admin_role_and_can_manage_clusters(self):
        admin = User.objects.get(user='admin')
        self.assertEqual(DevOpsRole.objects.get(user=admin).role, DevOpsRole.ROLE_ADMIN)
        session = self.client.session
        session['is_login'] = True
        session['user_id'] = admin.id
        session['user_name'] = admin.user
        session.save()

        page = self.client.get(reverse('devops:clusters'))
        self.assertEqual(page.status_code, 200)
        self.assertContains(page, reverse('devops:cluster_connect'))
        connect = self.client.get(reverse('devops:cluster_connect'))
        self.assertEqual(connect.status_code, 200)
        self.assertContains(connect, reverse('devops:cluster_create'))
        create = self.client.post(reverse('devops:cluster_create'), {
            'name': 'initial-admin-cluster',
            'kubeconfig_file': self.kubeconfig_upload(),
        })
        self.assertEqual(create.status_code, 302)
        self.assertEqual(create.url, reverse('devops:cluster_list'))
        self.assertTrue(K8sCluster.objects.filter(name='initial-admin-cluster').exists())

    def test_invalid_create_renders_connection_page_without_saving(self):
        response = self.client.post(reverse('devops:cluster_create'), {
            'name': 'invalid-cluster',
        })

        self.assertEqual(response.status_code, 400)
        self.assertTemplateUsed(response, 'devops/cluster_connection.html')
        self.assertContains(response, 'Kubeconfig', status_code=400)
        self.assertFalse(K8sCluster.objects.filter(name='invalid-cluster').exists())

    def test_invalid_create_does_not_echo_submitted_or_stored_kubeconfig(self):
        existing = self.create_cluster(name='duplicate-cluster')
        submitted_secret = 'apiVersion: v1\ntoken: submitted-secret-must-not-render\n'

        response = self.client.post(reverse('devops:cluster_create'), {
            'name': existing.name,
            'kubeconfig_file': self.kubeconfig_upload(submitted_secret),
        })

        self.assertEqual(response.status_code, 400)
        self.assertTemplateUsed(response, 'devops/cluster_connection.html')
        self.assertNotContains(response, submitted_secret, status_code=400)
        self.assertNotContains(response, 'submitted-secret-must-not-render', status_code=400)
        self.assertNotContains(response, existing.kubeconfig, status_code=400)
        self.assertEqual(K8sCluster.objects.filter(name=existing.name).count(), 1)

    def test_cluster_crud_and_blank_update_preserves_secret(self):
        create = self.client.post(reverse('devops:cluster_create'), {
            'name': 'created-cluster',
            'kubeconfig_file': self.kubeconfig_upload(),
        })
        self.assertEqual(create.status_code, 302)
        self.assertEqual(create.url, reverse('devops:cluster_list'))
        cluster = K8sCluster.objects.get(name='created-cluster')
        self.assertEqual(cluster.api_server, 'https://kubernetes.example.com:6443')
        self.assertEqual(cluster.default_namespace, 'operations')
        self.assertTrue(cluster.kubeconfig.startswith('enc:'))
        self.assertEqual(cluster.decrypted_kubeconfig, self.secret)
        cluster_list = self.client.get(reverse('devops:cluster_list'))
        self.assertContains(cluster_list, cluster.name)
        self.assertNotContains(cluster_list, self.secret)
        encrypted = cluster.kubeconfig

        update = self.client.post(reverse('devops:cluster_update', args=[cluster.id]), {
            'name': 'updated-cluster',
            'api_server': 'https://updated.example.com:6443',
            'default_namespace': 'platform',
            'kubeconfig': '',
        })
        self.assertEqual(update.status_code, 302)
        self.assertEqual(update.url, reverse('devops:cluster_list'))
        cluster.refresh_from_db()
        self.assertEqual(cluster.name, 'updated-cluster')
        self.assertEqual(cluster.kubeconfig, encrypted)
        self.assertEqual(cluster.decrypted_kubeconfig, self.secret)

        invalid = self.client.post(reverse('devops:cluster_update', args=[cluster.id]), {
            'name': '',
            'api_server': cluster.api_server,
            'default_namespace': cluster.default_namespace,
            'kubeconfig': '',
        })
        self.assertEqual(invalid.status_code, 400)
        self.assertTemplateUsed(invalid, 'devops/cluster_list.html')
        self.assertEqual(invalid.context['editing_cluster'], cluster)
        self.assertTrue(invalid.context['form'].errors)
        cluster.refresh_from_db()
        self.assertEqual(cluster.name, 'updated-cluster')

        audit_text = '\n'.join(AuditLog.objects.values_list('detail', flat=True))
        self.assertNotIn(self.secret, audit_text)
        self.assertNotIn(encrypted, audit_text)
        self.assertEqual(self.client.get(reverse('devops:cluster_create')).status_code, 405)
        self.assertEqual(self.client.get(reverse('devops:cluster_update', args=[cluster.id])).status_code, 405)
        self.assertEqual(self.client.get(reverse('devops:cluster_test', args=[cluster.id])).status_code, 405)
        self.assertEqual(self.client.get(reverse('devops:cluster_delete', args=[cluster.id])).status_code, 405)
        delete = self.client.post(reverse('devops:cluster_delete', args=[cluster.id]))
        self.assertEqual(delete.status_code, 302)
        self.assertEqual(delete.url, reverse('devops:cluster_list'))
        self.assertFalse(K8sCluster.objects.filter(id=cluster.id).exists())

    def test_create_accepts_extensionless_file_and_uses_context_namespace_fallbacks(self):
        content = '''apiVersion: v1
clusters:
- name: fallback-cluster
  cluster:
    server: http://127.0.0.1:8080
contexts:
- name: fallback-context
  context:
    cluster: fallback-cluster
'''
        response = self.client.post(reverse('devops:cluster_create'), {
            'name': 'fallback-cluster',
            'kubeconfig_file': self.kubeconfig_upload(content, name='config'),
        })

        self.assertEqual(response.status_code, 302)
        cluster = K8sCluster.objects.get(name='fallback-cluster')
        self.assertEqual(cluster.api_server, 'http://127.0.0.1:8080')
        self.assertEqual(cluster.default_namespace, 'default')
        self.assertEqual(cluster.decrypted_kubeconfig, content)

    def test_create_accepts_utf8_bom_and_normalizes_namespace(self):
        content = self.secret.replace('namespace: operations', 'namespace: Platform')
        response = self.client.post(reverse('devops:cluster_create'), {
            'name': 'bom-cluster',
            'kubeconfig_file': self.kubeconfig_upload(b'\xef\xbb\xbf' + content.encode('utf-8')),
        })

        self.assertEqual(response.status_code, 302)
        cluster = K8sCluster.objects.get(name='bom-cluster')
        self.assertEqual(cluster.default_namespace, 'platform')
        self.assertEqual(cluster.decrypted_kubeconfig, content)

    def test_create_rejects_oversize_invalid_encoding_and_malformed_yaml(self):
        cases = (
            ('oversize', b'a' * (1024 * 1024 + 1), '1 MiB'),
            ('encoding', b'\xff\xfe\x00', 'UTF-8'),
            ('yaml', b'clusters: [unterminated', '格式无效'),
        )
        for name, content, error in cases:
            with self.subTest(name=name):
                response = self.client.post(reverse('devops:cluster_create'), {
                    'name': name,
                    'kubeconfig_file': self.kubeconfig_upload(content),
                })
                self.assertEqual(response.status_code, 400)
                self.assertContains(response, error, status_code=400)
                self.assertFalse(K8sCluster.objects.filter(name=name).exists())

    def test_create_rejects_unresolvable_context_cluster_and_server(self):
        cases = (
            ('context', self.secret.replace('current-context: secret-context', 'current-context: missing-context')),
            ('cluster-reference', self.secret.replace('cluster: secret-cluster\n    namespace', 'cluster: missing-cluster\n    namespace')),
            ('server', self.secret.replace('    server: https://kubernetes.example.com:6443\n', '')),
            ('scheme', self.secret.replace('https://kubernetes.example.com:6443', 'ftp://kubernetes.example.com')),
            ('namespace', self.secret.replace('namespace: operations', 'namespace: invalid_namespace')),
        )
        for name, content in cases:
            with self.subTest(name=name):
                response = self.client.post(reverse('devops:cluster_create'), {
                    'name': name,
                    'kubeconfig_file': self.kubeconfig_upload(content),
                })
                self.assertEqual(response.status_code, 400)
                self.assertTrue(response.context['form'].errors)
                self.assertFalse(K8sCluster.objects.filter(name=name).exists())

    def test_create_rejects_non_string_kubeconfig_references_without_server_error(self):
        content = self.secret.replace('current-context: secret-context', 'current-context: 42')
        response = self.client.post(reverse('devops:cluster_create'), {
            'name': 'typed-reference',
            'kubeconfig_file': self.kubeconfig_upload(content),
        })

        self.assertEqual(response.status_code, 400)
        self.assertTrue(response.context['form'].errors)
        self.assertFalse(K8sCluster.objects.filter(name='typed-reference').exists())

    def test_invalid_upload_never_echoes_kubeconfig_secrets(self):
        marker = 'uploaded-token-must-never-render'
        content = self.secret.replace('never-render-this', marker).replace(
            'https://kubernetes.example.com:6443',
            'file:///private/cluster',
        )
        response = self.client.post(reverse('devops:cluster_create'), {
            'name': 'secret-response-check',
            'kubeconfig_file': self.kubeconfig_upload(content),
        })

        self.assertEqual(response.status_code, 400)
        self.assertNotContains(response, content, status_code=400)
        self.assertNotContains(response, marker, status_code=400)

    @mock.patch('devops.services.subprocess.run')
    def test_connect_test_saves_encrypted_cluster_and_syncs_online_status(self, run):
        run.return_value = mock.Mock(returncode=0, stdout='{}', stderr='')

        response = self.client.post(reverse('devops:cluster_connect_test'), {
            'name': 'tested-online-cluster',
            'kubeconfig_file': self.kubeconfig_upload(),
        })

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, reverse('devops:cluster_list'))
        cluster = K8sCluster.objects.get(name='tested-online-cluster')
        self.assertTrue(cluster.kubeconfig.startswith('enc:'))
        self.assertNotEqual(cluster.kubeconfig, self.secret)
        self.assertEqual(cluster.status, K8sCluster.STATUS_ONLINE)
        self.assertEqual(cluster.last_error, '')
        self.assertIsNotNone(cluster.last_checked_at)
        page = self.client.get(reverse('devops:cluster_list'))
        self.assertContains(page, '在线')
        self.assertNotContains(page, self.secret)
        audit_text = '\n'.join(AuditLog.objects.values_list('detail', flat=True))
        self.assertNotIn(self.secret, audit_text)

    @mock.patch('devops.services.subprocess.run')
    def test_connect_test_saves_encrypted_cluster_and_syncs_offline_status(self, run):
        failure_marker = 'private-token-must-not-render'
        secret = self.secret.replace('never-render-this', failure_marker)
        run.return_value = mock.Mock(returncode=1, stdout='', stderr=secret)

        response = self.client.post(reverse('devops:cluster_connect_test'), {
            'name': 'tested-offline-cluster',
            'kubeconfig_file': self.kubeconfig_upload(secret),
        })

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, reverse('devops:cluster_list'))
        cluster = K8sCluster.objects.get(name='tested-offline-cluster')
        self.assertTrue(cluster.kubeconfig.startswith('enc:'))
        self.assertEqual(cluster.status, K8sCluster.STATUS_OFFLINE)
        self.assertIsNotNone(cluster.last_checked_at)
        page = self.client.get(reverse('devops:cluster_list'))
        self.assertContains(page, '离线')
        self.assertNotContains(page, secret)
        self.assertNotContains(page, failure_marker)
        audit_text = '\n'.join(AuditLog.objects.values_list('detail', flat=True))
        self.assertNotIn(secret, audit_text)
        self.assertNotIn(failure_marker, audit_text)

    def test_connect_test_rejects_invalid_upload_without_saving_or_echoing_secret(self):
        marker = 'invalid-upload-secret-must-not-render'
        invalid = 'apiVersion: v1\ntoken: %s\n' % marker

        response = self.client.post(reverse('devops:cluster_connect_test'), {
            'name': 'invalid-tested-cluster',
            'kubeconfig_file': self.kubeconfig_upload(invalid),
        })

        self.assertEqual(response.status_code, 400)
        self.assertTemplateUsed(response, 'devops/cluster_connection.html')
        self.assertFalse(K8sCluster.objects.filter(name='invalid-tested-cluster').exists())
        self.assertNotContains(response, invalid, status_code=400)
        self.assertNotContains(response, marker, status_code=400)

    def test_connect_test_is_post_only_and_requires_admin_cluster_permission(self):
        self.assertEqual(self.client.get(reverse('devops:cluster_connect_test')).status_code, 405)
        DevOpsModulePermission.objects.update_or_create(
            user=self.user,
            module=DevOpsModulePermission.MODULE_CLUSTER,
            defaults={'role': DevOpsRole.ROLE_VIEWER},
        )

        response = self.client.post(reverse('devops:cluster_connect_test'), {
            'name': 'viewer-tested-cluster',
            'kubeconfig_file': self.kubeconfig_upload(),
        })

        self.assertEqual(response.status_code, 403)
        self.assertFalse(K8sCluster.objects.filter(name='viewer-tested-cluster').exists())

    def test_cluster_list_name_links_to_k8s_cluster_detail(self):
        cluster = self.create_cluster('linked-detail-cluster')

        response = self.client.get(reverse('devops:cluster_list'))

        self.assertContains(
            response,
            'href="%s"' % reverse('devops:k8s_cluster_detail', args=[cluster.id]),
        )

    @mock.patch('devops.services.subprocess.run')
    def test_connection_test_uses_private_temporary_file_and_cleans_it(self, run):
        cluster = self.create_cluster()
        observed = {}

        def fake_run(command, **kwargs):
            path = command[command.index('--kubeconfig') + 1]
            observed['path'] = path
            observed['mode'] = os.stat(path).st_mode & 0o777
            with open(path, 'r') as handle:
                observed['content_matches'] = handle.read() == self.secret
            observed['command'] = command
            observed['kwargs'] = kwargs
            return mock.Mock(returncode=0, stdout='{}', stderr='')

        run.side_effect = fake_run
        success, message = test_k8s_cluster_connection(cluster)

        self.assertTrue(success)
        self.assertEqual(message, '')
        self.assertEqual(observed['mode'], 0o600)
        self.assertTrue(observed['content_matches'])
        self.assertIsInstance(observed['command'], list)
        self.assertNotIn('shell', observed['kwargs'])
        self.assertFalse(os.path.exists(observed['path']))
        cluster.refresh_from_db()
        self.assertEqual(cluster.status, K8sCluster.STATUS_ONLINE)
        self.assertEqual(cluster.last_error, '')
        self.assertIsNotNone(cluster.last_checked_at)

    @mock.patch('devops.services.subprocess.run')
    def test_failed_connection_does_not_expose_secret(self, run):
        cluster = self.create_cluster()
        run.return_value = mock.Mock(returncode=1, stdout='', stderr=self.secret)

        response = self.client.post(reverse('devops:cluster_test', args=[cluster.id]))

        self.assertEqual(response.status_code, 302)
        cluster.refresh_from_db()
        self.assertEqual(cluster.status, K8sCluster.STATUS_OFFLINE)
        self.assertNotIn(self.secret, cluster.last_error)
        self.assertEqual(response.url, reverse('devops:cluster_list'))
        page = self.client.get(reverse('devops:cluster_list'))
        self.assertNotContains(page, self.secret)
        audit_text = '\n'.join(AuditLog.objects.values_list('detail', flat=True))
        self.assertNotIn(self.secret, audit_text)

    def test_resource_matching_is_namespace_aware_and_secret_safe(self):
        resources = {
            'deployments': [{
                'kind': 'Deployment', 'name': 'billing-api', 'status': '运行中',
                'replicas': '1 / 1', 'namespace': 'prod', 'created_at': '-', 'detail': 'billing:1',
            }],
            'pods': [
                {'kind': 'Pod', 'name': 'billing-api-7f9c8d6b5b-abc12', 'status': 'Running', 'replicas': '-', 'namespace': 'prod', 'created_at': '-', 'detail': 'node-a'},
                {'kind': 'Pod', 'name': 'billing-api-7f9c8d6b5b-def34', 'status': 'Running', 'replicas': '-', 'namespace': 'other', 'created_at': '-', 'detail': 'node-b'},
            ],
            'services': [
                {'kind': 'Service', 'name': 'billing-api', 'status': 'ClusterIP', 'replicas': '-', 'namespace': 'prod', 'created_at': '-', 'detail': '10.0.0.1'},
                {'kind': 'Service', 'name': 'billing', 'status': 'ClusterIP', 'replicas': '-', 'namespace': 'prod', 'created_at': '-', 'detail': '10.0.0.3'},
                {'kind': 'Service', 'name': 'billing-api-other', 'status': 'ClusterIP', 'replicas': '-', 'namespace': 'other', 'created_at': '-', 'detail': '10.0.0.2'},
            ],
            'secrets': [{
                'kind': 'Secret', 'name': 'billing-api-secret', 'status': 'Opaque',
                'replicas': '-', 'namespace': 'prod', 'created_at': '-', 'detail': '2 keys',
                'data': {'password': 'must-not-leak'},
            }],
        }

        groups = build_k8s_resource_matches(resources)

        self.assertEqual([item['name'] for item in groups[0]['resources']['pods']], ['billing-api-7f9c8d6b5b-abc12'])
        self.assertEqual([item['name'] for item in groups[0]['resources']['services']], ['billing-api'])
        self.assertNotIn('data', groups[0]['resources']['secrets'][0])
        self.assertNotIn('must-not-leak', str(groups))

    def test_load_namespaces_uses_private_tempfile_and_safe_fields(self):
        case = self
        observed = {}
        created_at = timezone.now()

        def new_client_from_config(config_file=None):
            observed['path'] = config_file
            observed['mode'] = os.stat(config_file).st_mode & 0o777
            return object()

        class CoreV1Api(object):
            def __init__(self, api_client):
                self.api_client = api_client

            def list_namespace(self, _request_timeout=None):
                return types.SimpleNamespace(items=[
                    types.SimpleNamespace(
                        metadata=types.SimpleNamespace(
                            name='default', labels={'environment': 'production'},
                            creation_timestamp=created_at,
                        ),
                        status=types.SimpleNamespace(phase='Active'),
                        data={'token': 'must-not-leak'},
                    ),
                ])

        fake_client = types.ModuleType('kubernetes.client')
        fake_client.CoreV1Api = CoreV1Api
        fake_config = types.ModuleType('kubernetes.config')
        fake_config.new_client_from_config = new_client_from_config
        fake_kubernetes = types.ModuleType('kubernetes')
        fake_kubernetes.client = fake_client
        fake_kubernetes.config = fake_config
        with mock.patch.dict('sys.modules', {
            'kubernetes': fake_kubernetes,
            'kubernetes.client': fake_client,
            'kubernetes.config': fake_config,
        }):
            result = load_k8s_namespaces(case.secret)

        self.assertTrue(result['ok'])
        self.assertEqual(result['namespaces'], [{
            'name': 'default', 'status': 'Active',
            'labels': 'environment=production',
            'created_at': created_at.strftime('%Y/%m/%d %H:%M:%S'),
        }])
        self.assertEqual(observed['mode'], 0o600)
        self.assertFalse(os.path.exists(observed['path']))
        self.assertNotIn('must-not-leak', str(result))

    def test_node_capacity_summary_normalizes_cpu_memory_and_ready_status(self):
        nodes = [
            types.SimpleNamespace(status=types.SimpleNamespace(
                capacity={'cpu': '4', 'memory': '8Gi'},
                allocatable={'cpu': '3800m', 'memory': '7Gi'},
                conditions=[types.SimpleNamespace(type='Ready', status='True')],
            )),
            types.SimpleNamespace(status=types.SimpleNamespace(
                capacity={'cpu': '1500m', 'memory': '1024Mi'},
                allocatable={'cpu': '1400m', 'memory': '900Mi'},
                conditions=[types.SimpleNamespace(type='Ready', status='False')],
            )),
        ]

        summary = summarize_k8s_nodes(nodes)

        self.assertEqual(summary['node_count'], 2)
        self.assertEqual(summary['ready_nodes'], 1)
        self.assertEqual(summary['cpu_capacity'], '5.5 核')
        self.assertEqual(summary['cpu_allocatable'], '5.2 核')
        self.assertEqual(summary['memory_capacity'], '9 GiB')
        self.assertEqual(summary['memory_allocatable'], '7.88 GiB')

    def test_node_detail_loads_usage_requests_limits_and_all_node_pods(self):
        observed = {}
        node = types.SimpleNamespace(
            metadata=types.SimpleNamespace(
                name='worker-01', creation_timestamp=None,
                labels={'node-role.kubernetes.io/worker': ''},
            ),
            status=types.SimpleNamespace(
                capacity={'cpu': '4', 'memory': '8Gi'},
                allocatable={'cpu': '3800m', 'memory': '7Gi'},
                conditions=[types.SimpleNamespace(type='Ready', status='True')],
                addresses=[types.SimpleNamespace(type='InternalIP', address='10.0.0.11')],
                node_info=types.SimpleNamespace(
                    kubelet_version='v1.31.2', container_runtime_version='containerd://1.7',
                    os_image='Linux', kernel_version='6.1', architecture='amd64',
                ),
            ),
        )

        def pod(name, namespace, cpu_request, cpu_limit, memory_request, memory_limit):
            resources = types.SimpleNamespace(
                requests={'cpu': cpu_request, 'memory': memory_request},
                limits={'cpu': cpu_limit, 'memory': memory_limit},
            )
            return types.SimpleNamespace(
                metadata=types.SimpleNamespace(
                    name=name, namespace=namespace, creation_timestamp=None,
                ),
                spec=types.SimpleNamespace(
                    containers=[types.SimpleNamespace(resources=resources)],
                    init_containers=[],
                ),
                status=types.SimpleNamespace(phase='Running', pod_ip='10.244.0.10'),
            )

        pods = [
            pod('api-01', 'production', '500m', '1', '256Mi', '512Mi'),
            pod('monitor-01', 'monitoring', '1', '2', '1Gi', '2Gi'),
        ]

        def new_client_from_config(config_file=None):
            observed['path'] = config_file
            return object()

        class CoreV1Api(object):
            def __init__(self, api_client):
                self.api_client = api_client

            def read_node(self, name=None, _request_timeout=None):
                observed['node_name'] = name
                return node

            def list_pod_for_all_namespaces(self, field_selector=None, _request_timeout=None):
                observed['field_selector'] = field_selector
                return types.SimpleNamespace(items=pods)

        class CustomObjectsApi(object):
            def __init__(self, api_client):
                self.api_client = api_client

            def get_cluster_custom_object(self, **kwargs):
                observed['metrics_name'] = kwargs.get('name')
                return {'usage': {'cpu': '1250m', 'memory': '2Gi'}}

        fake_client = types.ModuleType('kubernetes.client')
        fake_client.CoreV1Api = CoreV1Api
        fake_client.CustomObjectsApi = CustomObjectsApi
        fake_config = types.ModuleType('kubernetes.config')
        fake_config.new_client_from_config = new_client_from_config
        fake_kubernetes = types.ModuleType('kubernetes')
        fake_kubernetes.client = fake_client
        fake_kubernetes.config = fake_config
        with mock.patch.dict('sys.modules', {
            'kubernetes': fake_kubernetes,
            'kubernetes.client': fake_client,
            'kubernetes.config': fake_config,
        }):
            result = load_k8s_node_detail(self.secret, 'worker-01')

        self.assertTrue(result['ok'])
        self.assertEqual(observed['node_name'], 'worker-01')
        self.assertEqual(observed['field_selector'], 'spec.nodeName=worker-01')
        self.assertEqual(observed['metrics_name'], 'worker-01')
        self.assertFalse(os.path.exists(observed['path']))
        self.assertEqual(result['node']['ip_address'], '10.0.0.11')
        self.assertEqual(result['summary']['cpu_total'], '4 核')
        self.assertEqual(result['summary']['cpu_usage'], '1.25 核')
        self.assertEqual(result['summary']['cpu_request'], '1.5 核')
        self.assertEqual(result['summary']['cpu_limit'], '3 核')
        self.assertEqual(result['summary']['memory_total'], '8 GiB')
        self.assertEqual(result['summary']['memory_usage'], '2 GiB')
        self.assertEqual(result['summary']['memory_request'], '1.25 GiB')
        self.assertEqual(result['summary']['memory_limit'], '2.5 GiB')
        self.assertEqual(result['summary']['pod_total'], 2)
        self.assertEqual({item['namespace'] for item in result['pods']}, {'production', 'monitoring'})

    def test_node_detail_cache_reuses_successful_result(self):
        cache.clear()
        cluster = self.create_cluster('node-detail-cache-cluster')
        loaded = {
            'ok': True, 'message': 'ok', 'metrics_message': '',
            'node': {'name': 'worker-01'}, 'summary': {'pod_total': 0}, 'pods': [],
        }
        with mock.patch('devops.services.load_k8s_node_detail', return_value=loaded) as loader:
            first = load_cached_k8s_node_detail(
                cluster.id, cluster.decrypted_kubeconfig, 'worker-01',
            )
            second = load_cached_k8s_node_detail(
                cluster.id, cluster.decrypted_kubeconfig, 'worker-01',
            )

        loader.assert_called_once_with(cluster.decrypted_kubeconfig, 'worker-01', timeout=8)
        self.assertFalse(first['from_cache'])
        self.assertTrue(second['from_cache'])

    def test_detail_cache_lazily_loads_and_merges_requested_namespaces(self):
        cache.clear()
        cluster = self.create_cluster('cache-cluster')
        namespace_result = {'ok': True, 'message': 'ok', 'namespaces': [
            {'name': 'default', 'status': 'Active'}, {'name': 'ops', 'status': 'Active'},
        ]}

        def overview(_config, namespace, timeout=5):
            return {'ok': True, 'message': 'ok', 'version': 'v1', 'namespace': namespace, 'resources': {}, 'resource_errors': {}, 'resource_matches': []}

        with mock.patch('devops.services.load_k8s_namespaces', return_value=namespace_result) as load_namespaces, \
                mock.patch('devops.services.load_k8s_cluster_overview', side_effect=overview) as load_overview:
            first = load_cached_k8s_cluster_detail(cluster.id, cluster.decrypted_kubeconfig, 'default')
            self.assertEqual([call.args[1] for call in load_overview.call_args_list], ['default'])
            switched = load_cached_k8s_cluster_detail(cluster.id, cluster.decrypted_kubeconfig, 'ops')
            repeated_first = load_cached_k8s_cluster_detail(cluster.id, cluster.decrypted_kubeconfig, 'default')
            repeated_switched = load_cached_k8s_cluster_detail(cluster.id, cluster.decrypted_kubeconfig, 'ops')

        self.assertFalse(first['from_cache'])
        self.assertFalse(switched['from_cache'])
        self.assertTrue(repeated_first['from_cache'])
        self.assertTrue(repeated_switched['from_cache'])
        load_namespaces.assert_called_once()
        self.assertEqual([call.args[1] for call in load_overview.call_args_list], ['default', 'ops'])
        cached = cache.get(k8s_detail_cache_key(cluster.id, cluster.decrypted_kubeconfig))
        self.assertEqual(set(cached['overviews']), {'default', 'ops'})
        self.assertEqual(cached['overviews']['default']['namespace'], 'default')
        self.assertEqual(cached['overviews']['ops']['namespace'], 'ops')
        self.assertEqual(cached['namespace_result'], namespace_result)
        self.assertNotIn(self.secret, str(cached))
        self.assertNotIn('never-render-this', str(cached))
        self.assertNotIn('certificate-authority-data', str(cached))

        fresh_cache = FileBasedCache(self.k8s_cache_dir, {'TIMEOUT': 86400})
        self.assertEqual(fresh_cache.get(k8s_detail_cache_key(cluster.id, cluster.decrypted_kubeconfig)), cached)
        close_test_caches()
        with mock.patch('devops.services.load_k8s_namespaces') as load_namespaces, \
                mock.patch('devops.services.load_k8s_cluster_overview') as load_overview:
            persisted = load_cached_k8s_cluster_detail(
                cluster.id,
                cluster.decrypted_kubeconfig,
                'default',
            )
        self.assertTrue(persisted['from_cache'])
        self.assertEqual(persisted['overview'], cached['overviews']['default'])
        load_namespaces.assert_not_called()
        load_overview.assert_not_called()

    def test_detail_cache_refresh_reloads_only_namespaces_and_current_overview(self):
        cache.clear()
        cluster = self.create_cluster('refresh-cluster')
        initial_namespaces = {'ok': True, 'message': 'initial', 'namespaces': [
            {'name': 'default', 'status': 'Active'}, {'name': 'ops', 'status': 'Active'},
        ]}
        refreshed_namespaces = {'ok': True, 'message': 'refreshed', 'namespaces': [
            {'name': 'default', 'status': 'Active'}, {'name': 'ops', 'status': 'Active'}, {'name': 'new', 'status': 'Active'},
        ]}

        overview_versions = iter(['v1-initial', 'v1-ops', 'v2-refreshed'])

        def overview(_config, namespace, timeout=5):
            return {'ok': True, 'message': 'ok', 'version': next(overview_versions), 'namespace': namespace, 'resources': {}, 'resource_errors': {}, 'resource_matches': []}

        with mock.patch('devops.services.load_k8s_namespaces', side_effect=[initial_namespaces, refreshed_namespaces]) as load_namespaces, \
                mock.patch('devops.services.load_k8s_cluster_overview', side_effect=overview) as load_overview:
            load_cached_k8s_cluster_detail(cluster.id, cluster.decrypted_kubeconfig, 'default')
            load_cached_k8s_cluster_detail(cluster.id, cluster.decrypted_kubeconfig, 'ops')
            with override_settings(K8S_DETAIL_CACHE_TIMEOUT_SECONDS=86400), \
                    mock.patch('devops.services.cache.set', wraps=cache.set) as cache_set:
                refreshed = load_cached_k8s_cluster_detail(cluster.id, cluster.decrypted_kubeconfig, 'default', refresh=True)
            self.assertEqual(cache_set.call_args[0][2], 86400)
            self.assertEqual(load_namespaces.call_count, 2)
            self.assertEqual(
                [call.args[1] for call in load_overview.call_args_list],
                ['default', 'ops', 'default'],
            )
            load_namespaces.reset_mock()
            load_overview.reset_mock()
            repeated = load_cached_k8s_cluster_detail(cluster.id, cluster.decrypted_kubeconfig, 'default')
            load_namespaces.assert_not_called()
            load_overview.assert_not_called()

        self.assertFalse(refreshed['from_cache'])
        self.assertTrue(repeated['from_cache'])
        self.assertEqual(refreshed['namespace_result'], refreshed_namespaces)
        self.assertEqual(refreshed['overview']['version'], 'v2-refreshed')
        self.assertEqual(repeated['overview']['version'], 'v2-refreshed')
        cached = cache.get(k8s_detail_cache_key(cluster.id, cluster.decrypted_kubeconfig))
        self.assertEqual(set(cached['overviews']), {'default', 'ops'})
        self.assertEqual(cached['namespace_result'], refreshed_namespaces)
        self.assertEqual(cached['overviews']['default']['version'], 'v2-refreshed')
        self.assertEqual(cached['overviews']['ops']['version'], 'v1-ops')

    def test_detail_cache_repairs_missing_or_failed_namespace_data_without_reloading_overview(self):
        cache.clear()
        cluster = self.create_cluster('namespace-cache-repair-cluster')
        overview = {
            'ok': True, 'message': 'cached overview', 'version': 'v1', 'namespace': 'default',
            'resources': {}, 'resource_errors': {}, 'resource_matches': [],
        }
        key = k8s_detail_cache_key(cluster.id, cluster.decrypted_kubeconfig)
        repaired_namespaces = {
            'ok': True, 'message': '命名空间读取成功',
            'namespaces': [{'name': 'default', 'status': 'Active'}, {'name': 'ops', 'status': 'Active'}],
        }

        for broken_namespace_result in (None, {'ok': False, 'message': 'temporary failure', 'namespaces': []}):
            cached = {'overviews': {'default': overview}}
            if broken_namespace_result is not None:
                cached['namespace_result'] = broken_namespace_result
            cache.set(key, cached, 86400)
            with self.subTest(namespace_result=broken_namespace_result), \
                    mock.patch('devops.services.load_k8s_namespaces', return_value=repaired_namespaces) as load_namespaces, \
                    mock.patch('devops.services.load_k8s_cluster_overview') as load_overview:
                result = load_cached_k8s_cluster_detail(
                    cluster.id,
                    cluster.decrypted_kubeconfig,
                    'default',
                )

            load_namespaces.assert_called_once_with(cluster.decrypted_kubeconfig, timeout=5)
            load_overview.assert_not_called()
            self.assertEqual(result['namespace_result'], repaired_namespaces)
            self.assertEqual(result['overview'], overview)
            self.assertFalse(result['from_cache'])

    def test_failed_refresh_preserves_existing_resource_cache(self):
        cache.clear()
        cluster = self.create_cluster('failed-refresh-cache-cluster')
        namespace_result = {
            'ok': True, 'message': 'cached namespaces',
            'namespaces': [{'name': 'default', 'status': 'Active'}],
        }
        overview = {
            'ok': True, 'message': 'cached overview', 'version': 'v1', 'namespace': 'default',
            'cluster_capacity': {
                'node_count': 1, 'ready_nodes': 1, 'cpu_capacity': '4 核',
                'cpu_allocatable': '3.8 核', 'memory_capacity': '8 GiB',
                'memory_allocatable': '7 GiB',
            },
            'resources': {'nodes': [{'kind': 'Node', 'name': 'worker-01'}]},
            'resource_errors': {}, 'resource_matches': [],
        }
        cache.set(
            k8s_detail_cache_key(cluster.id, cluster.decrypted_kubeconfig),
            {'namespace_result': namespace_result, 'overviews': {'default': overview}},
            86400,
        )
        failed_namespaces = {'ok': False, 'message': 'namespace network failed', 'namespaces': []}
        failed_overview = {
            'ok': False, 'message': 'overview network failed', 'version': '', 'namespace': 'default',
            'resources': {}, 'resource_errors': {}, 'resource_matches': [],
        }

        with mock.patch('devops.services.load_k8s_namespaces', return_value=failed_namespaces), \
                mock.patch('devops.services.load_k8s_cluster_overview', return_value=failed_overview):
            result = load_cached_k8s_cluster_detail(
                cluster.id,
                cluster.decrypted_kubeconfig,
                'default',
                refresh=True,
            )

        self.assertEqual(result['namespace_result'], namespace_result)
        self.assertEqual(result['overview']['resources'], overview['resources'])
        self.assertEqual(result['overview']['cluster_capacity'], overview['cluster_capacity'])
        self.assertFalse(result['overview']['ok'])
        self.assertEqual(result['overview']['message'], 'overview network failed')

    def test_cluster_scoped_cache_is_reused_across_namespace_overviews(self):
        cache.clear()
        cluster = self.create_cluster('cluster-scoped-cache-cluster')
        namespace_result = {
            'ok': True, 'message': 'ok',
            'namespaces': [
                {'name': 'default', 'status': 'Active'},
                {'name': 'operations', 'status': 'Active'},
            ],
        }
        cluster_capacity = {
            'node_count': 1, 'ready_nodes': 1, 'cpu_capacity': '4 核',
            'cpu_allocatable': '3.8 核', 'memory_capacity': '8 GiB',
            'memory_allocatable': '7 GiB',
        }
        node_rows = [{'kind': 'Node', 'name': 'worker-01', 'status': 'Ready'}]
        default_overview = {
            'ok': True, 'message': 'ok', 'version': 'v1', 'namespace': 'default',
            'cluster_capacity': cluster_capacity,
            'resources': {
                'nodes': node_rows,
                'persistentvolumes': [{'kind': 'PV', 'name': 'pv-01'}],
                'storageclasses': [{'kind': 'StorageClass', 'name': 'fast'}],
            },
            'resource_errors': {}, 'resource_matches': [],
        }
        operations_overview = {
            'ok': True, 'message': 'old cached overview', 'version': 'v1',
            'namespace': 'operations', 'resources': {'deployments': []},
            'resource_errors': {}, 'resource_matches': [],
        }
        cache.set(
            k8s_detail_cache_key(cluster.id, cluster.decrypted_kubeconfig),
            {
                'namespace_result': namespace_result,
                'overviews': {'default': default_overview, 'operations': operations_overview},
            },
            86400,
        )

        with mock.patch('devops.services.load_k8s_namespaces') as load_namespaces, \
                mock.patch('devops.services.load_k8s_cluster_overview') as load_overview:
            result = load_cached_k8s_cluster_detail(
                cluster.id,
                cluster.decrypted_kubeconfig,
                'operations',
            )

        load_namespaces.assert_not_called()
        load_overview.assert_not_called()
        self.assertTrue(result['from_cache'])
        self.assertEqual(result['overview']['resources']['nodes'], node_rows)
        self.assertEqual(result['overview']['cluster_capacity'], cluster_capacity)
        self.assertEqual(result['overview']['resources']['persistentvolumes'][0]['name'], 'pv-01')

    def test_detail_cache_timeout_safely_falls_back_to_one_day(self):
        cache.clear()
        cluster = self.create_cluster('timeout-fallback-cluster')
        namespace_result = {'ok': True, 'message': 'ok', 'namespaces': []}
        overview = {
            'ok': True, 'message': 'ok', 'version': 'v1', 'namespace': 'default',
            'resources': {}, 'resource_errors': {}, 'resource_matches': [],
        }

        for configured_timeout in ('invalid', 0, -1, None):
            cache.clear()
            with self.subTest(configured_timeout=configured_timeout), \
                    override_settings(K8S_DETAIL_CACHE_TIMEOUT_SECONDS=configured_timeout), \
                    mock.patch('devops.services.load_k8s_namespaces', return_value=namespace_result), \
                    mock.patch('devops.services.load_k8s_cluster_overview', return_value=overview), \
                    mock.patch('devops.services.cache.set', wraps=cache.set) as cache_set:
                load_cached_k8s_cluster_detail(
                    cluster.id,
                    cluster.decrypted_kubeconfig,
                    'default',
                )
            self.assertEqual(cache_set.call_args[0][2], 86400)

    def test_detail_urls_context_and_refresh_permission(self):
        cluster = self.create_cluster('detail-cluster')
        detail = {
            'overview': {
                'ok': True, 'message': 'ok', 'version': 'v1', 'namespace': 'default',
                'resources': {'deployments': [{
                    'kind': 'Deployment', 'name': 'gateway', 'status': '运行中',
                    'replicas': '1 / 1', 'namespace': 'default', 'created_at': '-', 'detail': 'image',
                    'labels': 'app=gateway, environment=production',
                    'annotations': 'deployment.kubernetes.io/revision=3',
                }], 'pods': [{
                    'kind': 'Pod', 'name': 'gateway-abc12', 'status': 'Running',
                    'replicas': '-', 'namespace': 'default', 'created_at': '-', 'detail': 'worker-01',
                }], 'services': [{
                    'kind': 'Service', 'name': 'gateway', 'status': 'ClusterIP',
                    'replicas': '-', 'namespace': 'default', 'created_at': '-', 'detail': '10.0.0.10',
                }]},
                'resource_errors': {}, 'resource_matches': [],
            },
            'namespace_result': {'ok': True, 'message': 'ok', 'namespaces': [{'name': 'default', 'status': 'Active'}]},
            'from_cache': False,
        }
        with mock.patch('devops.views.load_cached_k8s_cluster_detail', return_value=detail):
            new_response = self.client.get(reverse('devops:k8s_cluster_detail', args=[cluster.id]))
            old_response = self.client.get(reverse('devops:cluster_detail', args=[cluster.id]))

        self.assertEqual(new_response.status_code, 200)
        self.assertEqual(old_response.status_code, 200)
        self.assertEqual(new_response.context['active_resource'], 'deployments')
        self.assertTrue(new_response.context['is_workload_resource'])
        self.assertEqual(len(new_response.context['resources'][0]['matched_pods']), 1)
        self.assertEqual(len(new_response.context['resources'][0]['matched_services']), 1)
        self.assertContains(new_response, 'app=gateway, environment=production')
        self.assertContains(new_response, 'data-expandable-labels')
        self.assertContains(new_response, '镜像地址')
        self.assertContains(new_response, 'deployment.kubernetes.io/revision=3')
        self.assertContains(new_response, '>Node<')
        self.assertContains(new_response, '匹配 Service')
        self.assertContains(new_response, '10.0.0.10')
        self.assertNotIn('kubeconfig', new_response.context)
        self.assertNotContains(new_response, self.secret)

        DevOpsModulePermission.objects.update_or_create(
            user=self.user,
            module=DevOpsModulePermission.MODULE_CLUSTER,
            defaults={'role': DevOpsRole.ROLE_VIEWER},
        )
        denied = self.client.get(reverse('devops:k8s_cluster_detail', args=[cluster.id]), {'refresh': '1'})
        self.assertEqual(denied.status_code, 403)

    def test_detail_supports_safe_searchable_generic_resources(self):
        cluster = self.create_cluster('generic-resource-cluster')
        generic_resources = {
            'services': [
                {
                    'kind': 'Service', 'name': 'gateway-service', 'status': 'ClusterIP',
                    'replicas': '-', 'namespace': 'default', 'created_at': '-', 'detail': '10.0.0.1',
                    'raw': 'must-not-render', 'token': 'service-token-must-not-render',
                },
                {'kind': 'Service', 'name': 'unrelated-service', 'namespace': 'default'},
            ],
            'persistentvolumeclaims': [
                {
                    'kind': 'PersistentVolumeClaim', 'name': 'gateway-storage', 'status': 'Bound',
                    'replicas': '-', 'namespace': 'default', 'created_at': '-', 'detail': '10Gi',
                    'data': {'password': 'pvc-password-must-not-render'},
                },
                {'kind': 'PersistentVolumeClaim', 'name': 'unrelated-storage', 'namespace': 'default'},
            ],
            'configmaps': [
                {
                    'kind': 'ConfigMap', 'name': 'gateway-config', 'status': 'Active',
                    'replicas': '-', 'namespace': 'default', 'created_at': '-', 'detail': '3 keys',
                    'certificate': 'config-certificate-must-not-render',
                },
                {'kind': 'ConfigMap', 'name': 'unrelated-config', 'namespace': 'default'},
            ],
        }
        detail = {
            'overview': {
                'ok': True, 'message': 'ok', 'version': 'v1', 'namespace': 'default',
                'resources': generic_resources,
                'resource_errors': {'services': 'service list warning'},
                'resource_matches': [],
            },
            'namespace_result': {
                'ok': True, 'message': 'ok',
                'namespaces': [{'name': 'default', 'status': 'Active'}],
            },
            'from_cache': True,
        }
        cases = (
            ('services', '服务', 'gateway-service'),
            ('persistentvolumeclaims', '存储', 'gateway-storage'),
            ('configmaps', '配置', 'gateway-config'),
        )

        with mock.patch('devops.views.load_cached_k8s_cluster_detail', return_value=detail) as loader:
            for resource_key, label, search in cases:
                with self.subTest(resource=resource_key):
                    response = self.client.get(
                        reverse('devops:k8s_cluster_detail', args=[cluster.id]),
                        {'resource': resource_key, 'namespace': 'default', 'q': search},
                    )
                    self.assertEqual(response.status_code, 200)
                    self.assertEqual(response.context['active_resource'], resource_key)
                    self.assertEqual(response.context['active_resource_label'], label)
                    self.assertFalse(response.context['is_workload_resource'])
                    self.assertEqual(response.context['workload_resource_keys'], [
                        'deployments', 'statefulsets', 'daemonsets', 'jobs', 'cronjobs',
                    ])
                    self.assertEqual(len(response.context['resources']), 1)
                    row = response.context['resources'][0]
                    self.assertEqual(row['name'], search)
                    self.assertNotIn('matched_pods', row)
                    self.assertNotIn('raw', row)
                    self.assertNotIn('data', row)
                    self.assertNotIn('token', row)
                    self.assertNotIn('certificate', row)
                    self.assertEqual(response.context['workloads'], response.context['resources'])

            unsafe_search_response = self.client.get(
                reverse('devops:k8s_cluster_detail', args=[cluster.id]),
                {'resource': 'services', 'q': 'service-token-must-not-render'},
            )

        self.assertEqual(loader.call_count, 4)
        self.assertEqual(unsafe_search_response.context['resources'], [])
        self.assertEqual(response.context['resource_error'], '')
        with mock.patch('devops.views.load_cached_k8s_cluster_detail', return_value=detail):
            service_response = self.client.get(
                reverse('devops:k8s_cluster_detail', args=[cluster.id]),
                {'resource': 'services'},
            )
        self.assertEqual(service_response.context['resource_error'], 'service list warning')
        rendered_context = str(service_response.context['resources'])
        self.assertNotIn('must-not-render', rendered_context)

    def test_namespace_resource_and_all_resource_lists_paginate_twenty_rows(self):
        cluster = self.create_cluster('paginated-resource-cluster')
        namespaces = [
            {
                'name': 'namespace-%02d' % index, 'status': 'Active',
                'labels': 'environment=test, index=%s' % index,
                'created_at': '2026/07/11 10:%02d:00 GMT+0800' % index,
            }
            for index in range(45)
        ]
        workload_rows = [
            {
                'kind': 'Deployment', 'name': 'deployment-%02d' % index,
                'status': '运行中', 'replicas': '1 / 1', 'namespace': 'default',
                'created_at': '-', 'detail': 'image:%s' % index,
            }
            for index in range(45)
        ]
        service_rows = [
            {
                'kind': 'Service', 'name': 'service-%02d' % index,
                'status': 'ClusterIP', 'replicas': '-', 'namespace': 'default',
                'created_at': '-', 'detail': '10.0.0.%s' % index,
            }
            for index in range(45)
        ]
        detail = {
            'overview': {
                'ok': True, 'message': 'ok', 'version': 'v1', 'namespace': 'default',
                'resources': {
                    'deployments': workload_rows,
                    'services': service_rows,
                    'pods': [],
                },
                'resource_errors': {}, 'resource_matches': [],
            },
            'namespace_result': {
                'ok': True, 'message': '命名空间读取成功', 'namespaces': namespaces,
            },
            'from_cache': True,
        }

        cases = (
            ('namespaces', 'namespace-20'),
            ('deployments', 'deployment-20'),
            ('services', 'service-20'),
        )
        with mock.patch('devops.views.load_cached_k8s_cluster_detail', return_value=detail):
            for resource_key, first_name in cases:
                with self.subTest(resource=resource_key):
                    response = self.client.get(
                        reverse('devops:k8s_cluster_detail', args=[cluster.id]),
                        {'resource': resource_key, 'namespace': 'default', 'page': '2'},
                    )
                    self.assertEqual(response.status_code, 200)
                    self.assertEqual(len(response.context['resources']), 20)
                    self.assertEqual(response.context['resources'][0]['name'], first_name)
                    self.assertEqual(response.context['resource_page'].number, 2)
                    self.assertEqual(response.context['resource_page'].paginator.count, 45)
                    self.assertContains(response, '第 2 / 3 页，共 45 条')

        with mock.patch('devops.views.load_cached_k8s_cluster_detail', return_value=detail):
            namespace_search = self.client.get(
                reverse('devops:k8s_cluster_detail', args=[cluster.id]),
                {'resource': 'namespaces', 'q': 'namespace-44'},
            )
        self.assertTrue(namespace_search.context['is_namespace_resource'])
        self.assertFalse(namespace_search.context['is_workload_resource'])
        self.assertEqual(namespace_search.context['active_resource_label'], 'Namespace')
        self.assertEqual(
            [item['name'] for item in namespace_search.context['resources']],
            ['namespace-44'],
        )
        self.assertContains(namespace_search, '标签')
        self.assertContains(namespace_search, 'environment=test, index=44')
        self.assertContains(namespace_search, '2026/07/11 10:44:00')
        self.assertNotContains(namespace_search, 'GMT+0800')
        self.assertContains(namespace_search, 'data-expandable-labels')

    def test_generic_resource_refresh_keeps_loader_arguments_and_query(self):
        cluster = self.create_cluster('generic-refresh-cluster')
        detail = {
            'overview': {
                'ok': True, 'message': 'ok', 'version': 'v1', 'namespace': 'ops',
                'resources': {'services': []}, 'resource_errors': {}, 'resource_matches': [],
            },
            'namespace_result': {
                'ok': True, 'message': 'ok', 'namespaces': [{'name': 'ops', 'status': 'Active'}],
            },
            'from_cache': False,
        }

        with mock.patch('devops.views.load_cached_k8s_cluster_detail', return_value=detail) as loader:
            response = self.client.get(
                reverse('devops:k8s_cluster_detail', args=[cluster.id]),
                {'resource': 'services', 'namespace': 'ops', 'q': 'gateway', 'refresh': '1'},
            )

        self.assertEqual(response.status_code, 200)
        loader.assert_called_once_with(
            cluster.id,
            cluster.decrypted_kubeconfig,
            'ops',
            refresh=True,
        )
        self.assertIn('resource=services', response.context['refresh_query'])
        self.assertIn('namespace=ops', response.context['refresh_query'])
        self.assertIn('q=gateway', response.context['refresh_query'])

    def test_service_storage_and_config_resource_groups_render_expected_tabs(self):
        cluster = self.create_cluster('grouped-resource-cluster')
        detail = {
            'overview': {
                'ok': True, 'message': 'ok', 'version': 'v1', 'namespace': 'default',
                'resources': {
                    'services': [],
                    'ingresses': [{
                        'kind': 'Ingress', 'name': 'public-gateway', 'status': '可用',
                        'replicas': '-', 'namespace': 'default', 'created_at': '-',
                        'detail': 'gateway.example.com',
                    }],
                    'persistentvolumeclaims': [],
                    'persistentvolumes': [{
                        'kind': 'PV', 'name': 'data-volume', 'status': 'Bound',
                        'replicas': '-', 'namespace': '-', 'created_at': '-', 'detail': 'fast',
                    }],
                    'storageclasses': [{
                        'kind': 'StorageClass', 'name': 'fast', 'status': '可用',
                        'replicas': '-', 'namespace': '-', 'created_at': '-', 'detail': 'csi.example.com',
                    }],
                    'configmaps': [],
                    'secrets': [{
                        'kind': 'Secret', 'name': 'registry-secret', 'status': 'Opaque',
                        'replicas': '-', 'namespace': 'default', 'created_at': '-',
                        'detail': '受保护数据', 'data': {'password': 'must-not-render'},
                    }],
                },
                'resource_errors': {}, 'resource_matches': [],
            },
            'namespace_result': {
                'ok': True, 'message': 'ok',
                'namespaces': [{'name': 'default', 'status': 'Active'}],
            },
            'from_cache': True,
        }
        cases = (
            ('ingresses', 'service', ['Service', 'Ingress'], 'public-gateway'),
            ('persistentvolumes', 'storage', ['PVC', 'PV', 'SC'], 'data-volume'),
            ('storageclasses', 'storage', ['PVC', 'PV', 'SC'], 'fast'),
            ('secrets', 'config', ['ConfigMap', 'Secret'], 'registry-secret'),
        )

        with mock.patch('devops.views.load_cached_k8s_cluster_detail', return_value=detail):
            for resource_key, group, labels, expected_name in cases:
                with self.subTest(resource=resource_key):
                    response = self.client.get(
                        reverse('devops:k8s_cluster_detail', args=[cluster.id]),
                        {'resource': resource_key, 'namespace': 'default'},
                    )
                    self.assertEqual(response.status_code, 200)
                    self.assertEqual(response.context['resource_group'], group)
                    self.assertEqual(
                        [tab['label'] for tab in response.context['resource_tabs']],
                        labels,
                    )
                    self.assertEqual(response.context['resources'][0]['name'], expected_name)
                    self.assertContains(response, expected_name)

        with mock.patch('devops.views.load_cached_k8s_cluster_detail', return_value=detail):
            secret_response = self.client.get(
                reverse('devops:k8s_cluster_detail', args=[cluster.id]),
                {'resource': 'secrets'},
            )
        self.assertNotIn('data', secret_response.context['resources'][0])
        self.assertNotContains(secret_response, 'must-not-render')

    def test_cluster_overview_and_node_resource_render_capacity_and_cluster_information(self):
        cluster = self.create_cluster('overview-cluster')
        detail = {
            'overview': {
                'ok': True, 'message': 'ok', 'version': 'v1.31.2', 'namespace': 'default',
                'cluster_capacity': {
                    'node_count': 3, 'ready_nodes': 2,
                    'cpu_capacity': '12 核', 'cpu_allocatable': '11.4 核',
                    'memory_capacity': '48 GiB', 'memory_allocatable': '44 GiB',
                },
                'resources': {
                    'nodes': [{
                        'kind': 'Node', 'name': 'worker-01', 'status': 'Ready',
                        'replicas': '-', 'namespace': '-', 'created_at': '-',
                        'ip_address': '10.0.0.11',
                        'detail': 'worker | Kubelet v1.31.2',
                    }],
                    'pods': [{
                        'kind': 'Pod', 'name': 'api-01', 'status': 'Running',
                        'replicas': '-', 'namespace': 'default', 'created_at': '-', 'detail': 'worker-01',
                    }],
                    'deployments': [], 'statefulsets': [], 'daemonsets': [],
                    'services': [], 'ingresses': [], 'persistentvolumeclaims': [],
                    'persistentvolumes': [], 'storageclasses': [], 'configmaps': [], 'secrets': [],
                },
                'resource_errors': {}, 'resource_matches': [],
            },
            'namespace_result': {
                'ok': True, 'message': 'ok',
                'namespaces': [
                    {'name': 'default', 'status': 'Active'},
                    {'name': 'operations', 'status': 'Active'},
                ],
            },
            'from_cache': True,
        }

        with mock.patch('devops.views.load_cached_k8s_cluster_detail', return_value=detail):
            overview_response = self.client.get(
                reverse('devops:k8s_cluster_detail', args=[cluster.id]),
                {'resource': 'overview'},
            )
            node_response = self.client.get(
                reverse('devops:k8s_cluster_detail', args=[cluster.id]),
                {'resource': 'nodes'},
            )

        self.assertEqual(overview_response.status_code, 200)
        self.assertTrue(overview_response.context['is_overview_resource'])
        self.assertEqual(overview_response.context['cluster_summary']['cpu_capacity'], '12 核')
        self.assertEqual(overview_response.context['cluster_summary']['memory_capacity'], '48 GiB')
        self.assertEqual(overview_response.context['cluster_summary']['namespace_count'], 2)
        self.assertContains(overview_response, 'CPU 总容量')
        self.assertContains(overview_response, '资源统计')
        self.assertContains(overview_response, 'v1.31.2')

        self.assertEqual(node_response.status_code, 200)
        self.assertFalse(node_response.context['is_overview_resource'])
        self.assertEqual(node_response.context['active_resource_label'], 'Node')
        self.assertEqual(node_response.context['resources'][0]['name'], 'worker-01')
        self.assertContains(node_response, 'worker-01')
        self.assertContains(node_response, '10.0.0.11')
        self.assertContains(node_response, reverse('devops:k8s_node_detail', args=[cluster.id, 'worker-01']))
        self.assertContains(node_response, 'worker | Kubelet v1.31.2')

    def test_node_detail_page_renders_metrics_all_pods_pagination_search_and_permissions(self):
        cluster = self.create_cluster('node-detail-page-cluster')
        pods = [
            {
                'name': 'pod-%02d' % index,
                'namespace': 'namespace-%02d' % (index % 3),
                'status': 'Running', 'pod_ip': '10.244.0.%s' % index,
                'created_at': '-', 'cpu_request': '0.1 核', 'cpu_limit': '0.2 核',
                'memory_request': '0.25 GiB', 'memory_limit': '0.5 GiB',
            }
            for index in range(45)
        ]
        detail = {
            'ok': True, 'message': '节点详情读取成功', 'metrics_message': '',
            'from_cache': True,
            'node': {
                'name': 'worker-01', 'status': 'Ready', 'ip_address': '10.0.0.11',
                'roles': 'worker', 'created_at': '-', 'kubelet_version': 'v1.31.2',
                'container_runtime': 'containerd://1.7', 'os_image': 'Linux',
                'kernel_version': '6.1', 'architecture': 'amd64',
            },
            'summary': {
                'cpu_total': '4 核', 'cpu_allocatable': '3.8 核',
                'cpu_usage': '1.25 核', 'cpu_request': '1.5 核', 'cpu_limit': '3 核',
                'memory_total': '8 GiB', 'memory_allocatable': '7 GiB',
                'memory_usage': '2 GiB', 'memory_request': '1.25 GiB',
                'memory_limit': '2.5 GiB', 'pod_total': 45,
            },
            'pods': pods,
        }

        with mock.patch('devops.views.load_cached_k8s_node_detail', return_value=detail) as loader:
            response = self.client.get(
                reverse('devops:k8s_node_detail', args=[cluster.id, 'worker-01']),
                {'page': '2'},
            )
            search_response = self.client.get(
                reverse('devops:k8s_node_detail', args=[cluster.id, 'worker-01']),
                {'q': 'pod-44'},
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context['pod_page'].number, 2)
        self.assertEqual(response.context['pod_page'].paginator.count, 45)
        self.assertEqual(len(response.context['pods']), 20)
        self.assertContains(response, '4 核')
        self.assertContains(response, '1.25 核')
        self.assertContains(response, '8 GiB')
        self.assertContains(response, '总数 45')
        self.assertContains(response, '第 2 / 3 页，共 45 条')
        self.assertEqual([item['name'] for item in search_response.context['pods']], ['pod-44'])
        self.assertEqual(loader.call_count, 2)

        DevOpsModulePermission.objects.update_or_create(
            user=self.user,
            module=DevOpsModulePermission.MODULE_CLUSTER,
            defaults={'role': DevOpsRole.ROLE_VIEWER},
        )
        with mock.patch('devops.views.load_cached_k8s_node_detail') as denied_loader:
            denied = self.client.get(
                reverse('devops:k8s_node_detail', args=[cluster.id, 'worker-01']),
                {'refresh': '1'},
            )
        self.assertEqual(denied.status_code, 403)
        denied_loader.assert_not_called()

    def test_node_detail_rejects_invalid_node_name_before_loading(self):
        cluster = self.create_cluster('invalid-node-detail-cluster')
        with mock.patch('devops.views.load_cached_k8s_node_detail') as loader:
            response = self.client.get('/devops/clusters/%s/nodes/bad%%2Fnode/' % cluster.id)
        self.assertEqual(response.status_code, 404)
        loader.assert_not_called()

    def test_namespace_switcher_only_renders_inside_namespaced_resource_pages(self):
        cluster = self.create_cluster('namespace-switcher-cluster')
        detail = {
            'overview': {
                'ok': True, 'message': 'ok', 'version': 'v1', 'namespace': 'default',
                'cluster_capacity': {
                    'node_count': 0, 'ready_nodes': 0, 'cpu_capacity': '0 核',
                    'cpu_allocatable': '0 核', 'memory_capacity': '0 GiB',
                    'memory_allocatable': '0 GiB',
                },
                'resources': {}, 'resource_errors': {}, 'resource_matches': [],
            },
            'namespace_result': {
                'ok': True, 'message': 'ok',
                'namespaces': [
                    {'name': 'default', 'status': 'Active'},
                    {'name': 'operations', 'status': 'Active'},
                ],
            },
            'from_cache': True,
        }
        namespaced_resources = (
            'deployments', 'statefulsets', 'daemonsets', 'jobs', 'cronjobs',
            'services', 'ingresses', 'persistentvolumeclaims', 'configmaps', 'secrets',
        )
        cluster_scoped_resources = (
            'overview', 'namespaces', 'nodes', 'persistentvolumes', 'storageclasses',
        )

        with mock.patch('devops.views.load_cached_k8s_cluster_detail', return_value=detail):
            for resource_key in namespaced_resources:
                with self.subTest(namespaced_resource=resource_key):
                    response = self.client.get(
                        reverse('devops:k8s_cluster_detail', args=[cluster.id]),
                        {'resource': resource_key},
                    )
                    body = response.content.decode()
                    self.assertTrue(response.context['show_namespace_switcher'])
                    self.assertEqual(body.count('id="k8s-namespace-select"'), 1)
                    self.assertLess(
                        body.find('class="k8s-workload-actions"'),
                        body.find('id="k8s-namespace-select"'),
                    )

            for resource_key in cluster_scoped_resources:
                with self.subTest(cluster_scoped_resource=resource_key):
                    response = self.client.get(
                        reverse('devops:k8s_cluster_detail', args=[cluster.id]),
                        {'resource': resource_key},
                    )
                    self.assertFalse(response.context['show_namespace_switcher'])
                    self.assertNotContains(response, 'id="k8s-namespace-select"')

    def test_cluster_scoped_pages_ignore_namespace_query_parameter(self):
        cluster = self.create_cluster('cluster-scoped-namespace-cluster')
        detail = {
            'overview': {
                'ok': True, 'message': 'ok', 'version': 'v1', 'namespace': 'default',
                'cluster_capacity': {
                    'node_count': 1, 'ready_nodes': 1, 'cpu_capacity': '4 核',
                    'cpu_allocatable': '3.8 核', 'memory_capacity': '8 GiB',
                    'memory_allocatable': '7 GiB',
                },
                'resources': {
                    'nodes': [{'kind': 'Node', 'name': 'worker-01', 'status': 'Ready'}],
                },
                'resource_errors': {}, 'resource_matches': [],
            },
            'namespace_result': {
                'ok': True, 'message': 'ok',
                'namespaces': [
                    {'name': 'default', 'status': 'Active'},
                    {'name': 'operations', 'status': 'Active'},
                ],
            },
            'from_cache': True,
        }
        cluster_scoped_resources = (
            'overview', 'namespaces', 'nodes', 'persistentvolumes', 'storageclasses',
        )

        with mock.patch('devops.views.load_cached_k8s_cluster_detail', return_value=detail) as loader:
            for resource_key in cluster_scoped_resources:
                with self.subTest(resource=resource_key):
                    response = self.client.get(
                        reverse('devops:k8s_cluster_detail', args=[cluster.id]),
                        {'resource': resource_key, 'namespace': 'operations'},
                    )
                    self.assertEqual(response.status_code, 200)
                    self.assertEqual(response.context['selected_namespace'], 'default')

        self.assertEqual(loader.call_count, len(cluster_scoped_resources))
        for call in loader.call_args_list:
            self.assertEqual(call.args[2], 'default')

    def test_offline_detail_returns_immediately_without_loading_or_exposing_errors(self):
        cluster = self.create_cluster('offline-detail-cluster')
        secret_marker = 'offline-private-token-must-not-render'
        cluster.status = K8sCluster.STATUS_OFFLINE
        cluster.last_error = secret_marker
        cluster.save(update_fields=['status', 'last_error', 'updated_at'])

        with mock.patch('devops.views.load_cached_k8s_cluster_detail') as loader:
            response = self.client.get(reverse('devops:k8s_cluster_detail', args=[cluster.id]))

        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'devops/k8s_cluster_detail.html')
        loader.assert_not_called()
        self.assertEqual(response.context['overview']['ok'], False)
        self.assertEqual(response.context['overview']['resources'], {})
        self.assertEqual(response.context['overview']['resource_errors'], {})
        self.assertEqual(response.context['resources'], [])
        self.assertEqual(response.context['workloads'], [])
        self.assertEqual(response.context['namespace_options'], ['default'])
        self.assertEqual(response.context['selected_namespace'], 'default')
        self.assertEqual(response.context['active_resource'], 'deployments')
        self.assertTrue(response.context['is_workload_resource'])
        self.assertEqual([tab['count'] for tab in response.context['resource_tabs']], [0, 0, 0, 0, 0])
        self.assertFalse(response.context['from_cache'])
        self.assertFalse(response.context['k8s_detail_from_cache'])
        self.assertContains(response, '集群当前处于离线状态，请测试连接或强制刷新后重试。')
        self.assertNotContains(response, secret_marker)
        self.assertNotContains(response, self.secret)

    def test_offline_generic_resource_context_is_safe(self):
        cluster = self.create_cluster('offline-generic-cluster')
        cluster.status = K8sCluster.STATUS_OFFLINE
        cluster.last_error = 'offline-secret-must-not-render'
        cluster.save(update_fields=['status', 'last_error', 'updated_at'])

        with mock.patch('devops.views.load_cached_k8s_cluster_detail') as loader:
            response = self.client.get(
                reverse('devops:k8s_cluster_detail', args=[cluster.id]),
                {'resource': 'configmaps'},
            )

        self.assertEqual(response.status_code, 200)
        loader.assert_not_called()
        self.assertEqual(response.context['active_resource'], 'configmaps')
        self.assertEqual(response.context['active_resource_label'], '配置')
        self.assertFalse(response.context['is_workload_resource'])
        self.assertEqual(response.context['resources'], [])
        self.assertEqual(response.context['resource_error'], '')
        self.assertNotContains(response, 'offline-secret-must-not-render')

    def test_offline_detail_admin_refresh_still_calls_loader(self):
        cluster = self.create_cluster('offline-refresh-cluster')
        cluster.status = K8sCluster.STATUS_OFFLINE
        cluster.save(update_fields=['status', 'updated_at'])
        detail = {
            'overview': {
                'ok': True, 'message': 'ok', 'version': 'v1', 'namespace': 'default',
                'resources': {}, 'resource_errors': {}, 'resource_matches': [],
            },
            'namespace_result': {
                'ok': True, 'message': 'ok',
                'namespaces': [{'name': 'default', 'status': 'Active'}],
            },
            'from_cache': False,
        }

        with mock.patch('devops.views.load_cached_k8s_cluster_detail', return_value=detail) as loader:
            response = self.client.get(
                reverse('devops:k8s_cluster_detail', args=[cluster.id]),
                {'refresh': '1'},
            )

        self.assertEqual(response.status_code, 200)
        loader.assert_called_once_with(
            cluster.id,
            cluster.decrypted_kubeconfig,
            'default',
            refresh=True,
        )

    def test_detail_invalid_resource_and_namespace_fall_back(self):
        cluster = self.create_cluster('fallback-cluster')
        detail = {
            'overview': {'ok': True, 'message': 'ok', 'version': 'v1', 'namespace': 'default', 'resources': {}, 'resource_errors': {}, 'resource_matches': []},
            'namespace_result': {'ok': False, 'message': 'failed', 'namespaces': []},
            'from_cache': False,
        }
        with mock.patch('devops.views.load_cached_k8s_cluster_detail', return_value=detail) as loader:
            response = self.client.get(reverse('devops:k8s_cluster_detail', args=[cluster.id]), {
                'resource': 'events', 'namespace': 'bad/path',
            })

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context['active_resource'], 'deployments')
        self.assertTrue(response.context['is_workload_resource'])
        self.assertEqual(response.context['selected_namespace'], 'default')
        loader.assert_called_once_with(cluster.id, cluster.decrypted_kubeconfig, 'default', refresh=False)


class DevOpsViewTests(TestCase):
    def setUp(self):
        self.user = User.objects.create(
            user='tester',
            email='tester@example.com',
            password='plain-password',
            confirm_pwd='plain-password',
        )
        self.host = NewLinux.objects.create(
            linux_name='test-host',
            linux_ip='127.0.0.1',
            linux_hostname='localhost',
            linux_port='22',
            linux_user='root',
            linux_passwd='bad-password',
            linux_app='',
        )
        session = self.client.session
        session['is_login'] = True
        session['user_id'] = self.user.id
        session['user_name'] = self.user.user
        session.save()

    def set_role(self, role):
        DevOpsRole.objects.update_or_create(user=self.user, defaults={'role': role})

    def test_dashboard_requires_login(self):
        self.client.session.flush()

        response = self.client.get(reverse('devops:dashboard'))

        self.assertEqual(response.status_code, 302)
        self.assertIn('/login/', response['Location'])

    def test_api_requires_login(self):
        self.client.session.flush()

        response = self.client.get(reverse('devops:api_bootstrap'))

        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json()['code'], 'unauthorized')

    def test_api_rejects_incomplete_login_session(self):
        session = self.client.session
        session['is_login'] = True
        session.pop('user_id', None)
        session['user_name'] = self.user.user
        session.save()

        response = self.client.get(reverse('devops:api_bootstrap'))

        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json()['code'], 'unauthorized')

    def test_vue_app_requires_login(self):
        self.client.session.flush()

        response = self.client.get(reverse('devops:vue_app'))

        self.assertEqual(response.status_code, 302)
        self.assertIn('/login/', response['Location'])

    def test_vue_app_renders_shell(self):
        response = self.client.get(reverse('devops:vue_app'))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'devops-vue-root')
        self.assertContains(response, 'devops-vue.js')
        self.assertContains(response, 'DevOps控制台')
        self.assertContains(response, '加载 DevOps 控制台')

    def test_vue_static_includes_approval_decision_controls(self):
        with open('static/js/devops-vue.js', 'r') as handle:
            content = handle.read()

        self.assertIn('approvalComments', content)
        self.assertIn('decideApproval(item, action)', content)
        self.assertIn('/devops/api/approvals/${item.id}/decide/', content)
        self.assertIn('canDecideApproval', content)

    def test_dashboard_uses_vue_shell(self):
        response = self.client.get(reverse('devops:dashboard'))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'devops-vue-root')
        self.assertContains(response, 'DevOps 控制台')
        self.assertContains(response, 'devops-vue.js')
        self.assertContains(response, 'devops-vue.js?v=20260708')

    def test_legacy_dashboard_still_available(self):
        response = self.client.get(reverse('devops:legacy_dashboard'))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'DevOps平台')
        self.assertContains(response, '最近命令')

    def test_api_bootstrap_returns_user_counts_and_module_permissions(self):
        response = self.client.get(reverse('devops:api_bootstrap'))

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertTrue(payload['ok'])
        self.assertEqual(payload['user']['name'], self.user.user)
        self.assertEqual(payload['counts']['hosts'], 1)
        for key in ('command', 'task', 'approval', 'metric', 'deployment', 'file', 'notification', 'audit'):
            self.assertIn(key, payload['permissions'])

    def test_api_bootstrap_module_permission_flags_respect_overrides(self):
        self.set_role(DevOpsRole.ROLE_ADMIN)
        DevOpsModulePermission.objects.create(
            user=self.user,
            module=DevOpsModulePermission.MODULE_DEPLOYMENT,
            role=DevOpsRole.ROLE_VIEWER,
        )
        DevOpsModulePermission.objects.create(
            user=self.user,
            module=DevOpsModulePermission.MODULE_FILE,
            role=DevOpsRole.ROLE_VIEWER,
        )
        DevOpsModulePermission.objects.create(
            user=self.user,
            module=DevOpsModulePermission.MODULE_AUDIT,
            role=DevOpsRole.ROLE_VIEWER,
        )

        response = self.client.get(reverse('devops:api_bootstrap'))

        self.assertEqual(response.status_code, 200)
        permissions = response.json()['permissions']
        self.assertTrue(permissions['deployment'])
        self.assertTrue(permissions['file'])
        self.assertTrue(permissions['audit'])
        self.assertTrue(permissions['command'])

    def test_api_hosts_returns_visible_hosts(self):
        response = self.client.get(reverse('devops:api_hosts'))

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload['results'][0]['name'], 'test-host')
        self.assertNotIn('linux_passwd', payload['results'][0])

    def test_api_dashboard_returns_recent_data(self):
        CommandExecution.objects.create(host=self.host, command='uptime', status=CommandExecution.STATUS_SUCCESS)
        record_metric_sample(self.host, MetricSample.METRIC_CPU, 0.72)

        response = self.client.get(reverse('devops:api_dashboard'))

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload['counts']['hosts'], 1)
        self.assertEqual(payload['recent_commands'][0]['command'], 'uptime')
        self.assertEqual(payload['host_metrics'][0]['cpu'], 72.0)

    def test_api_bootstrap_counts_respect_host_scope(self):
        allowed_group = HostGroup.objects.create(name='api-bootstrap-allowed')
        allowed_group.hosts.add(self.host)
        other = NewLinux.objects.create(
            linux_name='api-bootstrap-blocked',
            linux_ip='127.0.1.10',
            linux_hostname='api-bootstrap-blocked',
            linux_port='22',
            linux_user='root',
            linux_passwd='bad-password',
            linux_app='',
        )
        AlertEvent.objects.create(host=self.host, message='visible alert', status=AlertEvent.STATUS_OPEN)
        AlertEvent.objects.create(host=other, message='hidden alert', status=AlertEvent.STATUS_OPEN)
        ApprovalRequest.objects.create(
            request_type=ApprovalRequest.TYPE_COMMAND,
            status=ApprovalRequest.STATUS_PENDING,
            title='visible approval',
            host=self.host,
        )
        ApprovalRequest.objects.create(
            request_type=ApprovalRequest.TYPE_COMMAND,
            status=ApprovalRequest.STATUS_PENDING,
            title='hidden approval',
            host=other,
        )
        scope = DevOpsHostScope.objects.create(user=self.user)
        scope.groups.add(allowed_group)

        response = self.client.get(reverse('devops:api_bootstrap'))

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload['counts']['hosts'], 1)
        self.assertEqual(payload['counts']['groups'], 1)
        self.assertEqual(payload['counts']['open_alerts'], 1)
        self.assertEqual(payload['counts']['pending_approvals'], 1)

    def test_api_dashboard_filters_host_scoped_counts_and_alerts(self):
        allowed_group = HostGroup.objects.create(name='api-dashboard-allowed')
        allowed_group.hosts.add(self.host)
        other = NewLinux.objects.create(
            linux_name='api-dashboard-blocked',
            linux_ip='127.0.1.11',
            linux_hostname='api-dashboard-blocked',
            linux_port='22',
            linux_user='root',
            linux_passwd='bad-password',
            linux_app='',
        )
        CommandExecution.objects.create(host=self.host, command='visible-command')
        CommandExecution.objects.create(host=other, command='hidden-command')
        visible_task = BatchTask.objects.create(name='visible-task', command='uptime')
        visible_task.hosts.add(self.host)
        hidden_task = BatchTask.objects.create(name='hidden-task', command='uptime')
        hidden_task.hosts.add(other)
        AlertEvent.objects.create(host=self.host, message='visible alert', status=AlertEvent.STATUS_OPEN)
        AlertEvent.objects.create(host=other, message='hidden alert', status=AlertEvent.STATUS_OPEN)
        scope = DevOpsHostScope.objects.create(user=self.user)
        scope.groups.add(allowed_group)

        response = self.client.get(reverse('devops:api_dashboard'))

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload['counts']['hosts'], 1)
        self.assertEqual(payload['counts']['open_alerts'], 1)
        self.assertEqual(payload['counts']['tasks'], 1)
        self.assertEqual([item['command'] for item in payload['recent_commands']], ['visible-command'])
        self.assertEqual([item['message'] for item in payload['recent_alerts']], ['visible alert'])

    def test_api_alerts_respects_host_scope(self):
        allowed_group = HostGroup.objects.create(name='api-alerts-allowed')
        allowed_group.hosts.add(self.host)
        other = NewLinux.objects.create(
            linux_name='api-alerts-blocked',
            linux_ip='127.0.1.12',
            linux_hostname='api-alerts-blocked',
            linux_port='22',
            linux_user='root',
            linux_passwd='bad-password',
            linux_app='',
        )
        AlertEvent.objects.create(host=self.host, message='visible alert')
        AlertEvent.objects.create(host=other, message='hidden alert')
        scope = DevOpsHostScope.objects.create(user=self.user)
        scope.groups.add(allowed_group)

        response = self.client.get(reverse('devops:api_alerts'))

        self.assertEqual(response.status_code, 200)
        messages = [item['message'] for item in response.json()['results']]
        self.assertEqual(messages, ['visible alert'])

    def test_api_collection_host_counts_use_visible_hosts(self):
        allowed_group = HostGroup.objects.create(name='api-count-allowed')
        allowed_group.hosts.add(self.host)
        other = NewLinux.objects.create(
            linux_name='api-count-blocked',
            linux_ip='127.0.1.13',
            linux_hostname='api-count-blocked',
            linux_port='22',
            linux_user='root',
            linux_passwd='bad-password',
            linux_app='',
        )
        task = BatchTask.objects.create(name='mixed task', command='uptime')
        task.hosts.add(self.host, other)
        app = DeploymentApp.objects.create(name='mixed app')
        release = DeploymentRelease.objects.create(
            app=app,
            version='v1',
            deploy_script='echo deploy',
        )
        release.hosts.add(self.host, other)
        distribution = FileDistribution.objects.create(
            name='mixed file',
            source_file=SimpleUploadedFile('artifact.txt', b'hello'),
            remote_path='/tmp/artifact.txt',
        )
        distribution.hosts.add(self.host, other)
        scope = DevOpsHostScope.objects.create(user=self.user)
        scope.groups.add(allowed_group)

        task_response = self.client.get(reverse('devops:api_tasks'))
        deployment_response = self.client.get(reverse('devops:api_deployments'))
        file_response = self.client.get(reverse('devops:api_files'))

        self.assertEqual(task_response.status_code, 200)
        self.assertEqual(deployment_response.status_code, 200)
        self.assertEqual(file_response.status_code, 200)
        self.assertEqual(task_response.json()['results'][0]['host_count'], 1)
        self.assertEqual(deployment_response.json()['results'][0]['host_count'], 1)
        self.assertEqual(file_response.json()['results'][0]['host_count'], 1)

    def test_audit_logs_can_be_filtered(self):
        AuditLog.objects.create(user='alice', action='创建主机', target_type='NewLinux', target_id='1', detail='prod-web')
        AuditLog.objects.create(user='bob', action='删除密码记录', target_type='Password', target_id='2', detail='legacy')

        response = self.client.get(reverse('devops:audit_logs'), {'q': 'prod', 'user': 'alice'})

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, '创建主机')
        self.assertNotContains(response, '删除密码记录')

    def test_audit_logs_export_csv_uses_current_filter(self):
        AuditLog.objects.create(user='alice', action='创建主机', target_type='NewLinux', target_id='1', detail='prod-web')
        AuditLog.objects.create(user='bob', action='删除密码记录', target_type='Password', target_id='2', detail='legacy')

        response = self.client.get(reverse('devops:audit_logs'), {'target_type': 'NewLinux', 'export': 'csv'})

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], 'text/csv; charset=utf-8')
        content = response.content.decode('utf-8-sig')
        self.assertIn('时间,用户,动作,对象类型,对象ID,详情,IP', content)
        self.assertIn('创建主机', content)
        self.assertNotIn('删除密码记录', content)

    def test_audit_logs_export_csv_escapes_formula_cells(self):
        AuditLog.objects.create(
            user='=cmd',
            action='+action',
            target_type='-type',
            target_id='@id',
            detail='=HYPERLINK("http://example.com")',
            ip_address='127.0.0.1',
        )

        response = self.client.get(reverse('devops:audit_logs'), {'export': 'csv'})

        self.assertEqual(response.status_code, 200)
        content = response.content.decode('utf-8-sig')
        self.assertIn("'=cmd", content)
        self.assertIn("'+action", content)
        self.assertIn("'-type", content)
        self.assertIn("'@id", content)
        self.assertIn("'=HYPERLINK", content)

    def test_api_audit_logs_requires_login(self):
        self.client.session.flush()

        response = self.client.get(reverse('devops:api_audit_logs'))

        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json()['code'], 'unauthorized')

    def test_api_audit_logs_requires_audit_viewer_permission(self):
        self.set_role(DevOpsRole.ROLE_VIEWER)
        DevOpsModulePermission.objects.create(
            user=self.user,
            module=DevOpsModulePermission.MODULE_AUDIT,
            role='none',
        )

        response = self.client.get(reverse('devops:api_audit_logs'))

        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.json()['code'], 'forbidden')

    def test_api_audit_logs_returns_logs_for_audit_viewer(self):
        self.set_role(DevOpsRole.ROLE_VIEWER)
        DevOpsModulePermission.objects.create(
            user=self.user,
            module=DevOpsModulePermission.MODULE_AUDIT,
            role=DevOpsRole.ROLE_VIEWER,
        )
        AuditLog.objects.create(
            user='alice',
            action='创建主机',
            target_type='NewLinux',
            target_id='1',
            detail='prod-web',
            ip_address='127.0.0.1',
        )

        response = self.client.get(reverse('devops:api_audit_logs'))

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertTrue(payload['ok'])
        self.assertEqual(payload['results'][0]['user'], 'alice')
        self.assertEqual(payload['results'][0]['action'], '创建主机')
        self.assertEqual(payload['results'][0]['target_type'], 'NewLinux')
        self.assertEqual(payload['results'][0]['target_id'], '1')
        self.assertEqual(payload['results'][0]['detail'], 'prod-web')
        self.assertEqual(payload['results'][0]['ip_address'], '127.0.0.1')
        self.assertIn('created_at', payload['results'][0])

    def test_api_audit_logs_filters_results(self):
        self.set_role(DevOpsRole.ROLE_VIEWER)
        DevOpsModulePermission.objects.create(
            user=self.user,
            module=DevOpsModulePermission.MODULE_AUDIT,
            role=DevOpsRole.ROLE_VIEWER,
        )
        AuditLog.objects.create(user='alice', action='创建主机', target_type='NewLinux', target_id='1', detail='prod-web')
        AuditLog.objects.create(user='bob', action='删除密码记录', target_type='Password', target_id='2', detail='legacy')

        response = self.client.get(reverse('devops:api_audit_logs'), {
            'q': 'prod',
            'user': 'ali',
            'action': '创建',
            'target_type': 'Linux',
        })

        self.assertEqual(response.status_code, 200)
        results = response.json()['results']
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]['user'], 'alice')
        self.assertEqual(results[0]['target_type'], 'NewLinux')

    def test_api_audit_logs_redacts_sensitive_detail_fragments(self):
        self.set_role(DevOpsRole.ROLE_VIEWER)
        DevOpsModulePermission.objects.create(
            user=self.user,
            module=DevOpsModulePermission.MODULE_AUDIT,
            role=DevOpsRole.ROLE_VIEWER,
        )
        AuditLog.objects.create(
            user='alice',
            action='更新通知',
            target_type='NotificationChannel',
            target_id='1',
            detail='webhook=https://hooks.example.test/send token=abc123 password=plain enc:gAAAA-secret key=rawkey',
        )

        response = self.client.get(reverse('devops:api_audit_logs'))

        self.assertEqual(response.status_code, 200)
        detail = response.json()['results'][0]['detail']
        self.assertIn('[redacted-url]', detail)
        self.assertIn('token=[redacted]', detail)
        self.assertIn('password=[redacted]', detail)
        self.assertIn('enc:[redacted]', detail)
        self.assertIn('key=[redacted]', detail)
        self.assertNotIn('hooks.example.test', detail)
        self.assertNotIn('abc123', detail)
        self.assertNotIn('plain', detail)
        self.assertNotIn('gAAAA-secret', detail)
        self.assertNotIn('rawkey', detail)

    def test_cleanup_audit_logs_respects_retention_days(self):
        old_log = AuditLog.objects.create(user='alice', action='old')
        new_log = AuditLog.objects.create(user='bob', action='new')
        AuditLog.objects.filter(id=old_log.id).update(created_at=timezone.now() - timezone.timedelta(days=40))
        AuditLog.objects.filter(id=new_log.id).update(created_at=timezone.now() - timezone.timedelta(days=2))

        deleted = cleanup_audit_logs(30)

        self.assertEqual(deleted, 1)
        self.assertFalse(AuditLog.objects.filter(id=old_log.id).exists())
        self.assertTrue(AuditLog.objects.filter(id=new_log.id).exists())

    def test_cleanup_audit_logs_disabled_by_zero_days(self):
        AuditLog.objects.create(user='alice', action='old')

        deleted = cleanup_audit_logs(0)

        self.assertEqual(deleted, 0)
        self.assertEqual(AuditLog.objects.count(), 1)

    def test_cleanup_audit_logs_command_dry_run_does_not_delete(self):
        old_log = AuditLog.objects.create(user='alice', action='old')
        AuditLog.objects.filter(id=old_log.id).update(created_at=timezone.now() - timezone.timedelta(days=40))
        output = StringIO()

        call_command('cleanup_audit_logs', '--days=30', '--dry-run', stdout=output)

        self.assertIn('将清理 1 条审计日志', output.getvalue())
        self.assertTrue(AuditLog.objects.filter(id=old_log.id).exists())

    def test_api_command_post_creates_record(self):
        response = self.client.post(
            reverse('devops:api_commands'),
            data=json.dumps({'host_id': self.host.id, 'command': 'uptime'}),
            content_type='application/json',
        )

        self.assertEqual(response.status_code, 201)
        payload = response.json()
        self.assertTrue(payload['ok'])
        self.assertEqual(payload['record']['command'], 'uptime')
        self.assertTrue(CommandExecution.objects.filter(command='uptime').exists())

    def test_api_command_post_invalid_json_uses_json_error_code(self):
        response = self.client.post(
            reverse('devops:api_commands'),
            data='{bad json',
            content_type='application/json',
        )

        self.assertEqual(response.status_code, 400)
        payload = response.json()
        self.assertFalse(payload['ok'])
        self.assertEqual(payload['code'], 'invalid_json')
        self.assertFalse(CommandExecution.objects.exists())

    def test_api_command_post_rejects_unscoped_host_with_json_error(self):
        allowed_group = HostGroup.objects.create(name='api-command-submit-allowed')
        allowed_group.hosts.add(self.host)
        other = NewLinux.objects.create(
            linux_name='api-command-submit-blocked',
            linux_ip='127.0.1.14',
            linux_hostname='api-command-submit-blocked',
            linux_port='22',
            linux_user='root',
            linux_passwd='bad-password',
            linux_app='',
        )
        scope = DevOpsHostScope.objects.create(user=self.user)
        scope.groups.add(allowed_group)

        response = self.client.post(
            reverse('devops:api_commands'),
            data=json.dumps({'host_id': other.id, 'command': 'uptime'}),
            content_type='application/json',
        )

        self.assertEqual(response.status_code, 403)
        payload = response.json()
        self.assertFalse(payload['ok'])
        self.assertEqual(payload['code'], 'host_forbidden')
        self.assertFalse(CommandExecution.objects.exists())

    def test_api_dangerous_command_creates_approval(self):
        response = self.client.post(
            reverse('devops:api_commands'),
            data=json.dumps({'host_id': self.host.id, 'command': 'rm -rf /'}),
            content_type='application/json',
        )

        self.assertEqual(response.status_code, 202)
        payload = response.json()
        self.assertTrue(payload['requires_approval'])
        self.assertEqual(payload['approval']['request_type'], ApprovalRequest.TYPE_COMMAND)

    def test_api_approval_decide_requires_login(self):
        approval = ApprovalRequest.objects.create(
            request_type=ApprovalRequest.TYPE_COMMAND,
            title='api approval login',
            host=self.host,
            command='uptime',
            requester='alice',
        )
        self.client.session.flush()

        response = self.client.post(
            reverse('devops:api_approval_decide', args=[approval.id]),
            data=json.dumps({'action': 'reject'}),
            content_type='application/json',
        )

        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json()['code'], 'unauthorized')

    def test_api_approval_decide_requires_approval_admin(self):
        self.set_role(DevOpsRole.ROLE_OPERATOR)
        DevOpsModulePermission.objects.create(
            user=self.user,
            module=DevOpsModulePermission.MODULE_APPROVAL,
            role=DevOpsRole.ROLE_VIEWER,
        )
        approval = ApprovalRequest.objects.create(
            request_type=ApprovalRequest.TYPE_COMMAND,
            title='api approval forbidden',
            host=self.host,
            command='uptime',
            requester='alice',
        )

        response = self.client.post(
            reverse('devops:api_approval_decide', args=[approval.id]),
            data=json.dumps({'action': 'reject'}),
            content_type='application/json',
        )

        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.json()['code'], 'forbidden')

    def test_api_approval_decide_rejects_invalid_json(self):
        self.set_role(DevOpsRole.ROLE_ADMIN)
        approval = ApprovalRequest.objects.create(
            request_type=ApprovalRequest.TYPE_COMMAND,
            title='api approval invalid json',
            host=self.host,
            command='uptime',
            requester='alice',
        )

        response = self.client.post(
            reverse('devops:api_approval_decide', args=[approval.id]),
            data='{bad json',
            content_type='application/json',
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()['code'], 'invalid_json')

    def test_api_approval_decide_hides_unscoped_approval(self):
        self.set_role(DevOpsRole.ROLE_ADMIN)
        allowed_group = HostGroup.objects.create(name='api-approval-allowed')
        allowed_group.hosts.add(self.host)
        other = NewLinux.objects.create(
            linux_name='api-approval-blocked',
            linux_ip='127.0.1.15',
            linux_hostname='api-approval-blocked',
            linux_port='22',
            linux_user='root',
            linux_passwd='bad-password',
            linux_app='',
        )
        scope = DevOpsHostScope.objects.create(user=self.user)
        scope.groups.add(allowed_group)
        approval = ApprovalRequest.objects.create(
            request_type=ApprovalRequest.TYPE_COMMAND,
            title='api hidden approval',
            host=other,
            command='uptime',
            requester='alice',
        )

        response = self.client.post(
            reverse('devops:api_approval_decide', args=[approval.id]),
            data=json.dumps({'action': 'reject'}),
            content_type='application/json',
        )

        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.json()['code'], 'not_found')
        approval.refresh_from_db()
        self.assertEqual(approval.status, ApprovalRequest.STATUS_PENDING)

    def test_api_approval_decide_self_request_stays_pending(self):
        self.set_role(DevOpsRole.ROLE_ADMIN)
        approval = ApprovalRequest.objects.create(
            request_type=ApprovalRequest.TYPE_COMMAND,
            title='api self approval',
            host=self.host,
            command='uptime',
            requester=self.user.user,
        )

        response = self.client.post(
            reverse('devops:api_approval_decide', args=[approval.id]),
            data=json.dumps({'action': 'approve', 'comment': 'approved'}),
            content_type='application/json',
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()['code'], 'validation_error')
        approval.refresh_from_db()
        self.assertEqual(approval.status, ApprovalRequest.STATUS_PENDING)
        self.assertEqual(approval.comment, '申请人与审批人不能为同一人')
        self.assertTrue(AuditLog.objects.filter(action='API审批自审拦截', target_id=str(approval.id)).exists())

    def test_api_approval_decide_rejects_pending_request(self):
        self.set_role(DevOpsRole.ROLE_ADMIN)
        approval = ApprovalRequest.objects.create(
            request_type=ApprovalRequest.TYPE_COMMAND,
            title='api reject approval',
            host=self.host,
            command='uptime',
            requester='alice',
        )

        with mock.patch('devops.api.notify_approval') as notify:
            response = self.client.post(
                reverse('devops:api_approval_decide', args=[approval.id]),
                data=json.dumps({'action': 'reject', 'comment': 'not now'}),
                content_type='application/json',
            )

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertTrue(payload['ok'])
        self.assertEqual(payload['approval']['status'], ApprovalRequest.STATUS_REJECTED)
        approval.refresh_from_db()
        self.assertEqual(approval.status, ApprovalRequest.STATUS_REJECTED)
        self.assertEqual(approval.approver, self.user.user)
        self.assertEqual(approval.comment, 'not now')
        notify.assert_called_once_with(approval, '拒绝')
        self.assertTrue(AuditLog.objects.filter(action='API拒绝审批', target_id=str(approval.id)).exists())

    def test_api_approval_decide_approves_and_executes_request(self):
        self.set_role(DevOpsRole.ROLE_ADMIN)
        approval = ApprovalRequest.objects.create(
            request_type=ApprovalRequest.TYPE_COMMAND,
            title='api approve approval',
            host=self.host,
            command='uptime',
            requester='alice',
        )

        def mark_executed(item, role):
            item.status = ApprovalRequest.STATUS_EXECUTED
            item.executed_at = timezone.now()
            item.save(update_fields=['status', 'executed_at'])
            return item

        with mock.patch('devops.api.execute_approval_request', side_effect=mark_executed) as execute:
            response = self.client.post(
                reverse('devops:api_approval_decide', args=[approval.id]),
                data=json.dumps({'action': 'approve', 'comment': 'approved'}),
                content_type='application/json',
            )

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertTrue(payload['ok'])
        self.assertEqual(payload['approval']['status'], ApprovalRequest.STATUS_EXECUTED)
        approval.refresh_from_db()
        self.assertEqual(approval.approver, self.user.user)
        self.assertEqual(approval.comment, 'approved')
        self.assertEqual(approval.status, ApprovalRequest.STATUS_EXECUTED)
        execute.assert_called_once()
        self.assertTrue(AuditLog.objects.filter(action='API批准审批', target_id=str(approval.id)).exists())

    def test_api_approval_decide_rejects_non_pending_request(self):
        self.set_role(DevOpsRole.ROLE_ADMIN)
        approval = ApprovalRequest.objects.create(
            request_type=ApprovalRequest.TYPE_COMMAND,
            title='api approved approval',
            host=self.host,
            command='uptime',
            requester='alice',
            status=ApprovalRequest.STATUS_APPROVED,
        )

        response = self.client.post(
            reverse('devops:api_approval_decide', args=[approval.id]),
            data=json.dumps({'action': 'reject'}),
            content_type='application/json',
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()['code'], 'validation_error')
        approval.refresh_from_db()
        self.assertEqual(approval.status, ApprovalRequest.STATUS_APPROVED)

    def test_api_command_detail_respects_host_scope(self):
        allowed_group = HostGroup.objects.create(name='api-allowed')
        allowed_group.hosts.add(self.host)
        other = NewLinux.objects.create(
            linux_name='api-blocked',
            linux_ip='127.0.0.4',
            linux_hostname='blocked',
            linux_port='22',
            linux_user='root',
            linux_passwd='bad-password',
            linux_app='',
        )
        record = CommandExecution.objects.create(host=other, command='uptime')
        scope = DevOpsHostScope.objects.create(user=self.user)
        scope.groups.add(allowed_group)

        response = self.client.get(reverse('devops:api_command_detail', args=[record.id]))

        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.json()['code'], 'host_forbidden')

    def test_api_task_post_creates_task(self):
        response = self.client.post(
            reverse('devops:api_tasks'),
            data=json.dumps({'name': 'api task', 'host_ids': [self.host.id], 'command': 'hostname'}),
            content_type='application/json',
        )

        self.assertEqual(response.status_code, 201)
        task = BatchTask.objects.get(name='api task')
        self.assertEqual(task.hosts.get(), self.host)

    def test_api_metrics_returns_series(self):
        record_metric_sample(self.host, MetricSample.METRIC_CPU, 0.5)
        record_metric_sample(self.host, MetricSample.METRIC_MEMORY, 0.7)

        response = self.client.get(reverse('devops:api_metrics'), {'host': self.host.id, 'range': '24h'})

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload['host']['id'], self.host.id)
        self.assertIn('cpu', payload['series'])

    def test_dangerous_command_auto_creates_approval(self):
        response = self.client.post(reverse('devops:command_center'), {
            'host': self.host.id,
            'command': 'rm -rf /',
        })

        self.assertEqual(response.status_code, 302)
        self.assertFalse(CommandExecution.objects.exists())
        approval = ApprovalRequest.objects.get()
        self.assertEqual(approval.request_type, ApprovalRequest.TYPE_COMMAND)
        self.assertEqual(approval.status, ApprovalRequest.STATUS_PENDING)
        self.assertIn('拦截', approval.reason)
        self.assertTrue(AuditLog.objects.filter(action='高危命令转审批').exists())

    def test_default_command_policy_blocks_common_variants(self):
        blocked_commands = [
            'rm -fr /',
            'RM   -rf   /',
        ]

        for command in blocked_commands:
            decision, policy = evaluate_command_policy(command)
            self.assertEqual(decision, COMMAND_BLOCKED)

    def test_default_command_policy_rejects_power_command_variants(self):
        commands = [
            'sudo reboot',
            '/sbin/poweroff',
        ]

        for command in commands:
            decision, policy = evaluate_command_policy(command)
            self.assertNotEqual(decision, COMMAND_ALLOWED)

    def test_viewer_cannot_execute_command_when_roles_are_configured(self):
        self.set_role(DevOpsRole.ROLE_VIEWER)

        response = self.client.post(reverse('devops:command_center'), {
            'host': self.host.id,
            'command': 'uptime',
        })

        self.assertEqual(response.status_code, 403)
        self.assertFalse(CommandExecution.objects.exists())

    def test_admin_required_command_auto_creates_approval_for_operator(self):
        self.set_role(DevOpsRole.ROLE_OPERATOR)
        allowed_group = HostGroup.objects.create(name='operator-allowed')
        allowed_group.hosts.add(self.host)
        scope = DevOpsHostScope.objects.create(user=self.user)
        scope.groups.add(allowed_group)

        response = self.client.post(reverse('devops:command_center'), {
            'host': self.host.id,
            'command': 'reboot',
        })

        self.assertEqual(response.status_code, 302)
        self.assertFalse(CommandExecution.objects.exists())
        approval = ApprovalRequest.objects.get()
        self.assertEqual(approval.request_type, ApprovalRequest.TYPE_COMMAND)
        self.assertIn('管理员权限', approval.reason)

    def test_blocked_batch_task_records_host_results(self):
        response = self.client.post(reverse('devops:batch_tasks'), {
            'name': 'dangerous batch',
            'hosts': [self.host.id],
            'command': 'rm -rf /',
        })

        self.assertEqual(response.status_code, 302)
        task = BatchTask.objects.get()
        result = BatchTaskResult.objects.get(task=task)
        self.assertEqual(task.status, BatchTask.STATUS_BLOCKED)
        self.assertEqual(result.host, self.host)
        self.assertEqual(result.status, CommandExecution.STATUS_BLOCKED)

    def test_group_and_tag_can_be_created(self):
        group_response = self.client.post(reverse('devops:group_create'), {
            'name': 'prod',
            'description': 'production hosts',
            'hosts': [self.host.id],
        })
        tag_response = self.client.post(reverse('devops:tag_create'), {
            'name': 'web',
            'color': 'primary',
            'description': 'web servers',
            'hosts': [self.host.id],
        })

        self.assertEqual(group_response.status_code, 302)
        self.assertEqual(tag_response.status_code, 302)
        self.assertEqual(HostGroup.objects.get(name='prod').hosts.get(), self.host)
        self.assertEqual(HostTag.objects.get(name='web').hosts.get(), self.host)

    def test_module_permission_overrides_global_role(self):
        self.set_role(DevOpsRole.ROLE_ADMIN)
        DevOpsModulePermission.objects.create(
            user=self.user,
            module=DevOpsModulePermission.MODULE_COMMAND,
            role=DevOpsRole.ROLE_VIEWER,
        )

        response = self.client.post(reverse('devops:command_center'), {
            'host': self.host.id,
            'command': 'uptime',
        })

        self.assertEqual(response.status_code, 403)
        self.assertFalse(CommandExecution.objects.exists())

    def test_host_scope_filters_command_form_and_records(self):
        allowed_group = HostGroup.objects.create(name='allowed')
        allowed_group.hosts.add(self.host)
        other = NewLinux.objects.create(
            linux_name='out-of-scope',
            linux_ip='127.0.0.2',
            linux_hostname='other',
            linux_port='22',
            linux_user='root',
            linux_passwd='bad-password',
            linux_app='',
        )
        CommandExecution.objects.create(host=self.host, command='uptime')
        CommandExecution.objects.create(host=other, command='hostname')
        scope = DevOpsHostScope.objects.create(user=self.user)
        scope.groups.add(allowed_group)

        response = self.client.get(reverse('devops:command_center'))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'test-host')
        self.assertNotContains(response, 'out-of-scope')
        self.assertContains(response, 'uptime')
        self.assertNotContains(response, 'hostname')

    def test_host_scope_allows_hosts_by_tag(self):
        allowed_tag = HostTag.objects.create(name='allowed-tag', color='success')
        allowed_tag.hosts.add(self.host)
        other = NewLinux.objects.create(
            linux_name='tag-out-of-scope',
            linux_ip='127.0.0.12',
            linux_hostname='tag-other',
            linux_port='22',
            linux_user='root',
            linux_passwd='bad-password',
            linux_app='',
        )
        CommandExecution.objects.create(host=self.host, command='uptime')
        CommandExecution.objects.create(host=other, command='hostname')
        scope = DevOpsHostScope.objects.create(user=self.user)
        scope.tags.add(allowed_tag)

        response = self.client.get(reverse('devops:command_center'))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'test-host')
        self.assertNotContains(response, 'tag-out-of-scope')
        self.assertContains(response, 'uptime')
        self.assertNotContains(response, 'hostname')

    def test_empty_host_scope_allows_no_hosts(self):
        DevOpsHostScope.objects.create(user=self.user)
        CommandExecution.objects.create(host=self.host, command='uptime')

        response = self.client.get(reverse('devops:command_center'))

        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, 'test-host')
        self.assertNotContains(response, 'uptime')

    def test_non_admin_without_host_scope_sees_no_hosts_by_default(self):
        self.set_role(DevOpsRole.ROLE_OPERATOR)

        response = self.client.get(reverse('devops:api_hosts'))

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()['results'], [])

    def test_admin_without_host_scope_sees_all_hosts_by_default(self):
        self.set_role(DevOpsRole.ROLE_ADMIN)

        response = self.client.get(reverse('devops:api_hosts'))

        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.json()['results']), 1)

    def test_host_scope_set_saves_tags(self):
        self.set_role(DevOpsRole.ROLE_ADMIN)
        group = HostGroup.objects.create(name='scope-group')
        group.hosts.add(self.host)
        tag = HostTag.objects.create(name='scope-tag', color='primary')
        tag.hosts.add(self.host)

        response = self.client.post(reverse('devops:host_scope_set'), {
            'user': self.user.id,
            'groups': [group.id],
            'tags': [tag.id],
        })

        self.assertEqual(response.status_code, 302)
        scope = DevOpsHostScope.objects.get(user=self.user)
        self.assertEqual(scope.groups.get(), group)
        self.assertEqual(scope.tags.get(), tag)
        log = AuditLog.objects.get(action='设置主机范围')
        self.assertIn('用户=tester', log.detail)
        self.assertIn('主机组=scope-group', log.detail)
        self.assertIn('标签=scope-tag', log.detail)

    def test_host_scope_blocks_command_detail_for_unscoped_host(self):
        allowed_group = HostGroup.objects.create(name='allowed-detail')
        allowed_group.hosts.add(self.host)
        other = NewLinux.objects.create(
            linux_name='blocked-detail',
            linux_ip='127.0.0.3',
            linux_hostname='blocked',
            linux_port='22',
            linux_user='root',
            linux_passwd='bad-password',
            linux_app='',
        )
        record = CommandExecution.objects.create(host=other, command='uptime')
        scope = DevOpsHostScope.objects.create(user=self.user)
        scope.groups.add(allowed_group)

        response = self.client.get(reverse('devops:command_detail', args=[record.id]))

        self.assertEqual(response.status_code, 403)

    def test_command_detail_renders_full_record(self):
        record = CommandExecution.objects.create(
            host=self.host,
            command='uptime',
            status=CommandExecution.STATUS_SUCCESS,
            output='system up',
            created_by=self.user.user,
        )

        response = self.client.get(reverse('devops:command_detail', args=[record.id]))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'uptime')
        self.assertContains(response, 'system up')
        self.assertContains(response, '重试次数')
        self.assertContains(response, 'SSH连接超时')
        self.assertContains(response, '命令超时')

    def test_background_job_runs_inline_during_tests(self):
        state = []

        result = enqueue_background_job(lambda value: state.append(value), 'done')

        self.assertIsNone(result)
        self.assertEqual(state, ['done'])

    @mock.patch('devops.services.print')
    def test_background_job_marks_command_failed_on_unhandled_exception(self, print_mock):
        record = CommandExecution.objects.create(
            host=self.host,
            command='uptime',
            status=CommandExecution.STATUS_RUNNING,
            created_by=self.user.user,
        )

        def boom(target_record):
            raise RuntimeError('worker crashed')

        run_background_job(boom, (record,), {})

        record.refresh_from_db()
        self.assertEqual(record.status, CommandExecution.STATUS_FAILED)
        self.assertIn('worker crashed', record.error)
        self.assertIsNotNone(record.finished_at)
        self.assertTrue(AuditLog.objects.filter(
            action='后台任务异常',
            target_type='CommandExecution',
            target_id=str(record.id),
        ).exists())

    @mock.patch('devops.services.print')
    def test_background_job_marks_batch_task_failed_on_unhandled_exception(self, print_mock):
        task = BatchTask.objects.create(
            name='boom task',
            command='uptime',
            status=BatchTask.STATUS_RUNNING,
            created_by=self.user.user,
        )

        def boom(target_task):
            raise RuntimeError('batch crashed')

        run_background_job(boom, (task,), {})

        task.refresh_from_db()
        self.assertEqual(task.status, BatchTask.STATUS_FAILED)
        self.assertIn('batch crashed', task.summary)
        self.assertIsNotNone(task.finished_at)

    def test_batch_task_detail_renders_runtime_config(self):
        task = BatchTask.objects.create(
            name='detail task',
            command='uptime',
            status=BatchTask.STATUS_SUCCESS,
            created_by=self.user.user,
        )
        task.hosts.add(self.host)
        BatchTaskResult.objects.create(
            task=task,
            host=self.host,
            status=CommandExecution.STATUS_SUCCESS,
            output='ok',
        )

        response = self.client.get(reverse('devops:batch_task_detail', args=[task.id]))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, '重试次数')
        self.assertContains(response, 'SSH连接超时')
        self.assertContains(response, '命令超时')

    @mock.patch('devops.services.create_host_ssh_client', side_effect=socket.timeout('timed out'))
    def test_execute_command_record_classifies_ssh_error(self, create_host_ssh_client):
        record = CommandExecution.objects.create(
            host=self.host,
            command='uptime',
            created_by=self.user.user,
        )

        execute_command_record(record)

        record.refresh_from_db()
        self.assertEqual(record.status, CommandExecution.STATUS_FAILED)
        self.assertIn('超时', record.error)

    @mock.patch('devops.services.settings.DEVOPS_TASK_RETRY_COUNT', 1)
    @mock.patch('devops.services.create_host_ssh_client')
    def test_execute_command_record_retries_transient_ssh_error(self, create_host_ssh_client):
        class FakeStream(object):
            def __init__(self, value):
                self.value = value

            def read(self):
                return self.value

        class FakeClient(object):
            def exec_command(self, command, timeout=60):
                return None, FakeStream(b'ok'), FakeStream(b'')

            def close(self):
                pass

        create_host_ssh_client.side_effect = [socket.timeout('timed out'), FakeClient()]
        record = CommandExecution.objects.create(
            host=self.host,
            command='uptime',
            created_by=self.user.user,
        )

        execute_command_record(record)

        record.refresh_from_db()
        self.assertEqual(record.status, CommandExecution.STATUS_SUCCESS)
        self.assertEqual(record.output, 'ok')
        self.assertEqual(create_host_ssh_client.call_count, 2)

    @mock.patch('devops.services.settings.DEVOPS_COMMAND_OUTPUT_MAX_BYTES', 4)
    @mock.patch('devops.services.create_host_ssh_client')
    def test_execute_command_record_truncates_large_output(self, create_host_ssh_client):
        class FakeStream(object):
            def __init__(self, value):
                self.value = value

            def read(self):
                return self.value

        class FakeClient(object):
            def exec_command(self, command, timeout=60):
                return None, FakeStream(b'abcdef'), FakeStream(b'')

            def close(self):
                pass

        create_host_ssh_client.return_value = FakeClient()
        record = CommandExecution.objects.create(
            host=self.host,
            command='cat big.log',
            created_by=self.user.user,
        )

        execute_command_record(record)

        record.refresh_from_db()
        self.assertTrue(record.output.startswith('abcd'))
        self.assertIn('输出已截断', record.output)

    @mock.patch('devops.services.settings.DEVOPS_COMMAND_TIMEOUT_SECONDS', 7)
    @mock.patch('devops.services.settings.DEVOPS_SSH_CONNECT_TIMEOUT_SECONDS', 3)
    @mock.patch('devops.services.create_host_ssh_client')
    def test_execute_command_record_uses_configured_timeouts(self, create_host_ssh_client):
        class FakeStream(object):
            def __init__(self, value):
                self.value = value

            def read(self):
                return self.value

        class FakeClient(object):
            def __init__(self):
                self.exec_timeout = None

            def exec_command(self, command, timeout=60):
                self.exec_timeout = timeout
                return None, FakeStream(b'ok'), FakeStream(b'')

            def close(self):
                pass

        client = FakeClient()
        create_host_ssh_client.return_value = client
        record = CommandExecution.objects.create(
            host=self.host,
            command='uptime',
            created_by=self.user.user,
        )

        execute_command_record(record)

        self.assertEqual(create_host_ssh_client.call_args[1]['timeout'], 3)
        self.assertEqual(client.exec_timeout, 7)

    @mock.patch('devops.services.create_host_ssh_client')
    def test_execute_command_record_is_idempotent_after_started(self, create_host_ssh_client):
        record = CommandExecution.objects.create(
            host=self.host,
            command='uptime',
            status=CommandExecution.STATUS_RUNNING,
            created_by=self.user.user,
        )

        execute_command_record(record)

        record.refresh_from_db()
        self.assertEqual(record.status, CommandExecution.STATUS_RUNNING)
        create_host_ssh_client.assert_not_called()

    def test_execute_batch_task_is_idempotent_after_started(self):
        task = BatchTask.objects.create(
            name='already running',
            command='uptime',
            status=BatchTask.STATUS_RUNNING,
            created_by=self.user.user,
        )
        task.hosts.add(self.host)

        execute_batch_task(task)

        task.refresh_from_db()
        self.assertEqual(task.status, BatchTask.STATUS_RUNNING)
        self.assertFalse(CommandExecution.objects.exists())
        self.assertFalse(BatchTaskResult.objects.exists())

    def test_service_operation_rejects_unsafe_service_name(self):
        self.set_role(DevOpsRole.ROLE_OPERATOR)
        group = HostGroup.objects.create(name='service-allowed')
        group.hosts.add(self.host)
        scope = DevOpsHostScope.objects.create(user=self.user)
        scope.groups.add(group)

        response = self.client.post(reverse('devops:service_manage'), {
            'host': self.host.id,
            'service_name': 'nginx; reboot',
            'action': 'restart',
        })

        self.assertEqual(response.status_code, 200)
        self.assertFalse(CommandExecution.objects.filter(command__contains='nginx; reboot').exists())
        self.assertFalse(ServiceOperation.objects.exists())

    def test_alerts_are_deduplicated_by_host_and_metric(self):
        with mock.patch('devops.services.notify_alert') as notify:
            first, created_first = record_alert(self.host, 'cpu', 'cpu high')
            second, created_second = record_alert(self.host, 'cpu', 'cpu still high')

        self.assertTrue(created_first)
        self.assertFalse(created_second)
        self.assertEqual(first.id, second.id)
        second.refresh_from_db()
        self.assertEqual(second.repeat_count, 2)
        self.assertEqual(AlertEvent.objects.count(), 1)
        notify.assert_called_once_with(first)

    def test_alert_silence_marks_matching_alert(self):
        now = timezone.now()
        AlertSilence.objects.create(
            host=self.host,
            metric='memory',
            reason='maintenance',
            starts_at=now - timezone.timedelta(minutes=5),
            ends_at=now + timezone.timedelta(minutes=30),
            created_by=self.user.user,
        )

        with mock.patch('devops.services.notify_alert') as notify:
            alert, created = record_alert(self.host, 'memory', 'memory high')

        self.assertTrue(created)
        self.assertEqual(alert.status, AlertEvent.STATUS_SILENCED)
        notify.assert_not_called()

    def test_alert_silence_rejects_end_before_start(self):
        self.set_role(DevOpsRole.ROLE_OPERATOR)
        now = timezone.now()

        response = self.client.post(reverse('devops:silence_create'), {
            'host': self.host.id,
            'metric': 'cpu',
            'reason': 'invalid window',
            'starts_at': (now + timezone.timedelta(hours=1)).strftime('%Y-%m-%d %H:%M'),
            'ends_at': now.strftime('%Y-%m-%d %H:%M'),
        })

        self.assertEqual(response.status_code, 302)
        self.assertFalse(AlertSilence.objects.filter(reason='invalid window').exists())

    def test_alert_update_creates_history(self):
        self.set_role(DevOpsRole.ROLE_OPERATOR)
        alert = AlertEvent.objects.create(
            host=self.host,
            metric='disk',
            message='disk high',
            fingerprint='host:disk',
        )

        response = self.client.post(reverse('devops:alert_update', args=[alert.id]), {
            'status': AlertEvent.STATUS_RESOLVED,
            'handler': self.user.user,
            'remark': 'fixed',
        })

        self.assertEqual(response.status_code, 302)
        history = AlertHistory.objects.get(alert=alert)
        self.assertEqual(history.from_status, AlertEvent.STATUS_OPEN)
        self.assertEqual(history.to_status, AlertEvent.STATUS_RESOLVED)

    def test_alert_events_can_filter_collection_failures(self):
        AlertEvent.objects.create(
            host=self.host,
            metric='collector',
            level=AlertEvent.LEVEL_CRITICAL,
            message='collection failed',
            fingerprint='collector',
        )
        AlertEvent.objects.create(
            host=self.host,
            metric='cpu',
            level=AlertEvent.LEVEL_WARNING,
            message='cpu high',
            fingerprint='cpu',
        )

        response = self.client.get(reverse('devops:alert_events'), {'metric': 'collector'})

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'collection failed')
        self.assertNotContains(response, 'cpu high')
        self.assertContains(response, '采集失败 1')
        self.assertContains(response, '告警名称')
        self.assertContains(response, '告警类型')
        self.assertContains(response, '创建时间')
        self.assertContains(response, '创建人员')
        self.assertContains(response, '采集失败告警')
        self.assertContains(response, '系统采集')

        keyword_response = self.client.get(reverse('devops:alert_events'), {'q': 'CPU告警'})
        self.assertEqual(keyword_response.status_code, 200)
        self.assertContains(keyword_response, 'cpu high')
        self.assertNotContains(keyword_response, 'collection failed')

    def test_alert_update_returns_to_filtered_alert_page(self):
        self.set_role(DevOpsRole.ROLE_OPERATOR)
        alert = AlertEvent.objects.create(
            host=self.host,
            metric='collector',
            message='collection failed',
            fingerprint='collector',
        )

        response = self.client.post(reverse('devops:alert_update', args=[alert.id]), {
            'status': AlertEvent.STATUS_PROCESSING,
            'handler': self.user.user,
            'remark': 'checking',
            'next': reverse('devops:alert_events') + '?metric=collector',
        })

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response['Location'], reverse('devops:alert_events') + '?metric=collector')

    def test_alert_update_rejects_external_next_url(self):
        self.set_role(DevOpsRole.ROLE_OPERATOR)
        alert = AlertEvent.objects.create(
            host=self.host,
            metric='collector',
            message='collection failed',
            fingerprint='collector-external-next',
        )

        response = self.client.post(reverse('devops:alert_update', args=[alert.id]), {
            'status': AlertEvent.STATUS_PROCESSING,
            'handler': self.user.user,
            'remark': 'checking',
            'next': 'https://evil.example/phish',
        })

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response['Location'], reverse('devops:alert_events'))

    def test_metric_samples_are_recorded_and_latest_map_returns_newest(self):
        older = timezone.now() - timezone.timedelta(minutes=5)
        newer = timezone.now()
        record_metric_sample(self.host, MetricSample.METRIC_CPU, 0.5, collected_at=older)
        latest = record_metric_sample(self.host, MetricSample.METRIC_CPU, 0.8, collected_at=newer)

        latest_map = latest_metric_map([self.host])

        self.assertEqual(latest_map[(self.host.id, MetricSample.METRIC_CPU)].id, latest.id)

    def test_cleanup_metric_samples_removes_only_expired_rows(self):
        now = timezone.now()
        old_sample = record_metric_sample(
            self.host,
            MetricSample.METRIC_CPU,
            0.5,
            collected_at=now - timezone.timedelta(days=40),
        )
        fresh_sample = record_metric_sample(
            self.host,
            MetricSample.METRIC_CPU,
            0.8,
            collected_at=now - timezone.timedelta(days=2),
        )

        deleted = cleanup_metric_samples(retention_days=30, now=now)

        self.assertEqual(deleted, 1)
        self.assertFalse(MetricSample.objects.filter(id=old_sample.id).exists())
        self.assertTrue(MetricSample.objects.filter(id=fresh_sample.id).exists())

    def test_cleanup_metric_samples_disabled_with_zero_days(self):
        record_metric_sample(
            self.host,
            MetricSample.METRIC_MEMORY,
            0.5,
            collected_at=timezone.now() - timezone.timedelta(days=40),
        )

        deleted = cleanup_metric_samples(retention_days=0)

        self.assertEqual(deleted, 0)
        self.assertEqual(MetricSample.objects.count(), 1)

    def test_metrics_history_page_renders_samples(self):
        record_metric_sample(self.host, MetricSample.METRIC_MEMORY, 0.7)

        response = self.client.get(reverse('devops:metrics_history'))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, '监控历史')
        self.assertContains(response, '内存')
        self.assertContains(response, '70.00%')

    def test_metrics_history_filters_by_host_and_range(self):
        other = NewLinux.objects.create(
            linux_name='other-host',
            linux_ip='127.0.0.2',
            linux_hostname='other',
            linux_port='22',
            linux_user='root',
            linux_passwd='bad-password',
            linux_app='',
        )
        record_metric_sample(other, MetricSample.METRIC_CPU, 0.3)
        record_metric_sample(self.host, MetricSample.METRIC_CPU, 0.8)
        record_metric_sample(self.host, MetricSample.METRIC_MEMORY, 0.6)
        record_metric_sample(self.host, MetricSample.METRIC_DISK, 0.4)

        response = self.client.get(reverse('devops:metrics_history'), {
            'host': self.host.id,
            'range': '6h',
        })

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, '最近 6 小时')
        self.assertContains(response, '"host_name": "test-host"')
        self.assertContains(response, '80.0')

    def test_validate_remote_path_rejects_unsafe_paths(self):
        self.assertEqual(validate_remote_path('relative/path')[0], False)
        self.assertEqual(validate_remote_path('/tmp/../etc/passwd')[0], False)
        self.assertEqual(validate_remote_path('/')[0], False)
        self.assertEqual(validate_remote_path('/tmp/app.conf'), (True, '/tmp/app.conf'))

    def test_file_distribution_rejects_invalid_remote_path_before_creating_record(self):
        upload = SimpleUploadedFile('config.txt', b'hello')

        response = self.client.post(reverse('devops:file_distributions'), {
            'name': 'bad path',
            'source_file': upload,
            'remote_path': 'tmp/config.txt',
            'hosts': [self.host.id],
        })

        self.assertEqual(response.status_code, 200)
        self.assertFalse(FileDistribution.objects.exists())
        self.assertFalse(FileDistributionResult.objects.exists())

    @mock.patch('devops.services.settings.DEVOPS_TASK_RETRY_COUNT', 1)
    @mock.patch('devops.services.create_host_ssh_client')
    def test_file_distribution_retries_transient_ssh_error(self, create_host_ssh_client):
        class FakeSftp(object):
            def put(self, source, target):
                pass

            def close(self):
                pass

        class FakeClient(object):
            def open_sftp(self):
                return FakeSftp()

            def close(self):
                pass

        distribution = FileDistribution.objects.create(
            name='retry distribution',
            remote_path='/tmp/config.txt',
            created_by=self.user.user,
        )
        distribution.hosts.add(self.host)
        distribution.source_file.save('config.txt', ContentFile(b'hello'), save=True)
        create_host_ssh_client.side_effect = [socket.timeout('timed out'), FakeClient()]

        execute_file_distribution(distribution)

        distribution.refresh_from_db()
        result = FileDistributionResult.objects.get(distribution=distribution)
        self.assertEqual(distribution.status, FileDistribution.STATUS_SUCCESS)
        self.assertEqual(result.status, CommandExecution.STATUS_SUCCESS)
        self.assertEqual(create_host_ssh_client.call_count, 2)

    @mock.patch('devops.services.create_host_ssh_client')
    def test_file_distribution_is_idempotent_after_started(self, create_host_ssh_client):
        distribution = FileDistribution.objects.create(
            name='already running distribution',
            remote_path='/tmp/config.txt',
            status=FileDistribution.STATUS_RUNNING,
            created_by=self.user.user,
        )
        distribution.hosts.add(self.host)
        distribution.source_file.save('config.txt', ContentFile(b'hello'), save=True)

        execute_file_distribution(distribution)

        distribution.refresh_from_db()
        self.assertEqual(distribution.status, FileDistribution.STATUS_RUNNING)
        self.assertFalse(FileDistributionResult.objects.exists())
        create_host_ssh_client.assert_not_called()

    def test_file_distribution_page_renders(self):
        response = self.client.get(reverse('devops:file_distributions'))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, '文件分发')

    def test_viewer_cannot_create_file_distribution_when_roles_are_configured(self):
        self.set_role(DevOpsRole.ROLE_VIEWER)
        upload = SimpleUploadedFile('config.txt', b'hello')

        response = self.client.post(reverse('devops:file_distributions'), {
            'name': 'blocked upload',
            'source_file': upload,
            'remote_path': '/tmp/config.txt',
            'hosts': [self.host.id],
        })

        self.assertEqual(response.status_code, 403)
        self.assertFalse(FileDistribution.objects.exists())

    def test_deployment_app_can_be_created(self):
        response = self.client.post(reverse('devops:deployments'), {
            'form_type': 'app',
            'name': 'order-service',
            'description': 'order app',
        })

        self.assertEqual(response.status_code, 302)
        self.assertTrue(DeploymentApp.objects.filter(name='order-service').exists())

    def test_deployment_risk_preview_collects_only_active_and_recent_risks(self):
        other = NewLinux.objects.create(
            linux_name='preview-hidden-host',
            linux_ip='127.0.0.88',
            linux_hostname='preview-hidden-host',
        )
        app = DeploymentApp.objects.create(name='preview-service')
        recent = DeploymentRelease.objects.create(app=app, version='recent', deploy_script='echo deploy')
        recent.hosts.add(self.host)
        old = DeploymentRelease.objects.create(app=app, version='old', deploy_script='echo deploy')
        old.hosts.add(self.host)
        DeploymentRelease.objects.filter(id=old.id).update(created_at=timezone.now() - timezone.timedelta(hours=25))
        hidden = DeploymentRelease.objects.create(app=app, version='hidden', deploy_script='echo deploy')
        hidden.hosts.add(other)
        approval = ApprovalRequest.objects.create(
            request_type=ApprovalRequest.TYPE_ROLLBACK,
            title='preview rollback',
            deployment_release=recent,
        )
        AlertEvent.objects.create(host=self.host, message='open risk', status=AlertEvent.STATUS_OPEN)
        AlertEvent.objects.create(host=self.host, message='processing risk', status=AlertEvent.STATUS_PROCESSING)
        AlertEvent.objects.create(host=self.host, message='silenced risk', status=AlertEvent.STATUS_SILENCED)
        AlertEvent.objects.create(host=other, message='hidden risk', status=AlertEvent.STATUS_OPEN)
        older = record_metric_sample(
            self.host, MetricSample.METRIC_CPU, 0.2,
            collected_at=timezone.now() - timezone.timedelta(minutes=5),
        )
        latest = record_metric_sample(self.host, MetricSample.METRIC_CPU, 0.8)

        preview = deployment_risk_preview([self.host])

        self.assertEqual({alert.message for alert in preview['active_alerts']}, {'open risk', 'processing risk'})
        self.assertEqual({release.id for release in preview['recent_releases']}, {recent.id})
        self.assertEqual([item.id for item in preview['pending_approvals']], [approval.id])
        self.assertEqual(preview['host_metrics'][0]['cpu'].id, latest.id)
        self.assertNotEqual(preview['host_metrics'][0]['cpu'].id, older.id)

    def test_deployment_risk_preview_is_read_only_and_respects_host_scope(self):
        other = NewLinux.objects.create(
            linux_name='preview-outside-host',
            linux_ip='127.0.0.89',
            linux_hostname='preview-outside-host',
        )
        group = HostGroup.objects.create(name='preview-visible-hosts')
        group.hosts.add(self.host)
        scope = DevOpsHostScope.objects.create(user=self.user)
        scope.groups.add(group)
        app = DeploymentApp.objects.create(name='preview-page-service')
        hidden = DeploymentRelease.objects.create(app=app, version='hidden', deploy_script='echo deploy')
        hidden.hosts.add(other)
        AlertEvent.objects.create(host=self.host, message='visible preview risk', status=AlertEvent.STATUS_OPEN)
        AlertEvent.objects.create(host=other, message='hidden preview risk', status=AlertEvent.STATUS_OPEN)
        release_count = DeploymentRelease.objects.count()
        approval_count = ApprovalRequest.objects.count()
        audit_count = AuditLog.objects.count()

        response = self.client.post(reverse('devops:deployments'), {
            'form_type': 'release',
            'submit_mode': 'preview',
            'app': app.id,
            'version': 'candidate',
            'description': 'read-only preview',
            'deploy_script': 'echo deploy',
            'rollback_script': 'echo rollback',
            'hosts': [self.host.id],
        })

        self.assertEqual(response.status_code, 200)
        self.assertEqual(DeploymentRelease.objects.count(), release_count)
        self.assertEqual(ApprovalRequest.objects.count(), approval_count)
        self.assertEqual(AuditLog.objects.count(), audit_count)
        preview = response.context['preview']
        self.assertEqual([host.id for host in preview['hosts']], [self.host.id])
        self.assertEqual([alert.message for alert in preview['active_alerts']], ['visible preview risk'])
        self.assertNotContains(response, 'hidden preview risk')

        blocked_response = self.client.post(reverse('devops:deployments'), {
            'form_type': 'release',
            'submit_mode': 'preview',
            'app': app.id,
            'version': 'blocked-candidate',
            'deploy_script': 'echo deploy',
            'hosts': [other.id],
        })

        self.assertEqual(blocked_response.status_code, 200)
        self.assertIsNone(blocked_response.context['preview'])
        self.assertTrue(blocked_response.context['release_form'].errors)
        self.assertEqual(DeploymentRelease.objects.count(), release_count)

    def test_dangerous_deployment_is_blocked_with_host_results(self):
        app = DeploymentApp.objects.create(name='billing-service', created_by=self.user.user)

        response = self.client.post(reverse('devops:deployments'), {
            'form_type': 'release',
            'app': app.id,
            'version': 'v1.0.0',
            'description': 'blocked release',
            'deploy_script': 'rm -rf /',
            'rollback_script': 'echo rollback',
            'hosts': [self.host.id],
        })

        self.assertEqual(response.status_code, 302)
        release = DeploymentRelease.objects.get()
        result = DeploymentResult.objects.get(release=release)
        self.assertEqual(release.status, DeploymentRelease.STATUS_BLOCKED)
        self.assertEqual(result.status, CommandExecution.STATUS_BLOCKED)

    def test_deployment_release_is_idempotent_after_started(self):
        app = DeploymentApp.objects.create(name='running-release', created_by=self.user.user)
        release = DeploymentRelease.objects.create(
            app=app,
            version='v1',
            deploy_script='echo deploy',
            rollback_script='echo rollback',
            status=DeploymentRelease.STATUS_RUNNING,
            created_by=self.user.user,
        )
        release.hosts.add(self.host)
        DeploymentResult.objects.create(
            release=release,
            host=self.host,
            action=DeploymentResult.ACTION_DEPLOY,
            status=CommandExecution.STATUS_SUCCESS,
        )

        execute_deployment_release(release)

        release.refresh_from_db()
        self.assertEqual(release.status, DeploymentRelease.STATUS_RUNNING)
        self.assertFalse(CommandExecution.objects.exists())
        self.assertEqual(DeploymentResult.objects.filter(release=release).count(), 1)

    def test_deployment_rollback_is_idempotent_after_started(self):
        app = DeploymentApp.objects.create(name='running-rollback', created_by=self.user.user)
        release = DeploymentRelease.objects.create(
            app=app,
            version='v1',
            deploy_script='echo deploy',
            rollback_script='echo rollback',
            status=DeploymentRelease.STATUS_RUNNING,
            created_by=self.user.user,
        )
        release.hosts.add(self.host)
        DeploymentResult.objects.create(
            release=release,
            host=self.host,
            action=DeploymentResult.ACTION_ROLLBACK,
            status=CommandExecution.STATUS_SUCCESS,
        )

        execute_deployment_rollback(release)

        release.refresh_from_db()
        self.assertEqual(release.status, DeploymentRelease.STATUS_RUNNING)
        self.assertFalse(CommandExecution.objects.exists())
        self.assertEqual(DeploymentResult.objects.filter(release=release).count(), 1)

    def test_deployment_detail_renders_release(self):
        app = DeploymentApp.objects.create(name='web-service', created_by=self.user.user)
        release = DeploymentRelease.objects.create(
            app=app,
            version='v1.0.1',
            deploy_script='echo deploy',
            rollback_script='echo rollback',
            created_by=self.user.user,
        )

        response = self.client.get(reverse('devops:deployment_detail', args=[release.id]))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'web-service')
        self.assertContains(response, 'v1.0.1')

    def test_deployment_rollback_without_script_updates_summary(self):
        app = DeploymentApp.objects.create(name='empty-rollback', created_by=self.user.user)
        release = DeploymentRelease.objects.create(
            app=app,
            version='v1',
            deploy_script='echo deploy',
            rollback_script='',
            status=DeploymentRelease.STATUS_SUCCESS,
            created_by=self.user.user,
        )

        response = self.client.post(reverse('devops:deployment_rollback', args=[release.id]))

        self.assertEqual(response.status_code, 302)
        release.refresh_from_db()
        self.assertEqual(release.summary, '未配置回滚脚本')

    def test_force_rollback_approval_creates_approval(self):
        DevOpsSetting.objects.create(force_rollback_approval=True)
        app = DeploymentApp.objects.create(name='rollback-approval', created_by=self.user.user)
        release = DeploymentRelease.objects.create(
            app=app,
            version='v1',
            deploy_script='echo deploy',
            rollback_script='echo rollback',
            created_by=self.user.user,
        )

        response = self.client.post(reverse('devops:deployment_rollback', args=[release.id]))

        self.assertEqual(response.status_code, 302)
        approval = ApprovalRequest.objects.get()
        self.assertEqual(approval.request_type, ApprovalRequest.TYPE_ROLLBACK)
        self.assertEqual(approval.deployment_release, release)

    def test_viewer_cannot_create_deployment_when_roles_are_configured(self):
        self.set_role(DevOpsRole.ROLE_VIEWER)
        app = DeploymentApp.objects.create(name='viewer-app', created_by=self.user.user)

        response = self.client.post(reverse('devops:deployments'), {
            'form_type': 'release',
            'app': app.id,
            'version': 'v1',
            'deploy_script': 'echo deploy',
            'rollback_script': '',
            'hosts': [self.host.id],
        })

        self.assertEqual(response.status_code, 403)
        self.assertEqual(DeploymentRelease.objects.count(), 0)

    def test_command_approval_can_be_created(self):
        with mock.patch('devops.services.notify_approval') as notify:
            response = self.client.post(reverse('devops:command_approval_create'), {
                'host': self.host.id,
                'command': 'reboot',
                'reason': 'maintenance',
            })

        self.assertEqual(response.status_code, 302)
        approval = ApprovalRequest.objects.get()
        self.assertEqual(approval.request_type, ApprovalRequest.TYPE_COMMAND)
        self.assertEqual(approval.status, ApprovalRequest.STATUS_PENDING)
        notify.assert_called_once_with(approval, '创建')

    def test_admin_can_reject_approval(self):
        approver = User.objects.create(
            user='reject-approver',
            email='reject-approver@example.com',
            password='plain-password',
            confirm_pwd='plain-password',
        )
        DevOpsRole.objects.update_or_create(user=approver, defaults={'role': DevOpsRole.ROLE_ADMIN})
        session = self.client.session
        session['user_id'] = approver.id
        session['user_name'] = approver.user
        session.save()
        approval = ApprovalRequest.objects.create(
            request_type=ApprovalRequest.TYPE_COMMAND,
            title='reject command',
            host=self.host,
            command='reboot',
            requester=self.user.user,
        )

        with mock.patch('devops.views.notify_approval') as notify:
            response = self.client.post(reverse('devops:approval_decide', args=[approval.id]), {
                'action': 'reject',
                'comment': 'not now',
            })

        self.assertEqual(response.status_code, 302)
        approval.refresh_from_db()
        self.assertEqual(approval.status, ApprovalRequest.STATUS_REJECTED)
        self.assertEqual(approval.comment, 'not now')
        notify.assert_called_once_with(approval, '拒绝')

    def test_requester_cannot_approve_own_request(self):
        self.set_role(DevOpsRole.ROLE_ADMIN)
        approval = ApprovalRequest.objects.create(
            request_type=ApprovalRequest.TYPE_COMMAND,
            title='self approve',
            host=self.host,
            command='reboot',
            requester=self.user.user,
        )

        response = self.client.post(reverse('devops:approval_decide', args=[approval.id]), {
            'action': 'approve',
            'comment': 'approved',
        })

        self.assertEqual(response.status_code, 302)
        approval.refresh_from_db()
        self.assertEqual(approval.status, ApprovalRequest.STATUS_PENDING)
        self.assertEqual(approval.comment, '申请人与审批人不能为同一人')
        self.assertIsNone(approval.command_execution)

    def test_admin_approval_executes_command_request(self):
        approver = User.objects.create(
            user='approver',
            email='approver@example.com',
            password='plain-password',
            confirm_pwd='plain-password',
        )
        DevOpsRole.objects.update_or_create(user=approver, defaults={'role': DevOpsRole.ROLE_ADMIN})
        session = self.client.session
        session['user_id'] = approver.id
        session['user_name'] = approver.user
        session.save()
        approval = ApprovalRequest.objects.create(
            request_type=ApprovalRequest.TYPE_COMMAND,
            title='run command',
            host=self.host,
            command='reboot',
            requester=self.user.user,
        )

        response = self.client.post(reverse('devops:approval_decide', args=[approval.id]), {
            'action': 'approve',
            'comment': 'approved',
        })

        self.assertEqual(response.status_code, 302)
        approval.refresh_from_db()
        self.assertIsNotNone(approval.command_execution)
        self.assertIn(approval.status, [ApprovalRequest.STATUS_EXECUTED, ApprovalRequest.STATUS_FAILED])

    def test_force_deploy_approval_creates_approval(self):
        DevOpsSetting.objects.create(force_deploy_approval=True)
        app = DeploymentApp.objects.create(name='force-approval-app', created_by=self.user.user)

        response = self.client.post(reverse('devops:deployments'), {
            'form_type': 'release',
            'submit_mode': 'execute',
            'app': app.id,
            'version': 'v3',
            'description': 'forced approval',
            'deploy_script': 'echo deploy',
            'rollback_script': 'echo rollback',
            'hosts': [self.host.id],
        })

        self.assertEqual(response.status_code, 302)
        release = DeploymentRelease.objects.get()
        approval = ApprovalRequest.objects.get()
        self.assertEqual(release.status, DeploymentRelease.STATUS_PENDING)
        self.assertEqual(approval.request_type, ApprovalRequest.TYPE_DEPLOYMENT)
        self.assertEqual(approval.deployment_release, release)

    def test_deployment_can_be_submitted_for_approval(self):
        app = DeploymentApp.objects.create(name='approval-app', created_by=self.user.user)

        response = self.client.post(reverse('devops:deployments'), {
            'form_type': 'release',
            'submit_mode': 'approval',
            'app': app.id,
            'version': 'v2',
            'description': 'needs approval',
            'deploy_script': 'echo deploy',
            'rollback_script': 'echo rollback',
            'hosts': [self.host.id],
        })

        self.assertEqual(response.status_code, 302)
        release = DeploymentRelease.objects.get()
        approval = ApprovalRequest.objects.get()
        self.assertEqual(release.status, DeploymentRelease.STATUS_PENDING)
        self.assertEqual(approval.deployment_release, release)

    def test_notification_channel_encrypts_secret_fields(self):
        channel = NotificationChannel.objects.create(
            name='ops webhook',
            channel_type=NotificationChannel.TYPE_WEBHOOK,
            webhook_url='https://example.com/hook',
            secret='plain-secret',
            created_by=self.user.user,
        )

        stored = NotificationChannel.objects.get(id=channel.id)

        self.assertNotEqual(stored.webhook_url, 'https://example.com/hook')
        self.assertTrue(stored.webhook_url.startswith('enc:'))
        self.assertEqual(stored.decrypted_webhook_url, 'https://example.com/hook')
        self.assertEqual(stored.decrypted_secret, 'plain-secret')

    def test_send_notification_channel_records_success(self):
        channel = NotificationChannel.objects.create(
            name='generic',
            channel_type=NotificationChannel.TYPE_WEBHOOK,
            webhook_url='https://example.com/hook',
            notify_alert=True,
        )
        response = mock.Mock(status_code=200, text='ok')

        with mock.patch('devops.services.requests.post', return_value=response) as post:
            log = send_notification_channel(channel, NotificationLog.EVENT_ALERT, 'alert title', 'alert content')

        self.assertEqual(log.status, NotificationLog.STATUS_SUCCESS)
        post.assert_called_once()
        payload = post.call_args[1]['json']
        self.assertEqual(payload['event_type'], NotificationLog.EVENT_ALERT)
        self.assertEqual(payload['title'], 'alert title')

    def test_send_notification_channel_deduplicates_recent_same_message(self):
        channel = NotificationChannel.objects.create(
            name='dedupe',
            channel_type=NotificationChannel.TYPE_WEBHOOK,
            webhook_url='https://example.com/hook',
        )
        response = mock.Mock(status_code=200, text='ok')

        with mock.patch('devops.services.requests.post', return_value=response) as post:
            first = send_notification_channel(channel, NotificationLog.EVENT_ALERT, 'same title', 'same content')
            second = send_notification_channel(channel, NotificationLog.EVENT_ALERT, 'same title', 'same content')

        self.assertEqual(first.status, NotificationLog.STATUS_SUCCESS)
        self.assertEqual(second.status, NotificationLog.STATUS_SUCCESS)
        self.assertIn('deduped', second.response)
        post.assert_called_once()

    def test_send_notification_channel_records_failure(self):
        channel = NotificationChannel.objects.create(
            name='generic fail',
            channel_type=NotificationChannel.TYPE_WEBHOOK,
            webhook_url='https://example.com/hook',
        )

        with mock.patch('devops.services.requests.post', side_effect=Exception('network down')):
            log = send_notification_channel(channel, NotificationLog.EVENT_TEST, 'test', 'content')

        self.assertEqual(log.status, NotificationLog.STATUS_FAILED)
        self.assertIn('network down', log.response)

    @mock.patch('devops.services.settings.NOTIFICATION_RETRY_COUNT', 1)
    @mock.patch('devops.services.settings.NOTIFICATION_TIMEOUT_SECONDS', 3)
    def test_send_notification_channel_retries_failure(self):
        channel = NotificationChannel.objects.create(
            name='retry webhook',
            channel_type=NotificationChannel.TYPE_WEBHOOK,
            webhook_url='https://example.com/hook',
        )
        response = mock.Mock(status_code=200, text='ok')

        with mock.patch('devops.services.requests.post', side_effect=[Exception('network down'), response]) as post:
            log = send_notification_channel(channel, NotificationLog.EVENT_TEST, 'retry title', 'retry content')

        self.assertEqual(log.status, NotificationLog.STATUS_SUCCESS)
        self.assertIn('已尝试 2 次', log.response)
        self.assertEqual(post.call_count, 2)
        self.assertEqual(post.call_args[1]['timeout'], 3)

    def test_api_notifications_filters_logs_and_omits_channel_secrets(self):
        alert_channel = NotificationChannel.objects.create(
            name='alert webhook',
            channel_type=NotificationChannel.TYPE_WEBHOOK,
            webhook_url='https://example.com/alert-hook',
            secret='alert-secret',
        )
        deploy_channel = NotificationChannel.objects.create(
            name='deploy webhook',
            channel_type=NotificationChannel.TYPE_WEBHOOK,
            webhook_url='https://example.com/deploy-hook',
            secret='deploy-secret',
        )
        matched = NotificationLog.objects.create(
            channel=alert_channel,
            event_type=NotificationLog.EVENT_ALERT,
            title='matched alert',
            content='content',
            status=NotificationLog.STATUS_FAILED,
            response='failed',
        )
        NotificationLog.objects.create(
            channel=alert_channel,
            event_type=NotificationLog.EVENT_APPROVAL,
            title='wrong event',
            content='content',
            status=NotificationLog.STATUS_FAILED,
            response='failed',
        )
        NotificationLog.objects.create(
            channel=deploy_channel,
            event_type=NotificationLog.EVENT_ALERT,
            title='wrong channel',
            content='content',
            status=NotificationLog.STATUS_SUCCESS,
            response='ok',
        )

        response = self.client.get(reverse('devops:api_notifications'), {
            'channel': alert_channel.id,
            'event_type': NotificationLog.EVENT_ALERT,
            'status': NotificationLog.STATUS_FAILED,
        })

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual([item['id'] for item in payload['logs']], [matched.id])
        self.assertEqual(payload['logs'][0]['channel_id'], alert_channel.id)
        serialized = json.dumps(payload)
        self.assertNotIn('webhook_url', serialized)
        self.assertNotIn('secret', serialized)
        self.assertNotIn('https://example.com/alert-hook', serialized)
        self.assertNotIn('alert-secret', serialized)

    def test_api_notifications_requires_complete_login_session(self):
        NotificationChannel.objects.create(
            name='blocked webhook',
            channel_type=NotificationChannel.TYPE_WEBHOOK,
            webhook_url='https://example.com/blocked-hook',
            secret='blocked-secret',
        )
        session = self.client.session
        session['is_login'] = True
        session.pop('user_id', None)
        session['user_name'] = self.user.user
        session.save()

        response = self.client.get(reverse('devops:api_notifications'))

        self.assertEqual(response.status_code, 401)
        payload = response.json()
        self.assertFalse(payload['ok'])
        self.assertEqual(payload['code'], 'unauthorized')
        serialized = json.dumps(payload)
        self.assertNotIn('blocked webhook', serialized)
        self.assertNotIn('blocked-secret', serialized)
        self.assertNotIn('https://example.com/blocked-hook', serialized)

    def test_api_notifications_allows_security_module_viewer(self):
        self.set_role(DevOpsRole.ROLE_VIEWER)
        DevOpsModulePermission.objects.create(
            user=self.user,
            module=DevOpsModulePermission.MODULE_SECURITY,
            role=DevOpsRole.ROLE_VIEWER,
        )
        channel = NotificationChannel.objects.create(
            name='security webhook',
            channel_type=NotificationChannel.TYPE_WEBHOOK,
            webhook_url='https://example.com/security-hook',
            secret='security-secret',
        )

        response = self.client.get(reverse('devops:api_notifications'))

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload['channels'][0]['id'], channel.id)
        serialized = json.dumps(payload)
        self.assertNotIn('security-secret', serialized)
        self.assertNotIn('https://example.com/security-hook', serialized)

    def test_api_notifications_truncates_failure_response_preview(self):
        channel = NotificationChannel.objects.create(
            name='long response webhook',
            channel_type=NotificationChannel.TYPE_WEBHOOK,
            webhook_url='https://example.com/hook',
        )
        NotificationLog.objects.create(
            channel=channel,
            event_type=NotificationLog.EVENT_TEST,
            title='long failure',
            content='content',
            status=NotificationLog.STATUS_FAILED,
            response='x' * 500,
        )

        response = self.client.get(reverse('devops:api_notifications'))

        self.assertEqual(response.status_code, 200)
        preview = response.json()['logs'][0]['response']
        self.assertEqual(len(preview), 303)
        self.assertTrue(preview.endswith('...'))

    def test_api_notifications_rejects_invalid_filters(self):
        response = self.client.get(reverse('devops:api_notifications'), {'event_type': 'unknown'})

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()['code'], 'validation_error')

    def test_notification_page_renders(self):
        response = self.client.get(reverse('devops:notification_channels'))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, '通知渠道')

    def test_admin_can_create_notification_channel(self):
        self.set_role(DevOpsRole.ROLE_ADMIN)

        response = self.client.post(reverse('devops:notification_create'), {
            'name': 'wecom',
            'channel_type': NotificationChannel.TYPE_WECOM,
            'webhook_url': 'https://example.com/wecom',
            'secret': '',
            'notify_alert': 'on',
            'notify_approval': 'on',
            'notify_deployment': 'on',
            'enabled': 'on',
        })

        self.assertEqual(response.status_code, 302)
        channel = NotificationChannel.objects.get(name='wecom')
        self.assertEqual(channel.decrypted_webhook_url, 'https://example.com/wecom')
        log = AuditLog.objects.get(action='创建通知渠道')
        self.assertIn('名称=wecom', log.detail)
        self.assertIn('类型=wecom', log.detail)
        self.assertNotIn('https://example.com/wecom', log.detail)

    def test_notification_channel_rejects_invalid_webhook_url(self):
        self.set_role(DevOpsRole.ROLE_ADMIN)

        response = self.client.post(reverse('devops:notification_create'), {
            'name': 'bad-webhook',
            'channel_type': NotificationChannel.TYPE_WEBHOOK,
            'webhook_url': 'javascript:alert(1)',
            'secret': '',
            'notify_alert': 'on',
            'notify_approval': 'on',
            'notify_deployment': 'on',
            'enabled': 'on',
        })

        self.assertEqual(response.status_code, 302)
        self.assertFalse(NotificationChannel.objects.filter(name='bad-webhook').exists())

    def test_notification_update_keeps_secret_fields_when_blank(self):
        self.set_role(DevOpsRole.ROLE_ADMIN)
        channel = NotificationChannel.objects.create(
            name='keep-secret',
            channel_type=NotificationChannel.TYPE_WEBHOOK,
            webhook_url='https://example.com/original',
            secret='original-secret',
        )

        response = self.client.post(reverse('devops:notification_update', args=[channel.id]), {
            'name': 'keep-secret-updated',
            'channel_type': NotificationChannel.TYPE_WEBHOOK,
            'webhook_url': '',
            'secret': '',
            'notify_alert': 'on',
            'notify_approval': 'on',
            'notify_deployment': 'on',
            'enabled': 'on',
        })

        self.assertEqual(response.status_code, 302)
        channel.refresh_from_db()
        self.assertEqual(channel.name, 'keep-secret-updated')
        self.assertEqual(channel.decrypted_webhook_url, 'https://example.com/original')
        self.assertEqual(channel.decrypted_secret, 'original-secret')
        log = AuditLog.objects.get(action='更新通知渠道')
        self.assertIn('名称=keep-secret-updated', log.detail)
        self.assertNotIn('https://example.com/original', log.detail)
        self.assertNotIn('original-secret', log.detail)

    def test_compliance_baseline_form_rejects_unsafe_values(self):
        self.set_role(DevOpsRole.ROLE_ADMIN)
        response = self.client.post(reverse('devops:compliance_baseline_create'), {
            'name': 'bad-file', 'baseline_type': 'file_sha256', 'file_path': '../etc/passwd',
            'expected_sha256': 'not-a-sha', 'hosts': [self.host.id],
        })
        self.assertEqual(response.status_code, 302)
        self.assertFalse(ComplianceBaseline.objects.exists())

    @mock.patch('devops.services.create_host_ssh_client')
    def test_compliance_scan_records_drift_and_recovery(self, ssh_client):
        class Stream(object):
            def __init__(self, value): self.value = value
            def read(self): return self.value
        class Client(object):
            def __init__(self, value): self.value = value
            def exec_command(self, command, timeout=None): return None, Stream(self.value), Stream(b'')
            def close(self): pass
        baseline = ComplianceBaseline.objects.create(
            name='sshd active', baseline_type=ComplianceBaseline.TYPE_SERVICE_ACTIVE,
            service_name='sshd', created_by=self.user.user,
        )
        baseline.hosts.add(self.host)
        ssh_client.return_value = Client(b'inactive\n')
        scan_compliance_baseline(baseline)
        result = ComplianceResult.objects.get(baseline=baseline, host=self.host)
        self.assertEqual(result.state, ComplianceResult.STATE_DRIFT)
        self.assertTrue(AlertEvent.objects.filter(host=self.host, metric='compliance:%s' % baseline.id).exists())
        ssh_client.return_value = Client(b'active\n')
        scan_compliance_baseline(baseline)
        result.refresh_from_db()
        self.assertEqual(result.state, ComplianceResult.STATE_COMPLIANT)
        self.assertEqual(AlertEvent.objects.get(host=self.host, metric='compliance:%s' % baseline.id).status, AlertEvent.STATUS_RESOLVED)

    @mock.patch('devops.services.create_host_ssh_client', side_effect=Exception('connection failed'))
    def test_compliance_scan_marks_one_host_error_without_stopping(self, ssh_client):
        other = NewLinux.objects.create(linux_name='other', linux_ip='127.0.0.2', linux_hostname='other', linux_port='22', linux_user='root', linux_passwd='bad', linux_app='')
        baseline = ComplianceBaseline.objects.create(name='service error', baseline_type='service_active', service_name='sshd')
        baseline.hosts.add(self.host, other)
        self.assertEqual(scan_compliance_baseline(baseline), 2)
        self.assertEqual(ComplianceResult.objects.filter(baseline=baseline, state=ComplianceResult.STATE_ERROR).count(), 2)

    def test_compliance_page_permissions_and_manual_scan_audit(self):
        baseline = ComplianceBaseline.objects.create(name='manual', baseline_type='service_active', service_name='sshd')
        baseline.hosts.add(self.host)
        self.set_role(DevOpsRole.ROLE_VIEWER)
        self.assertEqual(self.client.post(reverse('devops:compliance_baseline_scan', args=[baseline.id])).status_code, 403)
        self.set_role(DevOpsRole.ROLE_ADMIN)
        with mock.patch('devops.views.scan_compliance_baseline') as scanner:
            response = self.client.post(reverse('devops:compliance_baseline_scan', args=[baseline.id]))
        self.assertEqual(response.status_code, 302)
        scanner.assert_called_once_with(baseline)
        self.assertTrue(AuditLog.objects.filter(action='手动扫描合规基线', target_id=str(baseline.id)).exists())

    def test_security_viewer_cannot_load_compliance_edit_target(self):
        baseline = ComplianceBaseline.objects.create(
            name='hidden-edit', baseline_type='service_active', service_name='sshd',
        )
        self.set_role(DevOpsRole.ROLE_VIEWER)

        response = self.client.get(reverse('devops:security_settings'), {'edit': baseline.id})

        self.assertEqual(response.status_code, 200)
        self.assertIsNone(response.context['compliance_edit_baseline'])
