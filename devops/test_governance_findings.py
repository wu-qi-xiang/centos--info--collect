from django.test import TestCase

from RemoteLinux.models import NewLinux, User
from .models import DevOpsHostScope, DevOpsModulePermission, DevOpsRole, HostGroup, K8sCluster


class GovernanceFindingTests(TestCase):
    def setUp(self):
        self.user = User.objects.create(user='governance-admin', email='governance@example.com', password='plain', confirm_pwd='plain')
        self.host = NewLinux.objects.create(
            linux_name='governance-host', linux_ip='127.0.0.1', linux_hostname='localhost',
            linux_port='22', linux_user='root', linux_passwd='not-used', linux_app='',
        )
        self.cluster = K8sCluster.objects.create(
            name='governance-cluster', api_server='https://k8s.example.test', kubeconfig='apiVersion: v1',
        )

    def test_vulnerability_finding_is_deduplicated_without_package_output(self):
        from .vulnerability import record_vulnerability_finding

        first = record_vulnerability_finding(self.host, 'openssl', 'CVE-2026-0001', 'high')
        second = record_vulnerability_finding(self.host, 'openssl', 'CVE-2026-0001', 'high')

        self.assertEqual(first.id, second.id)
        self.assertEqual(first.package_name, 'openssl')
        self.assertFalse(hasattr(first, 'command_output'))

    def test_gitops_drift_stores_digests_and_never_mutates_cluster(self):
        from .gitops import record_gitops_drift

        finding = record_gitops_drift(
            self.cluster, 'operations', 'api', 'Deployment',
            {'apiVersion': 'apps/v1', 'kind': 'Deployment', 'metadata': {'name': 'api', 'namespace': 'operations'}, 'spec': {'replicas': 2}},
            {'apiVersion': 'apps/v1', 'kind': 'Deployment', 'metadata': {'name': 'api', 'namespace': 'operations'}, 'spec': {'replicas': 3}},
        )

        self.assertEqual(finding.status, 'drifted')
        self.assertEqual(len(finding.desired_digest), 64)
        self.assertEqual(len(finding.observed_digest), 64)
        self.assertFalse(hasattr(finding, 'desired_manifest'))

    def login_as_security_viewer(self):
        DevOpsRole.objects.create(user=self.user, role=DevOpsRole.ROLE_VIEWER)
        DevOpsModulePermission.objects.create(
            user=self.user, module=DevOpsModulePermission.MODULE_SECURITY, role=DevOpsRole.ROLE_VIEWER,
        )
        group = HostGroup.objects.create(name='governance-scope')
        group.hosts.add(self.host)
        scope = DevOpsHostScope.objects.create(user=self.user)
        scope.groups.add(group)
        session = self.client.session
        session['is_login'] = True
        session['user_id'] = self.user.id
        session['user_name'] = self.user.user
        session.save()

    def test_vulnerability_api_requires_security_permission_and_returns_safe_fields(self):
        from .vulnerability import record_vulnerability_finding
        record_vulnerability_finding(self.host, 'openssl', 'CVE-2026-0001', 'high')
        self.login_as_security_viewer()

        response = self.client.get('/devops/api/vulnerabilities/')

        self.assertEqual(response.status_code, 200)
        item = response.json()['results'][0]
        self.assertEqual(set(item), {'id', 'host_id', 'package_name', 'advisory_id', 'severity', 'status', 'last_seen_at'})

    def test_gitops_drift_api_requires_cluster_permission(self):
        from .gitops import record_gitops_drift
        record_gitops_drift(self.cluster, 'operations', 'api', 'Deployment', {'a': 1}, {'a': 2})
        self.login_as_security_viewer()

        forbidden = self.client.get('/devops/api/gitops-drift/')
        self.assertEqual(forbidden.status_code, 200)
        DevOpsModulePermission.objects.create(
            user=self.user, module=DevOpsModulePermission.MODULE_CLUSTER, role=DevOpsRole.ROLE_VIEWER,
        )
        response = self.client.get('/devops/api/gitops-drift/')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(set(response.json()['results'][0]), {
            'id', 'cluster_id', 'namespace', 'resource_name', 'resource_kind',
            'desired_digest', 'observed_digest', 'status', 'last_seen_at',
        })
