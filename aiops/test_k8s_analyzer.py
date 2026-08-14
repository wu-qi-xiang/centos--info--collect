import json
from unittest.mock import patch

from django.test import TestCase

from RemoteLinux.models import User
from devops.models import DevOpsModulePermission, DevOpsRole, K8sCluster, K8sWorkloadServiceMapping, ServiceCatalog


class K8sAnalyzerApiTests(TestCase):
    def setUp(self):
        self.user = User.objects.create(user='k8s-api', email='k8s@example.com', password='pwd', confirm_pwd='pwd')
        DevOpsRole.objects.create(user=self.user, role=DevOpsRole.ROLE_ADMIN)
        for module in (DevOpsModulePermission.MODULE_CLUSTER, DevOpsModulePermission.MODULE_SERVICE):
            DevOpsModulePermission.objects.create(user=self.user, module=module, role=DevOpsRole.ROLE_VIEWER)
        self.service = ServiceCatalog.objects.create(name='mapped-service')
        self.hidden_service = ServiceCatalog.objects.create(name='hidden-service')
        self.cluster = K8sCluster.objects.create(name='analyzer-cluster', kubeconfig='private kubeconfig')
        K8sWorkloadServiceMapping.objects.create(cluster=self.cluster, service=self.service, namespace='default', workload_kind='Deployment', workload_name='api')
        session = self.client.session
        session.update({'is_login': True, 'user_id': self.user.id, 'user_name': self.user.user})
        session.save()

    def test_requires_permissions_and_mapping_scope(self):
        with patch('aiops.k8s_analyzer.load_cached_k8s_cluster_detail', return_value={'overview': {'ok': True, 'resources': {}, 'resource_errors': {}}}):
            self.assertEqual(self.client.get('/aiops/api/k8s-analyzer/%s/' % self.cluster.id).status_code, 200)
        K8sWorkloadServiceMapping.objects.all().delete()
        self.assertEqual(self.client.get('/aiops/api/k8s-analyzer/%s/' % self.cluster.id).status_code, 404)

    def test_invalid_namespace_does_not_call_loader(self):
        with patch('aiops.k8s_analyzer.load_cached_k8s_cluster_detail') as loader:
            response = self.client.get('/aiops/api/k8s-analyzer/%s/?namespace=Bad_Name' % self.cluster.id)
        self.assertEqual(response.status_code, 400)
        loader.assert_not_called()

    def test_safe_partial_result(self):
        detail = {'overview': {'ok': True, 'resources': {'deployments': [{'name': 'api', 'namespace': 'default', 'status': '异常'}], 'pods': [{'name': 'pod', 'namespace': 'default', 'status': 'Pending', 'detail': 'safe'}], 'secrets': [{'name': 'secret', 'detail': 'protected'}]}, 'resource_errors': {'nodes': 'private error'}}}
        with patch('aiops.k8s_analyzer.load_cached_k8s_cluster_detail', return_value=detail):
            response = self.client.get('/aiops/api/k8s-analyzer/%s/?namespace=default' % self.cluster.id)
        payload = response.json()['result']
        self.assertTrue(payload['partial'])
        self.assertNotIn('kubeconfig', repr(payload))
        self.assertNotIn('private error', repr(payload))
        self.assertTrue(payload['findings'])

    def test_unmapped_workload_and_other_namespace_are_excluded(self):
        detail = {'overview': {'ok': True, 'resources': {'deployments': [
            {'name': 'api', 'namespace': 'default', 'status': '异常'},
            {'name': 'unmapped', 'namespace': 'default', 'status': '异常'},
            {'name': 'api', 'namespace': 'other', 'status': '异常'},
        ]}, 'resource_errors': {}}}
        with patch('aiops.k8s_analyzer.load_cached_k8s_cluster_detail', return_value=detail):
            payload = self.client.get('/aiops/api/k8s-analyzer/%s/?namespace=default' % self.cluster.id).json()['result']
        self.assertEqual([item['name'] for item in payload['findings']], ['api'])

    def test_viewer_cannot_refresh(self):
        DevOpsRole.objects.filter(user=self.user).update(role=DevOpsRole.ROLE_OPERATOR)
        response = self.client.get('/aiops/api/k8s-analyzer/%s/?namespace=default&refresh=1' % self.cluster.id)
        self.assertEqual(response.status_code, 403)

    def test_namespace_without_mapping_is_not_found(self):
        response = self.client.get('/aiops/api/k8s-analyzer/%s/?namespace=other' % self.cluster.id)
        self.assertEqual(response.status_code, 404)
