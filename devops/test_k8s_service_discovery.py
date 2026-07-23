import os
import types
try:
    from unittest import mock
except ImportError:
    import mock

from django.test import TestCase

from RemoteLinux.models import NewLinux
from .models import K8sCluster, K8sWorkloadServiceMapping, ServiceCatalog
from .services import (
    associate_k8s_service_candidate,
    associate_k8s_workload_service,
    discover_and_associate_k8s_service_candidate,
    discover_k8s_service_candidates,
)


class K8sServiceDiscoveryTests(TestCase):
    def setUp(self):
        self.secret = 'apiVersion: v1\nusers:\n- user:\n    token: never-expose-this\n'
        self.cluster = K8sCluster.objects.create(
            name='discovery-cluster', default_namespace='operations', kubeconfig=self.secret,
        )
        self.service = ServiceCatalog.objects.create(name='payments-api')
        self.other_service = ServiceCatalog.objects.create(name='orders-api')

    def test_discovery_returns_only_safe_long_lived_workload_candidates(self):
        observed = {}
        mapping = K8sWorkloadServiceMapping.objects.create(
            service=self.service,
            cluster=self.cluster,
            namespace='operations',
            workload_kind='Deployment',
            workload_name='payments-api',
        )

        def workload(name, desired, ready):
            return types.SimpleNamespace(
                metadata=types.SimpleNamespace(
                    name=name, labels={'secret-label': 'do-not-expose'},
                    annotations={'secret-annotation': 'do-not-expose'},
                ),
                spec=types.SimpleNamespace(replicas=desired, template=object()),
                status=types.SimpleNamespace(ready_replicas=ready),
            )

        daemonset = types.SimpleNamespace(
            metadata=types.SimpleNamespace(
                name='node-agent', labels={'token': 'do-not-expose'}, annotations={},
            ),
            spec=types.SimpleNamespace(template=object()),
            status=types.SimpleNamespace(desired_number_scheduled=3, number_ready=2),
        )

        def new_client_from_config(config_file=None):
            observed['path'] = config_file
            observed['mode'] = os.stat(config_file).st_mode & 0o777
            return mock.Mock()

        class AppsV1Api(object):
            def __init__(self, api_client):
                self.api_client = api_client

            def list_namespaced_deployment(self, namespace=None, _request_timeout=None):
                observed['deployment_namespace'] = namespace
                return types.SimpleNamespace(items=[workload('payments-api', 2, 2)])

            def list_namespaced_stateful_set(self, namespace=None, _request_timeout=None):
                return types.SimpleNamespace(items=[workload('orders-db', 3, 1)])

            def list_namespaced_daemon_set(self, namespace=None, _request_timeout=None):
                return types.SimpleNamespace(items=[daemonset])

        fake_client = types.ModuleType('kubernetes.client')
        fake_client.AppsV1Api = AppsV1Api
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
            result = discover_k8s_service_candidates(self.cluster, 'operations')

        self.assertTrue(result['ok'])
        self.assertEqual(observed['mode'], 0o600)
        self.assertEqual(observed['deployment_namespace'], 'operations')
        self.assertFalse(os.path.exists(observed['path']))
        self.assertEqual(
            result['candidates'],
            [
                {
                    'cluster_id': self.cluster.id, 'cluster_name': 'discovery-cluster',
                    'namespace': 'operations', 'workload_kind': 'DaemonSet',
                    'workload_name': 'node-agent', 'status': '异常', 'replicas': '2 / 3',
                    'mapped_service_id': None, 'mapped_service_name': '',
                },
                {
                    'cluster_id': self.cluster.id, 'cluster_name': 'discovery-cluster',
                    'namespace': 'operations', 'workload_kind': 'Deployment',
                    'workload_name': 'payments-api', 'status': '运行中', 'replicas': '2 / 2',
                    'mapped_service_id': self.service.id, 'mapped_service_name': self.service.name,
                },
                {
                    'cluster_id': self.cluster.id, 'cluster_name': 'discovery-cluster',
                    'namespace': 'operations', 'workload_kind': 'StatefulSet',
                    'workload_name': 'orders-db', 'status': '异常', 'replicas': '1 / 3',
                    'mapped_service_id': None, 'mapped_service_name': '',
                },
            ],
        )
        rendered = str(result)
        self.assertNotIn('do-not-expose', rendered)
        self.assertNotIn('never-expose-this', rendered)
        self.assertEqual(K8sWorkloadServiceMapping.objects.count(), 1)
        self.assertEqual(K8sWorkloadServiceMapping.objects.get().id, mapping.id)

    def test_discovery_rejects_invalid_namespace_without_opening_cluster_config(self):
        result = discover_k8s_service_candidates(self.cluster, 'Not Valid')

        self.assertFalse(result['ok'])
        self.assertEqual(result['candidates'], [])
        self.assertEqual(result['message'], '命名空间无效')

    def test_association_is_idempotent_only_for_same_service_and_leaves_hosts_unchanged(self):
        host = NewLinux.objects.create(
            linux_name='mapped-host', linux_ip='192.0.2.31', linux_port='22',
            linux_user='ops', linux_passwd='not-used',
        )
        self.service.hosts.add(host)
        candidate = {
            'cluster_id': self.cluster.id,
            'cluster_name': self.cluster.name,
            'namespace': 'operations',
            'workload_kind': 'Deployment',
            'workload_name': 'payments-api',
            'status': '运行中',
            'replicas': '2 / 2',
        }

        created = associate_k8s_service_candidate(self.service, candidate)
        again = associate_k8s_service_candidate(self.service, candidate)
        conflict = associate_k8s_workload_service(
            self.other_service, self.cluster, 'operations', 'Deployment', 'payments-api',
        )

        self.assertTrue(created['ok'])
        self.assertEqual(created['code'], 'created')
        self.assertTrue(again['ok'])
        self.assertEqual(again['code'], 'already_associated')
        self.assertFalse(conflict['ok'])
        self.assertEqual(conflict['code'], 'mapping_conflict')
        self.assertEqual(K8sWorkloadServiceMapping.objects.count(), 1)
        self.assertEqual(list(self.service.hosts.all()), [host])

    def test_association_rejects_invalid_kind_namespace_and_name(self):
        invalid_kind = associate_k8s_workload_service(
            self.service, self.cluster, 'operations', 'Job', 'cleanup',
        )
        invalid_namespace = associate_k8s_workload_service(
            self.service, self.cluster, 'Operations', 'Deployment', 'payments-api',
        )
        invalid_name = associate_k8s_workload_service(
            self.service, self.cluster, 'operations', 'Deployment', 'Invalid Name',
        )

        self.assertEqual(invalid_kind['code'], 'invalid_workload')
        self.assertEqual(invalid_namespace['code'], 'invalid_namespace')
        self.assertEqual(invalid_name['code'], 'invalid_workload')
        self.assertFalse(K8sWorkloadServiceMapping.objects.exists())

    def test_association_rejects_malformed_candidate_without_exception(self):
        result = associate_k8s_service_candidate(self.service, {
            'cluster_id': 'not-a-number',
            'namespace': ['operations'],
            'workload_kind': ['Deployment'],
            'workload_name': {'name': 'payments-api'},
        })

        self.assertFalse(result['ok'])
        self.assertEqual(result['code'], 'invalid_target')
        self.assertFalse(K8sWorkloadServiceMapping.objects.exists())

    def test_fresh_discovery_is_required_before_high_level_association(self):
        candidate = {
            'cluster_id': self.cluster.id,
            'cluster_name': self.cluster.name,
            'namespace': 'operations',
            'workload_kind': 'Deployment',
            'workload_name': 'payments-api',
            'status': '运行中',
            'replicas': '2 / 2',
        }
        with mock.patch(
                'devops.services.discover_k8s_service_candidates',
                return_value={'ok': True, 'message': '工作负载发现成功', 'candidates': [candidate]},
        ) as discover:
            result = discover_and_associate_k8s_service_candidate(
                self.service, self.cluster, 'operations', 'Deployment', 'payments-api',
            )
        discover.assert_called_once_with(self.cluster, 'operations', timeout=8)
        self.assertTrue(result['ok'])
        self.assertEqual(result['code'], 'created')

        with mock.patch(
                'devops.services.discover_k8s_service_candidates',
                return_value={'ok': True, 'message': '工作负载发现成功', 'candidates': []},
        ):
            missing = discover_and_associate_k8s_service_candidate(
                self.other_service, self.cluster, 'operations', 'Deployment', 'missing',
            )
        self.assertFalse(missing['ok'])
        self.assertEqual(missing['code'], 'candidate_not_found')
        self.assertEqual(K8sWorkloadServiceMapping.objects.count(), 1)
