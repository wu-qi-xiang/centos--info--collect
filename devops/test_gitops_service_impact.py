from django.test import TestCase

from devops.models import GitOpsDriftFinding, K8sCluster, K8sWorkloadServiceMapping, ServiceCatalog


class GitOpsServiceImpactTests(TestCase):
    def test_maps_drifted_workloads_to_authorized_services(self):
        from .gitops_service_impact import build_gitops_service_impacts

        cluster = K8sCluster.objects.create(
            name='impact-cluster', api_server='https://cluster.example.invalid', kubeconfig='hidden',
        )
        service = ServiceCatalog.objects.create(name='gitops-impact-service', criticality='critical')
        K8sWorkloadServiceMapping.objects.create(
            service=service, cluster=cluster, namespace='platform', workload_kind='Deployment', workload_name='api',
        )
        finding = GitOpsDriftFinding.objects.create(
            cluster=cluster, namespace='platform', resource_name='api', resource_kind='Deployment',
            desired_digest='a' * 64, observed_digest='b' * 64, status=GitOpsDriftFinding.STATUS_DRIFTED,
        )

        result = build_gitops_service_impacts([finding], [service])

        self.assertEqual(result, [{
            'service': {'id': service.id, 'name': 'gitops-impact-service'},
            'criticality': 'critical', 'drifted_workload_count': 1,
            'dependency_count': 0, 'risk': 'critical',
            'recommendation': '优先核查关键服务的 GitOps 漂移并走受控修订流程',
        }])
        self.assertNotIn('cluster.example.invalid', repr(result))
