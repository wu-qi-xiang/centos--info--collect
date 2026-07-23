from unittest import mock

from django.test import TestCase
from django.urls import reverse

from RemoteLinux.models import NewLinux, User

from .models import (
    AuditLog, DevOpsHostScope, DevOpsModulePermission, DevOpsRole, HostGroup,
    K8sCluster, K8sWorkloadServiceMapping, ServiceCatalog,
)


class K8sServiceDiscoveryManagementTests(TestCase):
    def setUp(self):
        self.user = User.objects.create(
            user='discovery-admin', email='discovery-admin@example.com',
            password='plain-password', confirm_pwd='plain-password',
        )
        self.cluster = K8sCluster.objects.create(
            name='operations', api_server='https://kubernetes.example.com:6443',
            default_namespace='default', kubeconfig='apiVersion: v1\nclusters: []',
        )
        self.service = ServiceCatalog.objects.create(name='payments')
        session = self.client.session
        session['is_login'] = True
        session['user_id'] = self.user.id
        session['user_name'] = self.user.user
        session.save()

    def set_admin(self):
        DevOpsRole.objects.update_or_create(
            user=self.user, defaults={'role': DevOpsRole.ROLE_ADMIN},
        )

    def candidate(self, **overrides):
        value = {
            'cluster_id': self.cluster.id,
            'cluster_name': self.cluster.name,
            'namespace': 'default',
            'workload_kind': 'Deployment',
            'workload_name': 'payments-api',
            'status': '运行中',
            'replicas': '2 / 2',
            'mapped_service_id': None,
        }
        value.update(overrides)
        return value

    def association_payload(self, **overrides):
        value = {
            'cluster': self.cluster.id,
            'namespace': 'default',
            'workload_kind': 'Deployment',
            'workload_name': 'payments-api',
            'service': self.service.id,
        }
        value.update(overrides)
        return value

    def test_discovery_requires_cluster_and_service_administrator_permissions(self):
        self.set_admin()
        DevOpsModulePermission.objects.create(
            user=self.user, module=DevOpsModulePermission.MODULE_CLUSTER,
            role=DevOpsRole.ROLE_ADMIN,
        )
        DevOpsModulePermission.objects.create(
            user=self.user, module=DevOpsModulePermission.MODULE_SERVICE,
            role=DevOpsRole.ROLE_VIEWER,
        )

        service_denied = self.client.get(reverse('devops:k8s_service_discovery'))
        self.assertEqual(service_denied.status_code, 403)

        DevOpsModulePermission.objects.filter(
            user=self.user, module=DevOpsModulePermission.MODULE_SERVICE,
        ).update(role=DevOpsRole.ROLE_ADMIN)
        DevOpsModulePermission.objects.filter(
            user=self.user, module=DevOpsModulePermission.MODULE_CLUSTER,
        ).update(role=DevOpsRole.ROLE_VIEWER)
        cluster_denied = self.client.get(reverse('devops:k8s_service_discovery'))
        self.assertEqual(cluster_denied.status_code, 403)

    def test_navigation_requires_both_cluster_and_service_administrator_permissions(self):
        self.set_admin()
        DevOpsModulePermission.objects.create(
            user=self.user, module=DevOpsModulePermission.MODULE_CLUSTER,
            role=DevOpsRole.ROLE_ADMIN,
        )
        DevOpsModulePermission.objects.create(
            user=self.user, module=DevOpsModulePermission.MODULE_SERVICE,
            role=DevOpsRole.ROLE_VIEWER,
        )

        hidden = self.client.get(reverse('devops:dashboard'))
        self.assertNotContains(hidden, 'K8s服务发现')

        DevOpsModulePermission.objects.filter(
            user=self.user, module=DevOpsModulePermission.MODULE_SERVICE,
        ).update(role=DevOpsRole.ROLE_ADMIN)
        shown = self.client.get(reverse('devops:dashboard'))
        self.assertContains(shown, 'K8s服务发现')

    @mock.patch('devops.views.discover_k8s_service_candidates')
    def test_page_renders_only_safe_candidate_fields(self, discover):
        self.set_admin()
        discover.return_value = {
            'ok': True,
            'candidates': [self.candidate(labels='sensitive-label', image='private/image:tag')],
        }

        response = self.client.get(reverse('devops:k8s_service_discovery'), {
            'cluster': self.cluster.id, 'namespace': 'default',
        })

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'payments-api')
        self.assertContains(response, '2 / 2')
        self.assertNotContains(response, 'sensitive-label')
        self.assertNotContains(response, 'private/image:tag')
        discover.assert_called_once_with(self.cluster, 'default')

    @mock.patch('devops.views.discover_and_associate_k8s_service_candidate')
    def test_forged_workload_is_rejected_before_association(self, associate):
        self.set_admin()
        associate.return_value = {'ok': False, 'code': 'candidate_not_found'}

        response = self.client.post(
            reverse('devops:k8s_service_discovery_associate'), self.association_payload(),
        )

        self.assertEqual(response.status_code, 400)
        associate.assert_called_once_with(
            self.service, self.cluster, 'default', 'Deployment', 'payments-api',
        )
        audit = AuditLog.objects.get(action='关联K8s工作负载服务')
        self.assertIn('结果=failed', audit.detail)

    @mock.patch('devops.views.discover_and_associate_k8s_service_candidate')
    def test_valid_candidate_association_uses_service_layer_and_audits_safe_identity(self, associate):
        self.set_admin()
        associate.return_value = {'ok': True, 'code': 'created'}

        response = self.client.post(
            reverse('devops:k8s_service_discovery_associate'), self.association_payload(),
        )

        self.assertRedirects(response, '%s?cluster=%s&namespace=default' % (
            reverse('devops:k8s_service_discovery'), self.cluster.id,
        ))
        associate.assert_called_once_with(
            self.service, self.cluster, 'default', 'Deployment', 'payments-api',
        )
        audit = AuditLog.objects.get(action='关联K8s工作负载服务')
        self.assertIn('服务=payments(%s)' % self.service.id, audit.detail)
        self.assertIn('结果=created', audit.detail)

    @mock.patch('devops.views.discover_and_associate_k8s_service_candidate')
    def test_idempotent_association_audits_existing_from_service_code(self, associate):
        self.set_admin()
        associate.return_value = {'ok': True, 'code': 'already_associated'}

        response = self.client.post(
            reverse('devops:k8s_service_discovery_associate'), self.association_payload(),
        )

        self.assertEqual(response.status_code, 302)
        audit = AuditLog.objects.get(action='关联K8s工作负载服务')
        self.assertIn('结果=existing', audit.detail)

    @mock.patch('devops.views.discover_and_associate_k8s_service_candidate')
    def test_offline_cluster_short_circuits_association(self, associate):
        self.set_admin()
        self.cluster.status = K8sCluster.STATUS_OFFLINE
        self.cluster.save(update_fields=['status'])

        response = self.client.post(
            reverse('devops:k8s_service_discovery_associate'), self.association_payload(),
        )

        self.assertEqual(response.status_code, 400)
        associate.assert_not_called()
        self.assertContains(response, '集群当前离线', status_code=400)

    @mock.patch('devops.views.discover_and_associate_k8s_service_candidate')
    def test_scoped_admin_cannot_associate_an_out_of_scope_service(self, associate):
        self.set_admin()
        visible_host = NewLinux.objects.create(
            linux_name='visible-host', linux_ip='192.0.2.10', linux_port='22',
            linux_user='root', linux_passwd='x',
        )
        hidden_host = NewLinux.objects.create(
            linux_name='hidden-host', linux_ip='192.0.2.11', linux_port='22',
            linux_user='root', linux_passwd='x',
        )
        group = HostGroup.objects.create(name='discovery-scope')
        group.hosts.add(visible_host)
        scope = DevOpsHostScope.objects.create(user=self.user)
        scope.groups.add(group)
        hidden_service = ServiceCatalog.objects.create(name='hidden-payments')
        hidden_service.hosts.add(hidden_host)

        response = self.client.post(
            reverse('devops:k8s_service_discovery_associate'),
            self.association_payload(service=hidden_service.id),
        )

        self.assertEqual(response.status_code, 400)
        associate.assert_not_called()
        self.assertFalse(K8sWorkloadServiceMapping.objects.exists())
        self.assertFalse(AuditLog.objects.filter(action='关联K8s工作负载服务').exists())
