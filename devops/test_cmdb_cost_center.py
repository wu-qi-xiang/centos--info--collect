from django.test import TestCase

from RemoteLinux.models import NewLinux, User
from .models import (
    CloudDailyCostSummary, CloudResourceSummary, DevOpsHostScope,
    DevOpsModulePermission, DevOpsRole, HostGroup, ServiceCatalog,
)
from .services import record_cloud_daily_cost, record_cloud_resource_summary


class CmdbCostCenterTests(TestCase):
    def setUp(self):
        self.user = User.objects.create(user='cmdb-viewer', email='cmdb@example.com', password='plain', confirm_pwd='plain')
        self.host = NewLinux.objects.create(
            linux_name='cmdb-host', linux_ip='127.0.0.11', linux_hostname='cmdb-host',
            linux_port='22', linux_user='root', linux_passwd='not-used', linux_app='',
        )
        self.visible_service = ServiceCatalog.objects.create(
            name='cmdb-visible', owner='platform', lifecycle=ServiceCatalog.LIFECYCLE_ACTIVE,
            criticality=ServiceCatalog.CRITICALITY_HIGH,
        )
        self.visible_service.hosts.add(self.host)
        self.hidden_service = ServiceCatalog.objects.create(name='cmdb-hidden')
        self.hidden_host = NewLinux.objects.create(
            linux_name='cmdb-hidden-host', linux_ip='127.0.0.12', linux_hostname='cmdb-hidden-host',
            linux_port='22', linux_user='root', linux_passwd='not-used', linux_app='',
        )
        self.hidden_service.hosts.add(self.hidden_host)
        self.login_as_viewer()

    def login_as_viewer(self):
        DevOpsRole.objects.create(user=self.user, role=DevOpsRole.ROLE_VIEWER)
        DevOpsModulePermission.objects.create(user=self.user, module=DevOpsModulePermission.MODULE_SERVICE, role=DevOpsRole.ROLE_VIEWER)
        DevOpsModulePermission.objects.create(user=self.user, module=DevOpsModulePermission.MODULE_SECURITY, role=DevOpsRole.ROLE_VIEWER)
        group = HostGroup.objects.create(name='cmdb-scope')
        group.hosts.add(self.host)
        scope = DevOpsHostScope.objects.create(user=self.user)
        scope.groups.add(group)
        session = self.client.session
        session['is_login'] = True
        session['user_id'] = self.user.id
        session['user_name'] = self.user.user
        session.save()

    def test_service_catalog_serializes_lifecycle_and_hides_out_of_scope_service(self):
        response = self.client.get('/devops/api/service-catalog/')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.json()['results']), 1)
        item = response.json()['results'][0]
        self.assertEqual(item['name'], 'cmdb-visible')
        self.assertEqual(item['lifecycle'], ServiceCatalog.LIFECYCLE_ACTIVE)
        self.assertEqual(item['criticality'], ServiceCatalog.CRITICALITY_HIGH)

    def test_cloud_summary_is_deduplicated_and_only_exposes_tag_digest(self):
        first = record_cloud_resource_summary(
            self.visible_service, 'aws', 'ec2.instance', 'i-0123456789abcdef0', 'ap-east-1', {'team': 'platform'},
        )
        second = record_cloud_resource_summary(
            self.visible_service, 'aws', 'ec2.instance', 'i-0123456789abcdef0', 'ap-east-1', {'team': 'operations'},
        )
        self.assertEqual(first.id, second.id)
        self.assertEqual(CloudResourceSummary.objects.count(), 1)
        response = self.client.get('/devops/api/cloud-resources/')
        self.assertEqual(response.status_code, 200)
        item = response.json()['results'][0]
        self.assertEqual(set(item), {'id', 'service', 'provider', 'resource_type', 'resource_identifier', 'region', 'tag_digest', 'last_seen_at'})
        self.assertNotIn('operations', str(item))

    def test_cloud_cost_aggregates_are_scoped_and_do_not_store_credentials(self):
        visible = record_cloud_resource_summary(self.visible_service, 'aliyun', 'ecs.instance', 'i-123456', 'cn-hangzhou', {})
        hidden = record_cloud_resource_summary(self.hidden_service, 'aliyun', 'ecs.instance', 'i-654321', 'cn-hangzhou', {})
        record_cloud_daily_cost(visible, '2026-07-27', '12.3456', 'cny')
        record_cloud_daily_cost(hidden, '2026-07-27', '99.0000', 'CNY')
        self.assertEqual(CloudDailyCostSummary.objects.count(), 2)
        response = self.client.get('/devops/api/cloud-costs/')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()['results'], [{
            'resource_id': visible.id,
            'service': {'id': self.visible_service.id, 'name': 'cmdb-visible'},
            'provider': 'aliyun', 'cost_date': '2026-07-27', 'amount': '12.3456', 'currency': 'CNY',
        }])
        self.assertFalse(hasattr(visible, 'credential'))
