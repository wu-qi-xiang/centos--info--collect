import json
from decimal import Decimal

from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from RemoteLinux.models import NewLinux, User
from .models import (
    CloudDailyCostSummary,
    CloudResourceSummary,
    DevOpsHostScope,
    DevOpsModulePermission,
    DevOpsRole,
    HostGroup,
    MetricSample,
    ServiceCatalog,
)


class CapacityCostSimulationApiTests(TestCase):
    def setUp(self):
        self.user = User.objects.create(
            user='simulation-operator', email='simulation-operator@example.com',
            password='plain-password', confirm_pwd='plain-password',
        )
        DevOpsRole.objects.create(user=self.user, role=DevOpsRole.ROLE_OPERATOR)
        for module in (
            DevOpsModulePermission.MODULE_METRIC,
            DevOpsModulePermission.MODULE_SERVICE,
        ):
            DevOpsModulePermission.objects.create(
                user=self.user, module=module, role=DevOpsRole.ROLE_OPERATOR,
            )
        self.visible_host = self.make_host('simulation-visible', '127.0.21.1')
        self.hidden_host = self.make_host('simulation-hidden', '127.0.21.2')
        group = HostGroup.objects.create(name='simulation-visible-group')
        group.hosts.add(self.visible_host)
        scope = DevOpsHostScope.objects.create(user=self.user)
        scope.groups.add(group)
        self.login()

    def make_host(self, name, ip):
        return NewLinux.objects.create(
            linux_name=name, linux_ip=ip, linux_hostname=name,
            linux_port='22', linux_user='root', linux_passwd='not-exposed', linux_app='',
        )

    def login(self):
        session = self.client.session
        session['is_login'] = True
        session['user_id'] = self.user.id
        session['user_name'] = self.user.user
        session.save()

    def record_sample(self, host, metric, value):
        return MetricSample.objects.create(
            host=host, metric=metric, value=value, unit='percent',
            collected_at=timezone.now(),
        )

    def record_cost(self, name, host, identifier, amount, currency='USD'):
        service = ServiceCatalog.objects.create(name=name)
        service.hosts.add(host)
        resource = CloudResourceSummary.objects.create(
            service=service, provider=CloudResourceSummary.PROVIDER_AWS,
            resource_type='instance', resource_identifier=identifier,
            region='test-region', tag_digest='a' * 64,
        )
        return CloudDailyCostSummary.objects.create(
            resource=resource, cost_date=timezone.now().date(),
            amount=Decimal(str(amount)), currency=currency,
        )

    def post(self, payload):
        return self.client.post(
            reverse('devops:api_capacity_cost_simulation'),
            data=json.dumps(payload), content_type='application/json',
        )

    def test_operator_receives_only_visible_aggregate_risk_and_cost(self):
        self.record_sample(self.visible_host, MetricSample.METRIC_CPU, 70)
        self.record_sample(self.visible_host, MetricSample.METRIC_MEMORY, 50)
        self.record_sample(self.hidden_host, MetricSample.METRIC_CPU, 100)
        self.record_sample(self.hidden_host, MetricSample.METRIC_MEMORY, 100)
        self.record_cost('simulation-visible-service', self.visible_host, 'visible-instance', 10)
        self.record_cost('simulation-hidden-service', self.hidden_host, 'hidden-instance', 999)
        before = {
            'metrics': MetricSample.objects.count(),
            'costs': CloudDailyCostSummary.objects.count(),
        }

        response = self.post({
            'cpu_delta_percent': '30',
            'memory_delta_percent': 0,
            'instance_delta': 0,
        })

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload, {
            'ok': True,
            'capacity': {
                'baseline_risk': 'low',
                'projected_risk': 'high',
                'sampled_host_count': 1,
            },
            'costs': [{
                'currency': 'USD',
                'baseline_daily': '10.0000',
                'projected_daily': '10.0000',
                'delta_daily': '0.0000',
            }],
        })
        encoded = json.dumps(payload)
        self.assertNotIn(self.visible_host.linux_name, encoded)
        self.assertNotIn(self.hidden_host.linux_name, encoded)
        self.assertNotIn('visible-instance', encoded)
        self.assertNotIn('hidden-instance', encoded)
        self.assertNotIn('not-exposed', encoded)
        self.assertEqual(before['metrics'], MetricSample.objects.count())
        self.assertEqual(before['costs'], CloudDailyCostSummary.objects.count())

    def test_empty_metrics_and_costs_return_unknown_without_identifiers(self):
        response = self.post({
            'cpu_delta_percent': 0,
            'memory_delta_percent': '0',
            'instance_delta': 0,
        })

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {
            'ok': True,
            'capacity': {
                'baseline_risk': 'unknown',
                'projected_risk': 'unknown',
                'sampled_host_count': 0,
            },
            'costs': [],
        })

    def test_instance_delta_projects_currency_cost_without_resource_identifiers(self):
        self.record_cost('simulation-scale-service', self.visible_host, 'scale-instance', 12.5)

        response = self.post({
            'cpu_delta_percent': 0,
            'memory_delta_percent': 0,
            'instance_delta': 1,
        })

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()['costs'], [{
            'currency': 'USD',
            'baseline_daily': '12.5000',
            'projected_daily': '25.0000',
            'delta_daily': '12.5000',
        }])
        self.assertNotIn('scale-instance', json.dumps(response.json()))

    def test_rejects_missing_non_numeric_and_out_of_range_deltas(self):
        cases = (
            {},
            {'cpu_delta_percent': '1.5', 'memory_delta_percent': 0, 'instance_delta': 0},
            {'cpu_delta_percent': -51, 'memory_delta_percent': 0, 'instance_delta': 0},
            {'cpu_delta_percent': 0, 'memory_delta_percent': 101, 'instance_delta': 0},
            {'cpu_delta_percent': 0, 'memory_delta_percent': 0, 'instance_delta': -11},
            {'cpu_delta_percent': True, 'memory_delta_percent': 0, 'instance_delta': 0},
        )
        for payload in cases:
            with self.subTest(payload=payload):
                response = self.post(payload)
                self.assertEqual(response.status_code, 400)
                self.assertEqual(response.json()['code'], 'validation_error')

    def test_requires_operator_permission_for_both_modules(self):
        DevOpsModulePermission.objects.filter(
            user=self.user, module=DevOpsModulePermission.MODULE_SERVICE,
        ).update(role=DevOpsRole.ROLE_VIEWER)

        response = self.post({
            'cpu_delta_percent': 0, 'memory_delta_percent': 0, 'instance_delta': 0,
        })

        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.json()['code'], 'forbidden')

    def test_requires_login(self):
        self.client.logout()

        response = self.post({
            'cpu_delta_percent': 0, 'memory_delta_percent': 0, 'instance_delta': 0,
        })

        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json()['code'], 'unauthorized')
