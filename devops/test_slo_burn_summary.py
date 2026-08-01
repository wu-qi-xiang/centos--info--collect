from datetime import timedelta

from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from RemoteLinux.models import NewLinux, User
from devops.models import (
    DevOpsHostScope,
    DevOpsModulePermission,
    DevOpsRole,
    HostGroup,
    ServiceCatalog,
    ServiceSlo,
    ServiceSloEvaluation,
)


class ServiceSloBurnSummaryTests(TestCase):
    def setUp(self):
        self.now = timezone.now()
        self.host = NewLinux.objects.create(
            linux_name='burn-visible', linux_ip='127.0.0.291', linux_hostname='burn-visible',
        )
        self.service = ServiceCatalog.objects.create(name='burn-service')
        self.service.hosts.add(self.host)
        self.slo = ServiceSlo.objects.create(
            service=self.service, metric_kind=ServiceSlo.KIND_AVAILABILITY,
            target=99, enabled=True,
        )

    def test_uses_visible_numeric_snapshots_for_short_and_long_burn(self):
        from .slo_burn import build_slo_burn_summary

        ServiceSloEvaluation.objects.create(
            slo=self.slo, state=ServiceSlo.STATE_HEALTHY, summary='safe',
            observed_value='99.5000', budget_remaining_percent='50.0000',
            burn_rate='0.5000', evaluated_at=self.now - timedelta(minutes=30),
        )
        ServiceSloEvaluation.objects.create(
            slo=self.slo, state=ServiceSlo.STATE_EXHAUSTED, summary='safe',
            observed_value='98.0000', budget_remaining_percent='0.0000',
            burn_rate='2.0000', evaluated_at=self.now - timedelta(minutes=90),
        )

        result = build_slo_burn_summary(self.slo, now=self.now)

        self.assertEqual(result, {
            'slo_id': self.slo.id,
            'metric_kind': ServiceSlo.KIND_AVAILABILITY,
            'state': 'elevated',
            'budget_remaining_percent': '50.0',
            'short_window_burn_rate': '0.5',
            'long_window_burn_rate': '1.3',
            'recommendation': '持续观察 SLO 燃尽趋势并在发布前复核',
        })

    def test_returns_unavailable_without_budget_capable_snapshots(self):
        from .slo_burn import build_slo_burn_summary

        latency = ServiceSlo.objects.create(
            service=self.service, metric_kind=ServiceSlo.KIND_LATENCY,
            target=250, enabled=True,
        )
        ServiceSloEvaluation.objects.create(
            slo=latency, state=ServiceSlo.STATE_HEALTHY, summary='safe',
            evaluated_at=self.now,
        )

        self.assertEqual(build_slo_burn_summary(latency, now=self.now), {
            'slo_id': latency.id,
            'metric_kind': ServiceSlo.KIND_LATENCY,
            'state': 'unavailable',
            'budget_remaining_percent': None,
            'short_window_burn_rate': None,
            'long_window_burn_rate': None,
            'recommendation': '当前 SLO 类型或历史记录不支持错误预算燃尽计算',
        })

    def test_api_requires_service_view_permission_and_returns_safe_summary(self):
        user = User.objects.create(
            user='burn-viewer', email='burn-viewer@example.com', password='pwd', confirm_pwd='pwd',
        )
        DevOpsRole.objects.create(user=user, role=DevOpsRole.ROLE_VIEWER)
        DevOpsModulePermission.objects.create(
            user=user, module=DevOpsModulePermission.MODULE_SERVICE,
            role=DevOpsRole.ROLE_VIEWER,
        )
        group = HostGroup.objects.create(name='burn-summary-group')
        group.hosts.add(self.host)
        scope = DevOpsHostScope.objects.create(user=user)
        scope.groups.add(group)
        ServiceSloEvaluation.objects.create(
            slo=self.slo, state=ServiceSlo.STATE_HEALTHY, summary='private summary',
            observed_value='99.5000', budget_remaining_percent='50.0000',
            burn_rate='0.5000', evaluated_at=self.now,
        )
        session = self.client.session
        session['is_login'] = True
        session['user_id'] = user.id
        session['user_name'] = user.user
        session.save()

        response = self.client.get(reverse('devops:api_service_slo_burn_summary', args=[self.slo.id]))

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()['summary']['slo_id'], self.slo.id)
        self.assertNotIn('private summary', repr(response.json()))
