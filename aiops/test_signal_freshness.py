from datetime import timedelta

from django.test import TestCase
from django.utils import timezone

from RemoteLinux.models import NewLinux
from devops.models import MetricSample

from .signal_freshness import MAX_SIGNAL_FRESHNESS, build_signal_freshness


class SignalFreshnessTests(TestCase):
    def setUp(self):
        self.now = timezone.now().replace(microsecond=0)
        self.healthy = self.host('healthy-host', '127.0.0.211')
        self.partial = self.host('partial-host', '127.0.0.212')
        self.stale = self.host('stale-host', '127.0.0.213')
        self.absent = self.host('absent-host', '127.0.0.214')
        self.hidden = self.host('hidden-host', '127.0.0.215')

    def host(self, name, address):
        return NewLinux.objects.create(
            linux_name=name,
            linux_ip=address,
            linux_hostname=name,
        )

    def sample(self, host, metric, observed_at, value=76.54321):
        return MetricSample.objects.create(
            host=host,
            metric=metric,
            value=value,
            collected_at=observed_at,
        )

    def test_classifies_all_states_and_omits_sensitive_metric_host_data(self):
        fresh = self.now - timedelta(hours=1)
        stale = self.now - timedelta(hours=1, seconds=1)
        for metric in (MetricSample.METRIC_CPU, MetricSample.METRIC_MEMORY, MetricSample.METRIC_DISK):
            self.sample(self.healthy, metric, fresh)
        self.sample(self.partial, MetricSample.METRIC_CPU, fresh)
        self.sample(self.partial, MetricSample.METRIC_MEMORY, stale)
        self.sample(self.stale, MetricSample.METRIC_CPU, stale)
        self.sample(self.stale, MetricSample.METRIC_MEMORY, stale - timedelta(minutes=1))
        self.sample(self.hidden, MetricSample.METRIC_CPU, fresh, value=99.99999)
        self.sample(self.partial, MetricSample.METRIC_DISK, self.now + timedelta(minutes=1))

        before = MetricSample.objects.count()
        results = build_signal_freshness(
            [self.healthy, self.partial, self.stale, self.absent], now=self.now,
        )

        self.assertEqual([item['host_name'] for item in results], [
            'absent-host', 'stale-host', 'partial-host', 'healthy-host',
        ])
        self.assertEqual(results[0], {
            'host_id': self.absent.id,
            'host_name': 'absent-host',
            'state': 'absent',
            'fresh_count': 0,
            'stale_count': 0,
            'missing_count': 3,
            'metric_states': {'cpu': 'missing', 'memory': 'missing', 'disk': 'missing'},
        })
        self.assertEqual(results[1]['state'], 'stale')
        self.assertEqual(results[1]['fresh_count'], 0)
        self.assertEqual(results[1]['stale_count'], 2)
        self.assertEqual(results[1]['missing_count'], 1)
        self.assertEqual(results[1]['metric_states'], {'cpu': 'stale', 'memory': 'stale', 'disk': 'missing'})
        self.assertEqual(results[2]['state'], 'partial')
        self.assertEqual(results[2]['fresh_count'], 1)
        self.assertEqual(results[2]['stale_count'], 1)
        self.assertEqual(results[2]['missing_count'], 1)
        self.assertEqual(results[2]['metric_states'], {'cpu': 'fresh', 'memory': 'stale', 'disk': 'missing'})
        self.assertEqual(results[3]['state'], 'healthy')
        self.assertEqual(results[3]['fresh_count'], 3)
        self.assertEqual(results[3]['stale_count'], 0)
        self.assertEqual(results[3]['missing_count'], 0)
        rendered = repr(results)
        for private_value in (
                '127.0.0.211', '127.0.0.215', '76.54321', '99.99999',
                'hidden-host', fresh.strftime('%Y-%m-%d %H:%M:%S')):
            self.assertNotIn(private_value, rendered)
        self.assertEqual(before, MetricSample.objects.count())

    def test_orders_by_urgency_then_host_id_and_bounds_results(self):
        fresh = self.now - timedelta(minutes=1)
        self.sample(self.healthy, MetricSample.METRIC_CPU, fresh)
        self.sample(self.healthy, MetricSample.METRIC_MEMORY, fresh)
        self.sample(self.healthy, MetricSample.METRIC_DISK, fresh)
        many_absent = [self.host('bounded-%03d' % index, '127.0.1.%d' % index) for index in range(MAX_SIGNAL_FRESHNESS + 4)]

        first = build_signal_freshness([self.healthy] + many_absent, now=self.now)
        second = build_signal_freshness(list(reversed(many_absent)) + [self.healthy], now=self.now)

        self.assertEqual(len(first), MAX_SIGNAL_FRESHNESS)
        self.assertEqual(first, second)
        self.assertTrue(all(item['state'] == 'absent' for item in first))
        self.assertNotIn('healthy-host', [item['host_name'] for item in first])
