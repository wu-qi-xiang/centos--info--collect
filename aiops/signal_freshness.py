"""Read-only signal freshness aggregation for the AIOps dashboard."""

from datetime import timedelta

from django.utils import timezone

from devops.models import MetricSample


FRESHNESS_WINDOW = timedelta(hours=1)
MAX_SIGNAL_FRESHNESS = 50
METRICS = (
    MetricSample.METRIC_CPU,
    MetricSample.METRIC_MEMORY,
    MetricSample.METRIC_DISK,
)
STATE_PRIORITY = {
    'absent': 0,
    'stale': 1,
    'partial': 2,
    'healthy': 3,
}


def _state(samples, cutoff):
    metric_states = {}
    for metric in METRICS:
        sample = samples[metric]
        if sample is None:
            metric_states[metric] = 'missing'
        elif sample.collected_at >= cutoff:
            metric_states[metric] = 'fresh'
        else:
            metric_states[metric] = 'stale'
    fresh_count = sum(state == 'fresh' for state in metric_states.values())
    stale_count = sum(state == 'stale' for state in metric_states.values())
    missing_count = sum(state == 'missing' for state in metric_states.values())
    if fresh_count == len(METRICS):
        state = 'healthy'
    elif fresh_count:
        state = 'partial'
    elif stale_count:
        state = 'stale'
    else:
        state = 'absent'
    return state, metric_states, fresh_count, stale_count, missing_count


def build_signal_freshness(hosts, now=None):
    """Return bounded, metadata-only freshness rows for supplied hosts.

    Authorization is deliberately owned by the caller. This function makes no
    writes and queries only the three recognized metric categories for the
    supplied hosts.
    """
    supplied_hosts = {
        host.id: host for host in hosts if getattr(host, 'id', None)
    }
    if not supplied_hosts:
        return []

    current = now or timezone.now()
    samples_by_key = {}
    samples = MetricSample.objects.filter(
        host_id__in=supplied_hosts,
        metric__in=METRICS,
        collected_at__lte=current,
    ).order_by('host_id', 'metric', '-collected_at', '-id')
    for sample in samples.iterator():
        samples_by_key.setdefault((sample.host_id, sample.metric), sample)

    cutoff = current - FRESHNESS_WINDOW
    results = []
    for host_id, host in supplied_hosts.items():
        host_samples = {
            metric: samples_by_key.get((host_id, metric))
            for metric in METRICS
        }
        state, metric_states, fresh_count, stale_count, missing_count = _state(host_samples, cutoff)
        results.append({
            '_host_id': host_id,
            'host_id': host_id,
            'host_name': host.linux_name or '未命名主机',
            'state': state,
            'fresh_count': fresh_count,
            'stale_count': stale_count,
            'missing_count': missing_count,
            'metric_states': metric_states,
        })

    results.sort(key=lambda item: (STATE_PRIORITY[item['state']], item['_host_id']))
    return [
        {
            'host_id': item['host_id'],
            'host_name': item['host_name'],
            'state': item['state'],
            'fresh_count': item['fresh_count'],
            'stale_count': item['stale_count'],
            'missing_count': item['missing_count'],
            'metric_states': item['metric_states'],
        }
        for item in results[:MAX_SIGNAL_FRESHNESS]
    ]
