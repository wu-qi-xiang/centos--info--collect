"""Deterministic, read-only alert grouping for the AIOps workbench."""

from collections import defaultdict

from devops.models import AlertEvent, AlertQualityFeedback, Incident


ACTIVE_STATUSES = (
    AlertEvent.STATUS_OPEN,
    AlertEvent.STATUS_PROCESSING,
    AlertEvent.STATUS_SILENCED,
)
MAX_GROUPS = 32
PUBLIC_METRICS = frozenset((
    'availability', 'cpu', 'disk', 'error_rate', 'latency', 'load', 'memory',
    'network', 'process', 'service',
))
PUBLIC_LEVELS = frozenset((
    AlertEvent.LEVEL_INFO,
    AlertEvent.LEVEL_WARNING,
    AlertEvent.LEVEL_CRITICAL,
))


def _public_metric(metric):
    return metric if metric in PUBLIC_METRICS else 'other'


def _public_level(level):
    return level if level in PUBLIC_LEVELS else 'unknown'


def build_alert_groups(hosts, window_start, window_end):
    host_ids = [host.id for host in hosts]
    if not host_ids:
        return []
    alerts = list(AlertEvent.objects.filter(
        host_id__in=host_ids,
        status__in=ACTIVE_STATUSES,
        updated_at__gte=window_start,
        updated_at__lte=window_end,
    ).order_by('-updated_at', '-id'))
    incident_statuses = defaultdict(set)
    for incident in Incident.objects.filter(alert__in=alerts).values('alert_id', 'status'):
        incident_statuses[incident['alert_id']].add(incident['status'])
    feedback_counts = defaultdict(lambda: defaultdict(int))
    for feedback in AlertQualityFeedback.objects.filter(alert_id__in=[alert.id for alert in alerts]).values(
            'alert_id', 'classification'):
        feedback_counts[feedback['alert_id']][feedback['classification']] += 1
    groups = {}
    for alert in alerts:
        metric = _public_metric(alert.metric)
        level = _public_level(alert.level)
        key = '%s:%s' % (metric, level)
        group = groups.setdefault(key, {
            'key': key,
            'metric': metric,
            'level': level,
            'host_ids': set(),
            'active_count': 0,
            'silenced_count': 0,
            'repeat_count': 0,
            'incident_statuses': set(),
            'quality_feedback_counts': defaultdict(int),
        })
        group['host_ids'].add(alert.host_id)
        group['repeat_count'] += max(1, alert.repeat_count)
        group['incident_statuses'].update(incident_statuses.get(alert.id, set()))
        for classification, count in feedback_counts[alert.id].items():
            group['quality_feedback_counts'][classification] += count
        if alert.status == AlertEvent.STATUS_SILENCED:
            group['silenced_count'] += 1
        else:
            group['active_count'] += 1
    results = []
    for group in groups.values():
        active = group['active_count']
        quality_counts = {
            'valid': group['quality_feedback_counts'][AlertQualityFeedback.CLASSIFICATION_VALID],
            'noise': group['quality_feedback_counts'][AlertQualityFeedback.CLASSIFICATION_NOISE],
            'duplicate': group['quality_feedback_counts'][AlertQualityFeedback.CLASSIFICATION_DUPLICATE],
            'threshold': group['quality_feedback_counts'][AlertQualityFeedback.CLASSIFICATION_THRESHOLD],
        }
        quality_state = 'needs_review' if (
            quality_counts['noise'] or quality_counts['duplicate'] or quality_counts['threshold']
        ) else 'normal'
        results.append({
            'key': group['key'],
            'metric': group['metric'],
            'level': group['level'],
            'host_count': len(group['host_ids']),
            'active_count': active,
            'silenced_count': group['silenced_count'],
            'repeat_count': group['repeat_count'],
            'incident_statuses': sorted(group['incident_statuses']),
            'quality_feedback_counts': quality_counts,
            'quality_state': quality_state,
            'recommendation': (
                '优先处理质量反馈并人工复核阈值或聚合策略'
                if quality_state == 'needs_review' else
                ('优先建立或更新事件并检查近期变更' if active else '当前仅有静默告警，持续观察维护窗口结束后的状态')
            ),
        })
    return sorted(results, key=lambda item: (-item['active_count'], -item['host_count'], -item['repeat_count'], item['key']))[:MAX_GROUPS]
