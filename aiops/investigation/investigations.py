"""Read-only, bounded evidence and deterministic root-cause analysis."""


from django.utils import timezone
from django.db.models import Q
import sys

from devops.models import (
    AlertEvent,
    CIDelivery,
    DeploymentHealthEvaluation,
    DeploymentRelease,
    Incident,
    MetricSample,
    ServiceDependency,
    ServiceSlo,
)


MAX_TIMELINE = 64
MAX_PER_SOURCE = 32
MAX_ROOT_CAUSES = 4
ACTIVE_ALERT_STATUSES = (
    AlertEvent.STATUS_OPEN,
    AlertEvent.STATUS_PROCESSING,
    AlertEvent.STATUS_SILENCED,
)


def _ids(items):
    return {getattr(item, 'id', item) for item in (items or ()) if getattr(item, 'id', item)}


def _stamp(value):
    if not value:
        return None
    return timezone.localtime(value).isoformat()


def _row(kind, ref_id, occurred_at, severity='info', resource=None, summary=''):
    return {
        'kind': kind,
        'ref_id': ref_id,
        'occurred_at': _stamp(occurred_at),
        'severity': severity,
        'resource': resource or {},
        'summary': summary,
        '_sort': (_stamp(occurred_at) or '', kind, ref_id or 0),
    }


def _collect_alerts(host_ids, start, end):
    rows = []
    qs = AlertEvent.objects.filter(host_id__in=host_ids, status__in=ACTIVE_ALERT_STATUSES,
                                   updated_at__gte=start, updated_at__lte=end)
    for item in qs.order_by('-updated_at', '-id')[:MAX_PER_SOURCE]:
        rows.append(_row('alert', item.id, item.updated_at, item.level,
                          {'host_id': item.host_id, 'metric': item.metric},
                          '活动告警：%s' % item.level))
    return rows


def _collect_metrics(host_ids, start, end):
    rows = []
    qs = MetricSample.objects.filter(host_id__in=host_ids, collected_at__gte=start, collected_at__lte=end)
    for item in qs.order_by('-collected_at', '-id')[:MAX_PER_SOURCE]:
        rows.append(_row('metric', item.id, item.collected_at, 'warning',
                          {'host_id': item.host_id, 'metric': item.metric}, '指标样本已采集'))
    return rows


def _collect_incidents(host_ids, start, end):
    rows = []
    qs = Incident.objects.filter(host_id__in=host_ids,
                                 status__in=(Incident.STATUS_OPEN, Incident.STATUS_PROCESSING),
                                 updated_at__gte=start, updated_at__lte=end)
    for item in qs.order_by('-updated_at', '-id')[:MAX_PER_SOURCE]:
        rows.append(_row('incident', item.id, item.updated_at, item.severity,
                          {'host_id': item.host_id, 'status': item.status}, '未关闭事件'))
    return rows


def _collect_releases(host_ids, start, end):
    rows = []
    qs = DeploymentRelease.objects.filter(hosts__id__in=host_ids,
                                          created_at__gte=start, created_at__lte=end).distinct()
    releases = list(qs.order_by('-created_at', '-id')[:MAX_PER_SOURCE])
    release_ids = [item.id for item in releases]
    host_map = {release_id: [] for release_id in release_ids}
    through = DeploymentRelease.hosts.through
    for release_id, host_id in through.objects.filter(deploymentrelease_id__in=release_ids,
                                                       newlinux_id__in=host_ids).values_list('deploymentrelease_id', 'newlinux_id'):
        host_map.setdefault(release_id, []).append(host_id)
    ci_map = {release_id: [] for release_id in release_ids}
    for delivery in CIDelivery.objects.filter(release_id__in=release_ids,
                                              received_at__gte=start, received_at__lte=end).order_by('-received_at', '-id')[:MAX_PER_SOURCE]:
        ci_map.setdefault(delivery.release_id, []).append(delivery)
    health_map = {release_id: [] for release_id in release_ids}
    for health in DeploymentHealthEvaluation.objects.filter(release_id__in=release_ids,
                                                             evaluated_at__gte=start, evaluated_at__lte=end).order_by('-evaluated_at', '-id')[:MAX_PER_SOURCE]:
        health_map.setdefault(health.release_id, []).append(health)
    for item in releases:
        rows.append(_row('release', item.id, item.created_at,
                          'critical' if item.status in (DeploymentRelease.STATUS_FAILED,
                                                         DeploymentRelease.STATUS_ROLLED_BACK) else 'info',
                          {'host_ids': sorted(set(host_map.get(item.id, []))),
                           'status': item.status}, '近期发布'))
        for delivery in ci_map.get(item.id, []):
            rows.append(_row('ci_delivery', delivery.id, delivery.received_at,
                              'critical' if delivery.status == 'failed' else 'info',
                              {'release_id': item.id, 'provider': delivery.provider, 'status': delivery.status},
                              'CI 交付状态：%s' % delivery.status))
        for health in health_map.get(item.id, []):
            rows.append(_row('deployment_health', health.id, health.evaluated_at,
                              'critical' if health.status == DeploymentHealthEvaluation.STATUS_UNHEALTHY else 'info',
                              {'release_id': item.id, 'status': health.status, 'score': health.score}, '发布健康评估'))
    rows.sort(key=lambda row: row['_sort'], reverse=True)
    return rows[:MAX_PER_SOURCE]


def _collect_slos(service_ids, start, end):
    rows = []
    qs = ServiceSlo.objects.filter(service_id__in=service_ids, enabled=True,
                                   last_state=ServiceSlo.STATE_EXHAUSTED).filter(
                                       Q(last_evaluated_at__isnull=True,
                                         updated_at__gte=start, updated_at__lte=end) |
                                       Q(last_evaluated_at__gte=start, last_evaluated_at__lte=end)
                                   )
    for item in qs.order_by('id'):
        at = item.last_evaluated_at or item.updated_at
        if at and not (start <= at <= end):
            continue
        rows.append(_row('slo', item.id, at, 'critical',
                          {'service_id': item.service_id, 'metric_kind': item.metric_kind}, 'SLO 预算已耗尽'))
        if len(rows) >= MAX_PER_SOURCE:
            break
    return rows


def _collect_dependencies(service_ids, start=None, end=None):
    """Collect static, authorized topology; dependency creation is not a signal window."""
    rows = []
    qs = ServiceDependency.objects.filter(service_id__in=service_ids,
                                          upstream_service_id__in=service_ids).select_related('service', 'upstream_service')
    for item in qs.order_by('service_id', 'upstream_service_id')[:MAX_PER_SOURCE]:
        rows.append(_row('dependency', item.id, item.created_at, 'info',
                          {'service_id': item.service_id, 'upstream_service_id': item.upstream_service_id},
                          '服务存在上游依赖'))
    return rows


def build_investigation_result(investigation, visible_hosts, visible_services, now=None):
    """Build safe analysis for an already-authorized investigation scope."""
    now = now or timezone.now()
    start = investigation.window_start
    end = investigation.window_end or now
    if start > end:
        raise ValueError('invalid investigation window')
    host_ids = _ids(visible_hosts) & set(investigation.hosts.values_list('id', flat=True))
    service_ids = _ids(visible_services) & set(investigation.services.values_list('id', flat=True))
    legacy = sys.modules.get('aiops.investigations')
    resolve_collector = lambda name, fallback: getattr(legacy, name, fallback) if legacy else fallback
    collectors = (
        ('alerts', lambda: resolve_collector('_collect_alerts', _collect_alerts)(host_ids, start, end)),
        ('metrics', lambda: resolve_collector('_collect_metrics', _collect_metrics)(host_ids, start, end)),
        ('incidents', lambda: resolve_collector('_collect_incidents', _collect_incidents)(host_ids, start, end)),
        ('releases', lambda: resolve_collector('_collect_releases', _collect_releases)(host_ids, start, end)),
        ('slos', lambda: resolve_collector('_collect_slos', _collect_slos)(service_ids, start, end)),
        ('dependencies', lambda: resolve_collector('_collect_dependencies', _collect_dependencies)(service_ids, start, end)),
    )
    timeline, errors, source_rows = [], [], {}
    for source, collect in collectors:
        try:
            source_rows[source] = collect()
            timeline.extend(source_rows[source])
        except Exception:
            source_rows[source] = []
            errors.append({'source': source, 'code': 'source_unavailable'})
    timeline.sort(key=lambda row: row['_sort'], reverse=True)
    timeline = [{key: value for key, value in row.items() if key != '_sort'} for row in timeline[:MAX_TIMELINE]]

    alerts = source_rows.get('alerts', [])
    critical_count = sum(1 for row in alerts if row['severity'] == AlertEvent.LEVEL_CRITICAL)
    release_rows = source_rows.get('releases', [])
    failed_release = any(row['severity'] == 'critical' and row['kind'] == 'release' for row in release_rows)
    ci_failed = any(row['kind'] == 'ci_delivery' and row['severity'] == 'critical' for row in release_rows)
    slo_rows = source_rows.get('slos', [])
    deps = source_rows.get('dependencies', [])
    service_host_map = {
        getattr(service, 'id', service): set(service.hosts.filter(id__in=host_ids).values_list('id', flat=True))
        for service in (visible_services or ()) if getattr(service, 'id', service)
    }
    upstream_signal_ids = set()
    for dep in deps:
        upstream_hosts = service_host_map.get(dep['resource']['upstream_service_id'], set())
        if any(row.get('resource', {}).get('host_id') in upstream_hosts
               for row in alerts + source_rows.get('incidents', []) + source_rows.get('metrics', [])):
            upstream_signal_ids.add(dep['ref_id'])
        if any(row.get('resource', {}).get('service_id') == dep['resource']['upstream_service_id'] for row in slo_rows):
            upstream_signal_ids.add(dep['ref_id'])
    candidates = []
    def add(key, score, summary, refs, action):
        if refs:
            candidates.append({'key': key, 'confidence': min(100, score), 'summary': summary,
                               'evidence_refs': sorted(set(refs))[:12], 'next_action': action})
    add('recent_release', 82 if failed_release or ci_failed else 62,
        '近期发布与调查窗口内信号重叠', [r['ref_id'] for r in release_rows if r['kind'] in ('release', 'ci_delivery', 'deployment_health')],
        '核对发布批次健康评估与回滚条件')
    add('critical_alert_cluster', min(95, 48 + critical_count * 12), '严重告警在调查窗口内聚集',
        [r['ref_id'] for r in alerts if r['severity'] == AlertEvent.LEVEL_CRITICAL], '按主机和指标聚合告警并确认影响范围')
    add('exhausted_slo', 86, '服务 SLO 预算已耗尽', [r['ref_id'] for r in slo_rows], '核对 SLO 评估记录和服务错误率')
    add('upstream_dependency', 58, '上游服务在同一窗口存在健康信号', list(upstream_signal_ids), '先检查上游服务同窗口健康信号')
    candidates.sort(key=lambda item: (-item['confidence'], item['key']))
    return {
        'summary': '调查范围内采集到 %s 条安全证据' % len(timeline),
        'timeline': timeline,
        'root_causes': candidates[:MAX_ROOT_CAUSES],
        'scope': {'host_ids': sorted(host_ids), 'service_ids': sorted(service_ids),
                  'host_count': len(host_ids), 'service_count': len(service_ids),
                  'window_start': _stamp(start), 'window_end': _stamp(end)},
        'partial': bool(errors), 'errors': sorted(errors, key=lambda item: item['source']),
    }
