"""Deterministic, read-only service reliability scoring for AIOps."""

from django.db.models import Q
from django.utils import timezone

from devops.models import (
    AlertEvent,
    CIDelivery,
    DeploymentHealthEvaluation,
    Incident,
    IncidentActionItem,
    ServiceSlo,
)
from devops.incident_actions import is_overdue

from .service_impact import (
    ACTIVE_ALERT_STATUSES,
    OPEN_INCIDENT_STATUSES,
    _batch_contains_any_host,
    _visible_service_hosts,
    _visible_service_releases,
)

MAX_RELIABILITY_SERVICES = 32
SEVERITIES = {
    Incident.SEVERITY_LOW: 8,
    Incident.SEVERITY_MEDIUM: 14,
    Incident.SEVERITY_HIGH: 22,
    Incident.SEVERITY_CRITICAL: 32,
}
STATE_ORDER = {'critical': 0, 'degraded': 1, 'healthy': 2, 'unknown': 3}


def _window_filter(queryset, field_name, start, end):
    return queryset.filter(**{'%s__gte' % field_name: start, '%s__lte' % field_name: end})


def _service_evidence(service, visible_host_ids, start, end, now):
    service_host_ids = _visible_service_hosts(service, visible_host_ids)
    has_hosts = service.hosts.exists()
    if has_hosts and not service_host_ids:
        return None
    releases = _visible_service_releases(service, service_host_ids)
    alerts = _window_filter(AlertEvent.objects.filter(
        host_id__in=service_host_ids, status__in=ACTIVE_ALERT_STATUSES,
    ), 'updated_at', start, end)
    incidents = _window_filter(Incident.objects.filter(
        status__in=OPEN_INCIDENT_STATUSES,
    ).filter(Q(host_id__in=service_host_ids) |
             Q(host__isnull=True, deployment_release__in=releases)), 'updated_at', start, end)
    closed_incidents = _window_filter(Incident.objects.filter(
        status=Incident.STATUS_CLOSED,
    ).filter(Q(host_id__in=service_host_ids) |
             Q(host__isnull=True, deployment_release__in=releases)), 'updated_at', start, end)
    review_incidents = _window_filter(Incident.objects.filter(
        status__in=OPEN_INCIDENT_STATUSES + (Incident.STATUS_CLOSED,),
    ).filter(Q(host_id__in=service_host_ids) |
             Q(host__isnull=True, deployment_release__in=releases)), 'updated_at', start, end)
    action_items = IncidentActionItem.objects.filter(incident__in=review_incidents)
    overdue = sum(1 for item in action_items if is_overdue(item, now=now))
    unhealthy = _window_filter(DeploymentHealthEvaluation.objects.filter(
        release__in=releases, status=DeploymentHealthEvaluation.STATUS_UNHEALTHY,
    ), 'evaluated_at', start, end)
    unhealthy_count = sum(
        1 for item in unhealthy.only('batch_identity')
        if _batch_contains_any_host(item.batch_identity, service_host_ids)
    )
    failed_ci = _window_filter(CIDelivery.objects.filter(
        release__in=releases, status='failed',
    ), 'received_at', start, end).count()
    exhausted_slos = ServiceSlo.objects.filter(
        service=service, enabled=True, last_state=ServiceSlo.STATE_EXHAUSTED,
    ).count()
    open_count = incidents.count()
    closed_without_postmortem = closed_incidents.filter(
        root_cause='', resolution='', follow_up='',
    ).count()
    evidence = {
        'active_alerts': alerts.count(),
        'open_incidents': open_count,
        'exhausted_slos': exhausted_slos,
        'unhealthy_deployments': unhealthy_count,
        'failed_ci_deliveries': failed_ci,
    }
    review = {
        'open': open_count,
        'closed_without_postmortem': closed_without_postmortem,
        'action_items_open': action_items.filter(
            status__in=(IncidentActionItem.STATUS_OPEN, IncidentActionItem.STATUS_IN_PROGRESS),
        ).count(),
        'action_items_overdue': overdue,
    }
    return evidence, review, incidents


def _score(evidence, review, incidents):
    penalty = min(45, evidence['active_alerts'] * 8)
    penalty += min(45, sum(SEVERITIES.get(item.severity, 14) for item in incidents))
    penalty += min(25, evidence['exhausted_slos'] * 15)
    penalty += min(25, evidence['unhealthy_deployments'] * 12)
    penalty += min(20, evidence['failed_ci_deliveries'] * 8)
    penalty += min(15, review['closed_without_postmortem'] * 5)
    penalty += min(15, review['action_items_overdue'] * 5)
    score = max(0, min(100, 100 - penalty))
    total = sum(evidence.values()) + review['closed_without_postmortem']
    if not total:
        return score, 'healthy'
    if score < 50 or evidence['exhausted_slos'] or evidence['unhealthy_deployments']:
        return score, 'critical'
    if score < 85 or evidence['active_alerts'] or evidence['open_incidents']:
        return score, 'degraded'
    return score, 'healthy'


def build_service_reliability(services, visible_hosts, window_start, window_end, now=None):
    """Return bounded service reliability rows for already-authorized services."""
    now = now or timezone.now()
    visible_host_ids = {getattr(host, 'id', host) for host in visible_hosts if getattr(host, 'id', host)}
    rows = []
    for service in sorted(list(services), key=lambda item: (item.name, item.id)):
        result = _service_evidence(service, visible_host_ids, window_start, window_end, now)
        if result is None:
            continue
        evidence, review, incidents = result
        score, state = _score(evidence, review, incidents)
        recommendation = {
            'critical': '优先协调服务负责人处理可靠性风险并核查发布健康状态',
            'degraded': '持续跟踪告警、事件复盘和行动项完成情况',
            'healthy': '保持现有监控覆盖并按周期复核可靠性证据',
        }[state]
        rows.append({
            'service': {'id': service.id, 'name': service.name},
            'score': score,
            'state': state,
            'evidence_counts': evidence,
            'incident_review': review,
            'recommendation': recommendation,
        })
    rows.sort(key=lambda item: (STATE_ORDER[item['state']], item['score'], item['service']['name'], item['service']['id']))
    return rows[:MAX_RELIABILITY_SERVICES]
