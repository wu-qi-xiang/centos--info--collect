"""Read-only, host-scoped service impact aggregation for the AIOps workbench."""

from django.db.models import Q

from devops.models import (
    AlertEvent,
    CIDelivery,
    DeploymentHealthEvaluation,
    DeploymentRelease,
    Incident,
    ServiceCatalog,
    ServiceSlo,
)


MAX_SERVICE_IMPACTS = 32
ACTIVE_ALERT_STATUSES = (
    AlertEvent.STATUS_OPEN,
    AlertEvent.STATUS_PROCESSING,
    AlertEvent.STATUS_SILENCED,
)
OPEN_INCIDENT_STATUSES = (
    Incident.STATUS_OPEN,
    Incident.STATUS_PROCESSING,
)
PUBLIC_CRITICALITIES = frozenset((
    ServiceCatalog.CRITICALITY_LOW,
    ServiceCatalog.CRITICALITY_MEDIUM,
    ServiceCatalog.CRITICALITY_HIGH,
    ServiceCatalog.CRITICALITY_CRITICAL,
))
STATE_ORDER = {'critical': 0, 'degraded': 1, 'healthy': 2}


def _visible_service_hosts(service, visible_host_ids):
    return set(service.hosts.filter(id__in=visible_host_ids).values_list('id', flat=True))


def _visible_service_releases(service, host_ids):
    """Return service-associated releases that deployed to a visible service host."""
    if not host_ids:
        return DeploymentRelease.objects.none()
    return DeploymentRelease.objects.filter(
        Q(app__devops_projects__services=service) | Q(hosts__id__in=host_ids),
        hosts__id__in=host_ids,
    ).distinct()


def _batch_contains_any_host(batch_identity, host_ids):
    prefix = 'host_ids='
    if not (batch_identity or '').startswith(prefix):
        return False
    return bool(set(batch_identity[len(prefix):].split(',')) & {
        str(host_id) for host_id in host_ids
    })


def _state_and_recommendation(has_critical_alert, evidence):
    if (has_critical_alert or evidence['exhausted_slos'] or
            evidence['unhealthy_deployments'] or evidence['failed_ci_deliveries']):
        return 'critical', '优先协调服务负责人处理活动事件并核查发布健康状态'
    if evidence['active_alerts'] or evidence['open_incidents']:
        return 'degraded', '持续跟踪活动告警和事件处置进展'
    return 'healthy', '当前未发现需要升级的服务影响信号'


def _in_window(queryset, field_name, window_start, window_end):
    if window_start is None or window_end is None:
        return queryset
    return queryset.filter(**{
        '%s__gte' % field_name: window_start,
        '%s__lte' % field_name: window_end,
    })


def build_service_impacts(services, visible_hosts, now=None, window_start=None, window_end=None):
    """Return bounded safe service impacts for caller-authorized objects.

    The caller owns service and host authorization. This helper is analysis-only:
    it performs no writes and intentionally omits raw alert, incident, deployment,
    and CI fields. ``now`` is accepted to keep the API deterministic as its
    caller evolves window handling.  When supplied, ``window_start`` and
    ``window_end`` constrain locally stored operational evidence.
    """
    del now
    if (window_start is None) != (window_end is None):
        raise ValueError('both window boundaries are required')
    if window_start is not None and window_start > window_end:
        raise ValueError('invalid service impact window')
    visible_host_ids = {
        getattr(host, 'id', host) for host in visible_hosts if getattr(host, 'id', host)
    }
    if not visible_host_ids:
        return []

    results = []
    for service in sorted(list(services), key=lambda item: (item.name, item.id)):
        service_host_ids = _visible_service_hosts(service, visible_host_ids)
        has_hosts = service.hosts.exists()
        # A hostless catalog entry is intentionally visible under the established
        # catalog rule, but a service whose only hosts are outside caller scope is not.
        if not service_host_ids and has_hosts:
            continue

        alerts = _in_window(AlertEvent.objects.filter(
            host_id__in=service_host_ids,
            status__in=ACTIVE_ALERT_STATUSES,
        ), 'updated_at', window_start, window_end)
        incidents = _in_window(Incident.objects.filter(
            host_id__in=service_host_ids,
            status__in=OPEN_INCIDENT_STATUSES,
        ), 'updated_at', window_start, window_end)
        affected_host_ids = set(alerts.values_list('host_id', flat=True))
        affected_host_ids.update(incidents.values_list('host_id', flat=True))

        visible_releases = _visible_service_releases(service, service_host_ids)
        unhealthy_deployments = sum(
            1 for evaluation in _in_window(DeploymentHealthEvaluation.objects.filter(
                release__in=visible_releases,
                status=DeploymentHealthEvaluation.STATUS_UNHEALTHY,
            ), 'evaluated_at', window_start, window_end).only('batch_identity')
            if _batch_contains_any_host(evaluation.batch_identity, service_host_ids)
        )
        failed_ci_deliveries = _in_window(CIDelivery.objects.filter(
            release__in=visible_releases,
            status='failed',
        ), 'received_at', window_start, window_end).count()
        evidence = {
            'active_alerts': alerts.count(),
            'open_incidents': incidents.count(),
            'exhausted_slos': ServiceSlo.objects.filter(
                service=service,
                enabled=True,
                last_state=ServiceSlo.STATE_EXHAUSTED,
            ).count(),
            'unhealthy_deployments': unhealthy_deployments,
            'failed_ci_deliveries': failed_ci_deliveries,
        }
        state, recommendation = _state_and_recommendation(
            alerts.filter(level=AlertEvent.LEVEL_CRITICAL).exists(), evidence,
        )
        criticality = service.criticality
        if criticality not in PUBLIC_CRITICALITIES:
            criticality = ServiceCatalog.CRITICALITY_MEDIUM
        results.append({
            'service': {'id': service.id, 'name': service.name},
            'criticality': criticality,
            'host_count': len(service_host_ids),
            'affected_host_count': len(affected_host_ids),
            'dependency_count': service.upstream_links.count(),
            'evidence_counts': evidence,
            'state': state,
            'recommendation': recommendation,
        })

    results.sort(key=lambda item: (
        STATE_ORDER[item['state']],
        -sum(item['evidence_counts'].values()),
        item['service']['name'],
        item['service']['id'],
    ))
    return results[:MAX_SERVICE_IMPACTS]
