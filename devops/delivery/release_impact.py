"""Read-only service-level release impact simulation."""

from math import ceil

from django.db.models import Q

from ..models import AlertEvent, CIDelivery, DeploymentHealthEvaluation, Incident, ServiceSlo


def _batch_contains_visible_host(batch_identity, host_ids):
    prefix = 'host_ids='
    if not (batch_identity or '').startswith(prefix):
        return False
    return bool(set(batch_identity[len(prefix):].split(',')) & {str(host_id) for host_id in host_ids})


def build_release_draft_impact_preview(services, visible_hosts, batch_size=0):
    """Return a safe, read-only risk summary for an unsaved release draft."""
    host_ids = {
        getattr(host, 'id', host) for host in visible_hosts
        if getattr(host, 'id', host)
    }
    if not host_ids:
        raise ValueError('release draft is outside the supplied host scope')
    service_ids = [service.id for service in services]
    batch_size = int(batch_size or 0)
    if batch_size < 0 or batch_size > len(host_ids):
        raise ValueError('invalid batch size')
    critical_alerts = AlertEvent.objects.filter(
        host_id__in=host_ids,
        status__in=(AlertEvent.STATUS_OPEN, AlertEvent.STATUS_PROCESSING),
        level=AlertEvent.LEVEL_CRITICAL,
    ).count()
    open_incidents = Incident.objects.filter(
        host_id__in=host_ids,
        status__in=(Incident.STATUS_OPEN, Incident.STATUS_PROCESSING),
    ).count()
    exhausted_slos = ServiceSlo.objects.filter(
        service_id__in=service_ids, enabled=True,
        last_state=ServiceSlo.STATE_EXHAUSTED,
    ).count()
    evidence = {
        'critical_alerts': critical_alerts,
        'open_incidents': open_incidents,
        'exhausted_slos': exhausted_slos,
        'unhealthy_deployments': 0,
        'failed_ci_deliveries': 0,
    }
    reasons = [key for key in (
        'critical_alerts', 'open_incidents', 'exhausted_slos',
        'unhealthy_deployments', 'failed_ci_deliveries',
    ) if evidence[key]]
    risk = 'critical' if any((critical_alerts, exhausted_slos)) else (
        'elevated' if open_incidents else 'low'
    )
    effective_batch_size = batch_size or len(host_ids)
    return {
        'risk': risk,
        'service_count': len(service_ids),
        'visible_host_count': len(host_ids),
        'proposed_batch_size': effective_batch_size,
        'proposed_batch_count': int(ceil(float(len(host_ids)) / effective_batch_size)),
        'evidence_counts': evidence,
        'reasons': reasons,
        'recommendation': (
            '保持当前范围，先处理活动风险并走人工审批' if risk == 'critical' else
            ('建议缩小灰度批次并在发布前复核事件处置' if risk == 'elevated' else '当前未发现需要升级的发布影响信号')
        ),
    }


def build_release_impact_preview(release, services, visible_hosts, batch_size=0):
    """Return safe release risk for already-authorized release/service objects."""
    host_ids = {getattr(host, 'id', host) for host in visible_hosts if getattr(host, 'id', host)}
    release_host_ids = set(release.hosts.filter(id__in=host_ids).values_list('id', flat=True))
    if not release_host_ids:
        raise ValueError('release is outside the supplied host scope')
    service_ids = [service.id for service in services]
    if not service_ids:
        raise ValueError('no authorized services')
    batch_size = int(batch_size or 0)
    if batch_size < 0 or batch_size > len(release_host_ids):
        raise ValueError('invalid batch size')
    critical_alerts = AlertEvent.objects.filter(
        host_id__in=release_host_ids,
        status__in=(AlertEvent.STATUS_OPEN, AlertEvent.STATUS_PROCESSING),
        level=AlertEvent.LEVEL_CRITICAL,
    ).count()
    open_incidents = Incident.objects.filter(
        Q(host_id__in=release_host_ids) |
        Q(host__isnull=True, deployment_release_id=release.id),
        status__in=(Incident.STATUS_OPEN, Incident.STATUS_PROCESSING),
    ).count()
    exhausted_slos = ServiceSlo.objects.filter(
        service_id__in=service_ids, enabled=True,
        last_state=ServiceSlo.STATE_EXHAUSTED,
    ).count()
    unhealthy_deployments = sum(
        1 for row in DeploymentHealthEvaluation.objects.filter(
            release=release, status=DeploymentHealthEvaluation.STATUS_UNHEALTHY,
        ).only('batch_identity')
        if _batch_contains_visible_host(row.batch_identity, release_host_ids)
    )
    failed_ci_deliveries = CIDelivery.objects.filter(release=release, status='failed').count()
    evidence = {
        'critical_alerts': critical_alerts,
        'open_incidents': open_incidents,
        'exhausted_slos': exhausted_slos,
        'unhealthy_deployments': unhealthy_deployments,
        'failed_ci_deliveries': failed_ci_deliveries,
    }
    reasons = [key for key in (
        'critical_alerts', 'open_incidents', 'exhausted_slos',
        'unhealthy_deployments', 'failed_ci_deliveries',
    ) if evidence[key]]
    risk = 'critical' if any((critical_alerts, exhausted_slos, unhealthy_deployments, failed_ci_deliveries)) else (
        'elevated' if open_incidents else 'low'
    )
    effective_batch_size = batch_size or len(release_host_ids)
    return {
        'risk': risk,
        'service_count': len(service_ids),
        'visible_host_count': len(release_host_ids),
        'proposed_batch_size': effective_batch_size,
        'proposed_batch_count': int(ceil(float(len(release_host_ids)) / effective_batch_size)),
        'evidence_counts': evidence,
        'reasons': reasons,
        'recommendation': (
            '保持当前范围，先处理活动风险并走人工审批' if risk == 'critical' else
            ('建议缩小灰度批次并在发布前复核事件处置' if risk == 'elevated' else '当前未发现需要升级的发布影响信号')
        ),
    }
