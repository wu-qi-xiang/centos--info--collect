"""Read-only, host-scoped service incident workbench aggregation."""

from django.db.models import Q
from django.utils import timezone

from devops.models import CIDelivery, DeploymentHealthEvaluation, Incident

from .service_impact import (
    OPEN_INCIDENT_STATUSES,
    _batch_contains_any_host,
    _visible_service_hosts,
    _visible_service_releases,
    build_service_impacts,
)


MAX_WORKBENCH_INCIDENTS = 8
MAX_WORKBENCH_RELEASES = 8


def _timestamp(value):
    return timezone.localtime(value).strftime('%Y-%m-%d %H:%M:%S') if value else None


def _latest_visible_health(release_id, service_host_ids, window_start, window_end):
    evaluations = DeploymentHealthEvaluation.objects.filter(
        release_id=release_id,
        evaluated_at__gte=window_start,
        evaluated_at__lte=window_end,
    ).only('status', 'batch_identity', 'evaluated_at').order_by('-evaluated_at', '-id')
    for evaluation in evaluations:
        if _batch_contains_any_host(evaluation.batch_identity, service_host_ids):
            return evaluation
    return None


def build_service_workbench(service, visible_hosts, window_start, window_end):
    """Build bounded safe records for one caller-authorized service.

    The caller must verify service visibility. This helper only queries existing
    local records and intentionally excludes incident content, release scripts,
    CI metadata, host details, and health summaries.
    """
    if not window_start or not window_end or window_start > window_end:
        raise ValueError('invalid service workbench window')
    visible_host_ids = {
        getattr(host, 'id', host) for host in visible_hosts if getattr(host, 'id', host)
    }
    service_host_ids = _visible_service_hosts(service, visible_host_ids)
    if service.hosts.exists() and not service_host_ids:
        raise ValueError('service is outside the supplied host scope')

    impact_rows = build_service_impacts(
        [service], visible_hosts, window_start=window_start, window_end=window_end,
    )
    impact = impact_rows[0] if impact_rows else {
        'evidence_counts': {
            'active_alerts': 0, 'open_incidents': 0, 'exhausted_slos': 0,
            'unhealthy_deployments': 0, 'failed_ci_deliveries': 0,
        },
        'state': 'healthy',
    }

    visible_releases = _visible_service_releases(service, service_host_ids)
    incidents = Incident.objects.filter(
        status__in=OPEN_INCIDENT_STATUSES,
        updated_at__gte=window_start,
        updated_at__lte=window_end,
    ).filter(
        Q(host_id__in=service_host_ids) |
        Q(host__isnull=True, deployment_release__in=visible_releases)
    ).order_by('-updated_at', '-id')[:MAX_WORKBENCH_INCIDENTS]

    incident_rows = [{
        'id': incident.id,
        'status': incident.status,
        'owner': incident.owner,
        'sla_due_at': _timestamp(incident.sla_due_at),
    } for incident in incidents]

    candidate_releases = visible_releases.filter(
        Q(created_at__gte=window_start, created_at__lte=window_end) |
        Q(health_evaluations__evaluated_at__gte=window_start,
          health_evaluations__evaluated_at__lte=window_end) |
        Q(ci_deliveries__received_at__gte=window_start,
          ci_deliveries__received_at__lte=window_end)
    ).distinct().order_by('-created_at', '-id')[:MAX_WORKBENCH_RELEASES * 4]
    release_rows = []
    for release in candidate_releases:
        health = _latest_visible_health(release.id, service_host_ids, window_start, window_end)
        latest_ci = CIDelivery.objects.filter(
            release_id=release.id, received_at__gte=window_start, received_at__lte=window_end,
        ).only('received_at').order_by('-received_at', '-id').first()
        observed_at = health.evaluated_at if health else (
            latest_ci.received_at if latest_ci else (release.finished_at or release.created_at)
        )
        release_rows.append({
            'id': release.id,
            'status': release.status,
            'health_state': health.status if health else 'unknown',
            'observed_at': _timestamp(observed_at),
            '_observed_at': observed_at,
        })
    release_rows.sort(key=lambda item: (item['_observed_at'], item['id']), reverse=True)
    for item in release_rows:
        item.pop('_observed_at', None)

    return {
        'service': {'id': service.id, 'name': service.name},
        'counts': impact['evidence_counts'],
        'state': impact['state'],
        'incidents': incident_rows,
        'releases': release_rows[:MAX_WORKBENCH_RELEASES],
    }
