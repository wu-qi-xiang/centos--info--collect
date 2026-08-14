"""Safe, read-only aggregation for the DevOps incident command center."""

from django.db.models import Q

from ..models import (
    AlertEvent,
    ApprovalRequest,
    CIDelivery,
    DeploymentHealthEvaluation,
    DeploymentRelease,
    Incident,
    IncidentActionItem,
    ServiceSlo,
)


TIMELINE_LIMIT = 12


def _fully_visible_releases(visible_host_ids):
    """Return releases whose complete target set is inside the caller scope."""
    candidates = DeploymentRelease.objects.select_related('app').prefetch_related('hosts').all()
    results = []
    for release in candidates:
        release_host_ids = set(release.hosts.values_list('id', flat=True))
        if release_host_ids and release_host_ids.issubset(visible_host_ids):
            results.append(release)
    return results


def _scoped_approvals(visible_host_ids, release_ids):
    approvals = ApprovalRequest.objects.select_related('host', 'deployment_release').all()
    results = []
    for approval in approvals:
        if not approval.host_id and not approval.deployment_release_id:
            continue
        if approval.host_id and approval.host_id not in visible_host_ids:
            continue
        if approval.deployment_release_id and approval.deployment_release_id not in release_ids:
            continue
        results.append(approval)
    return results


def _latest_health_by_release(releases):
    health = {}
    for evaluation in DeploymentHealthEvaluation.objects.filter(
            release__in=releases).only('release_id', 'status', 'evaluated_at').order_by(
                'release_id', '-evaluated_at', '-id'):
        health.setdefault(evaluation.release_id, evaluation)
    return health


def _timeline(incidents, alerts, releases, slos, approvals, deliveries):
    """Build bounded metadata-only chronology without operational payloads."""
    entries = []
    entries.extend({
        'kind': 'incident', 'id': item.id, 'status': item.status,
        'severity': item.severity, 'occurred_at': item.updated_at,
    } for item in incidents)
    entries.extend({
        'kind': 'alert', 'id': item.id, 'status': item.status,
        'severity': item.level, 'occurred_at': item.updated_at,
    } for item in alerts)
    entries.extend({
        'kind': 'deployment', 'id': item.id, 'status': item.status,
        'severity': None, 'occurred_at': item.finished_at or item.created_at,
    } for item in releases)
    entries.extend({
        'kind': 'slo', 'id': item.id, 'status': item.last_state,
        'severity': None, 'occurred_at': item.last_evaluated_at or item.updated_at,
    } for item in slos)
    entries.extend({
        'kind': 'approval', 'id': item.id, 'status': item.status,
        'severity': None, 'occurred_at': item.decided_at or item.created_at,
    } for item in approvals)
    entries.extend({
        'kind': 'ci_delivery', 'id': item.id, 'status': item.status,
        'severity': None, 'occurred_at': item.received_at,
    } for item in deliveries)
    return [{
        'kind': item['kind'], 'id': item['id'], 'status': item['status'],
        'severity': item['severity'], 'occurred_at': item['occurred_at'],
    } for item in sorted(entries, key=lambda entry: entry['occurred_at'], reverse=True)[:TIMELINE_LIMIT]]


def build_incident_command_center(visible_hosts, visible_services, scoped_incidents):
    """Return a bounded, locally-derived command-center safety summary.

    Callers must provide already-authorized hosts, services, and incidents.  The
    result intentionally contains no incident text, alert payload, release/CI
    metadata, commands, or action-item text.
    """
    visible_host_ids = set(visible_hosts.values_list('id', flat=True))
    visible_service_ids = set(visible_services.values_list('id', flat=True))
    incident_ids = {incident.id for incident in scoped_incidents}
    active_alerts = list(AlertEvent.objects.filter(
        Q(host_id__in=visible_host_ids) | Q(host__isnull=True),
        status__in=(AlertEvent.STATUS_OPEN, AlertEvent.STATUS_PROCESSING),
    ).only('id', 'status', 'level', 'updated_at'))
    active_incidents = [item for item in scoped_incidents if item.status in (
        Incident.STATUS_OPEN, Incident.STATUS_PROCESSING,
    )]
    releases = _fully_visible_releases(visible_host_ids)
    release_ids = {release.id for release in releases}
    latest_health = _latest_health_by_release(releases)
    unhealthy_release_ids = {
        release_id for release_id, item in latest_health.items()
        if item.status == DeploymentHealthEvaluation.STATUS_UNHEALTHY
    }
    slos = list(ServiceSlo.objects.filter(service_id__in=visible_service_ids, enabled=True).only(
        'id', 'last_state', 'last_evaluated_at', 'updated_at',
    ))
    approvals = _scoped_approvals(visible_host_ids, release_ids)
    failed_deliveries = list(CIDelivery.objects.filter(
        release_id__in=release_ids, status='failed',
    ).only('id', 'status', 'received_at'))
    action_items = IncidentActionItem.objects.filter(incident_id__in=incident_ids)
    action_counts = {
        'open': action_items.filter(status=IncidentActionItem.STATUS_OPEN).count(),
        'in_progress': action_items.filter(status=IncidentActionItem.STATUS_IN_PROGRESS).count(),
    }
    from django.utils import timezone
    action_counts['overdue'] = action_items.filter(
        status__in=(IncidentActionItem.STATUS_OPEN, IncidentActionItem.STATUS_IN_PROGRESS),
        due_at__lt=timezone.now(),
    ).count()
    return {
        'counts': {
            'active_alerts': len(active_alerts),
            'open_incidents': len(active_incidents),
            'critical_incidents': sum(1 for item in active_incidents if item.severity == Incident.SEVERITY_CRITICAL),
            'unhealthy_releases': len(unhealthy_release_ids),
            'exhausted_slos': sum(1 for item in slos if item.last_state == ServiceSlo.STATE_EXHAUSTED),
            'pending_approvals': sum(1 for item in approvals if item.status == ApprovalRequest.STATUS_PENDING),
            'failed_ci_deliveries': len(failed_deliveries),
        },
        'action_items': action_counts,
        'timeline': _timeline(
            active_incidents, active_alerts, releases, slos, approvals, failed_deliveries,
        ),
    }
