"""Derived, allowlist-only data for the unauthenticated service status page."""

from django.utils import timezone

from ..models import AlertEvent, Incident, MaintenanceWindow, ServiceCatalog, ServiceSlo


STATE_OPERATIONAL = 'operational'
STATE_DEGRADED = 'degraded'
STATE_MAINTENANCE = 'maintenance'

STATE_LABELS = {
    STATE_OPERATIONAL: '运行正常',
    STATE_DEGRADED: '服务受影响',
    STATE_MAINTENANCE: '维护中',
}

TREND_STABLE = 'stable'
TREND_AT_RISK = 'at_risk'
TREND_UNAVAILABLE = 'unavailable'
TREND_LABELS = {
    TREND_STABLE: '稳定',
    TREND_AT_RISK: '存在风险',
    TREND_UNAVAILABLE: '数据不可用',
}

ACTIVE_ALERT_STATUSES = (AlertEvent.STATUS_OPEN, AlertEvent.STATUS_PROCESSING)
ACTIVE_INCIDENT_STATUSES = (Incident.STATUS_OPEN, Incident.STATUS_PROCESSING)


def _service_trend(slos):
    states = {slo.last_state for slo in slos if slo.enabled}
    if ServiceSlo.STATE_UNAVAILABLE in states:
        return TREND_UNAVAILABLE
    if ServiceSlo.STATE_EXHAUSTED in states:
        return TREND_AT_RISK
    return TREND_STABLE


def _incident_timeline(now):
    timeline = []
    incidents = Incident.objects.only('status', 'created_at', 'resolved_at').order_by('-created_at')[:12]
    for incident in incidents:
        if incident.status in ACTIVE_INCIDENT_STATUSES:
            timeline.append({
                'state': 'investigating',
                'state_label': '事件处理中',
                'occurred_at': incident.created_at,
            })
        elif incident.status in (Incident.STATUS_RESOLVED, Incident.STATUS_CLOSED):
            timeline.append({
                'state': 'resolved',
                'state_label': '事件已解决',
                'occurred_at': incident.resolved_at or incident.created_at,
            })
    return sorted(timeline, key=lambda item: item['occurred_at'] or now, reverse=True)[:12]


def build_public_status(now=None):
    """Return a new, explicitly allowlisted public read model.

    This deliberately reads state fields only. It never returns Django model
    instances, model dictionaries, host information, free-form alert/incident
    text, owners, credentials, URLs, or version values.
    """
    now = now or timezone.now()
    services = list(ServiceCatalog.objects.exclude(
        lifecycle=ServiceCatalog.LIFECYCLE_RETIRED
    ).prefetch_related('hosts', 'slos'))
    active_windows = list(MaintenanceWindow.objects.filter(
        enabled=True, starts_at__lte=now, ends_at__gt=now,
    ).prefetch_related('services'))

    maintenance_service_ids = set()
    maintenance = []
    for window in active_windows:
        service_ids = set(window.services.values_list('id', flat=True))
        maintenance_service_ids.update(service_ids)
        maintenance.append({
            'title': window.name,
            'state': 'scheduled',
            'state_label': '计划维护',
            'service_count': len(service_ids),
            'starts_at': window.starts_at,
            'ends_at': window.ends_at,
        })

    service_host_ids = {
        service.id: {host.id for host in service.hosts.all()}
        for service in services
    }
    active_alert_host_ids = set(AlertEvent.objects.filter(
        status__in=ACTIVE_ALERT_STATUSES,
    ).exclude(host__isnull=True).values_list('host_id', flat=True))
    active_incident_host_ids = set()
    for incident in Incident.objects.filter(status__in=ACTIVE_INCIDENT_STATUSES).only(
            'host_id', 'alert__host_id'):
        if incident.host_id:
            active_incident_host_ids.add(incident.host_id)
        elif incident.alert_id and incident.alert and incident.alert.host_id:
            active_incident_host_ids.add(incident.alert.host_id)

    public_services = []
    for service in services:
        trend = _service_trend(service.slos.all())
        host_ids = service_host_ids[service.id]
        has_active_event = bool(host_ids & (active_alert_host_ids | active_incident_host_ids))
        if service.id in maintenance_service_ids or service.lifecycle == ServiceCatalog.LIFECYCLE_MAINTENANCE:
            state = STATE_MAINTENANCE
        elif has_active_event or trend != TREND_STABLE:
            state = STATE_DEGRADED
        else:
            state = STATE_OPERATIONAL
        public_services.append({
            'name': service.name,
            'state': state,
            'state_label': STATE_LABELS[state],
            'availability_trend': trend,
            'availability_trend_label': TREND_LABELS[trend],
        })

    states = {service['state'] for service in public_services}
    if STATE_MAINTENANCE in states or maintenance:
        overall_state = STATE_MAINTENANCE
    elif STATE_DEGRADED in states:
        overall_state = STATE_DEGRADED
    else:
        overall_state = STATE_OPERATIONAL
    return {
        'overall_state': overall_state,
        'overall_state_label': STATE_LABELS[overall_state],
        'services': public_services,
        'maintenance': maintenance,
        'timeline': _incident_timeline(now),
        'generated_at': now,
    }
