"""Safe, non-persistent postmortem draft generation for resolved incidents."""

from .models import Incident, RunbookEffectivenessFeedback


def build_incident_postmortem_draft(incident):
    """Return a structured draft without exposing or persisting free-form incident text."""
    if incident.status not in (Incident.STATUS_RESOLVED, Incident.STATUS_CLOSED):
        raise ValueError('only resolved incidents can produce a postmortem draft')
    feedback_count = 0
    if incident.command_execution_id:
        feedback_count = RunbookEffectivenessFeedback.objects.filter(
            command_execution_id=incident.command_execution_id,
        ).count()
    return {
        'incident': {
            'id': incident.id,
            'severity': incident.severity,
            'status': incident.status,
        },
        'evidence_counts': {
            'timeline_entries': incident.timeline.count(),
            'linked_alert': 1 if incident.alert_id else 0,
            'linked_release': 1 if incident.deployment_release_id else 0,
            'linked_command': 1 if incident.command_execution_id else 0,
            'runbook_feedback_entries': feedback_count,
        },
        'draft': {
            'impact': '请根据服务影响与事件处置记录确认实际影响范围',
            'root_cause': '请基于已确认的证据填写根因，避免推测性结论',
            'resolution': '请记录已验证的处置和恢复结果',
            'follow_up': '请登记后续预防措施、负责人和完成时间',
        },
    }
