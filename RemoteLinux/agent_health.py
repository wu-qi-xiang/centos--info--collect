"""Safe, local health evaluation for outbound Host Agent registrations."""

from django.conf import settings
from django.utils import timezone

from devops.models import AlertEvent
from devops.services import record_alert, resolve_alert

from .models import HostAgent


AGENT_HEARTBEAT_METRIC = 'agent_heartbeat'


def _health_state(agent, now, timeout_seconds):
    if agent.is_revoked:
        return 'revoked'
    reference_at = agent.last_heartbeat_at or agent.created_at
    if not reference_at or (now - reference_at).total_seconds() > timeout_seconds:
        return 'offline'
    if agent.collection_delay_seconds > timeout_seconds:
        return 'stale'
    return 'healthy'


def evaluate_host_agent_health(now=None, timeout_seconds=None):
    """Open or resolve one fixed lifecycle alert per registered host."""
    now = now or timezone.now()
    timeout_seconds = timeout_seconds or settings.AGENT_HEARTBEAT_TIMEOUT_SECONDS
    result = {'evaluated': 0, 'offline': 0, 'stale': 0, 'recovered': 0, 'revoked': 0}
    for agent in HostAgent.objects.select_related('host').all():
        state = _health_state(agent, now, timeout_seconds)
        if state == 'revoked':
            result['revoked'] += 1
            continue
        result['evaluated'] += 1
        if state == 'offline':
            record_alert(agent.host, AGENT_HEARTBEAT_METRIC,
                         'Host Agent 心跳超过 %s 秒未上报' % timeout_seconds,
                         AlertEvent.LEVEL_CRITICAL)
            result['offline'] += 1
        elif state == 'stale':
            record_alert(agent.host, AGENT_HEARTBEAT_METRIC,
                         'Host Agent 采集延迟超过 %s 秒' % timeout_seconds,
                         AlertEvent.LEVEL_WARNING)
            result['stale'] += 1
        elif resolve_alert(agent.host, AGENT_HEARTBEAT_METRIC, 'Host Agent 心跳已恢复'):
            result['recovered'] += 1
    return result
