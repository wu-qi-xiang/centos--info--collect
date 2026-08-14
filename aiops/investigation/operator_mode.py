"""Bounded, read-only local operator scan."""
from datetime import timedelta

from django.utils import timezone
from devops.models import AlertEvent, MetricSample, ServiceSlo, DeploymentHealthEvaluation
from RemoteLinux.models import HostAgent
from RemoteLinux.models import NewLinux
from devops.models import ServiceCatalog

MAX_FINDINGS = 80


def run_scheduled_operator_scan():
    """Run a local, read-only aggregate without persisting findings."""
    result = build_operator_scan(list(NewLinux.objects.all()), list(ServiceCatalog.objects.all()), window='24h')
    return {'scanned': result.get('counts', {}).get('hosts', 0),
            'findings': result.get('counts', {}).get('findings', 0),
            'partial': bool(result.get('partial')), 'errors': len(result.get('errors') or [])}


def build_operator_scan(hosts, services, window='24h', now=None):
    now = now or timezone.now()
    delta = {'6h': timedelta(hours=6), '24h': timedelta(hours=24), '7d': timedelta(days=7)}.get(window, timedelta(hours=24))
    start = now - delta
    findings, errors = [], []
    host_ids = [host.id for host in hosts]

    def add(kind, resource, severity, status, summary, occurred_at=None):
        findings.append({'kind': kind, 'resource': str(resource)[:200], 'severity': severity,
                         'status': status, 'summary': str(summary)[:300],
                         'occurred_at': occurred_at.isoformat() if occurred_at else None})
    try:
        alerts = AlertEvent.objects.filter(host_id__in=host_ids, updated_at__gte=start,
                                           status__in=(AlertEvent.STATUS_OPEN, AlertEvent.STATUS_PROCESSING))
        critical = list(alerts.filter(level=AlertEvent.LEVEL_CRITICAL)[:40])
        if critical:
            add('critical_alert_cluster', 'visible-hosts', 'critical', 'active',
                '授权主机存在活动严重告警聚集', critical[0].updated_at)
    except Exception:
        errors.append({'source': 'alerts', 'code': 'source_unavailable'})
    try:
        for agent in HostAgent.objects.filter(host_id__in=host_ids, is_revoked=False)[:80]:
            if not agent.last_heartbeat_at or agent.last_heartbeat_at < now - timedelta(minutes=15):
                add('host_agent', agent.host_id, 'warning', 'stale', '主机 Agent 心跳过期', agent.last_heartbeat_at)
    except Exception:
        errors.append({'source': 'agents', 'code': 'source_unavailable'})
    try:
        for slo in ServiceSlo.objects.filter(service__in=services, last_state=ServiceSlo.STATE_EXHAUSTED,
                last_evaluated_at__gte=start, last_evaluated_at__lte=now)[:40]:
            add('slo', slo.service_id, 'high', 'exhausted', '服务 SLO 预算已耗尽', slo.last_evaluated_at)
    except Exception:
        errors.append({'source': 'slos', 'code': 'source_unavailable'})
    try:
        for health in DeploymentHealthEvaluation.objects.filter(release__hosts__in=hosts,
                status=DeploymentHealthEvaluation.STATUS_UNHEALTHY, evaluated_at__gte=start,
                evaluated_at__lte=now)[:40]:
            add('deployment', health.release_id, 'high', 'unhealthy', '发布健康评估异常', health.evaluated_at)
    except Exception:
        errors.append({'source': 'deployments', 'code': 'source_unavailable'})
    try:
        for host in hosts:
            if not MetricSample.objects.filter(host=host, collected_at__gte=start).exists():
                add('metric', host.id, 'warning', 'missing', '时间窗口内缺少监控样本')
    except Exception:
        errors.append({'source': 'metrics', 'code': 'source_unavailable'})
    findings.sort(key=lambda row: (row['occurred_at'] or '', row['kind'], row['resource']))
    return {'window': window, 'counts': {'findings': len(findings), 'hosts': len(host_ids), 'services': len(services)},
            'findings': findings[:MAX_FINDINGS], 'partial': bool(errors), 'errors': errors[:10],
            'recommendation': '按严重度确认告警、Agent、发布和 SLO 状态，再进入现有审批流程。'}
