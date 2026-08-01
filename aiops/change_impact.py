"""Deterministic, read-only change-impact correlation for the AIOps dashboard."""

from collections import defaultdict
from datetime import timedelta

from django.db.models import Q
from django.urls import reverse
from django.utils import timezone

from devops.models import (
    AuditLog,
    DeploymentRelease,
    DevOpsModulePermission,
    DevOpsRole,
    PrometheusRuleRevision,
)
from devops.services import has_role


DEFAULT_WINDOW_HOURS = 2
MAX_IMPACTS = 12


def _timestamp(value):
    if not value:
        return None
    return timezone.localtime(value).strftime('%Y-%m-%d %H:%M:%S')


def _host_name(host):
    return host.linux_name or host.linux_ip or host.linux_hostname or '未命名主机'


def _audit_evidence(audits):
    """Return metadata only. AuditLog.detail can contain operational secrets."""
    return [
        {
            'kind': 'audit',
            'summary': '审计：%s（%s #%s）' % (audit.action, audit.target_type or '-', audit.target_id or '-'),
            'observed_at': _timestamp(audit.created_at),
        }
        for audit in audits
    ]


def _health_evidence(release, host_id):
    prefix = 'host_ids='
    host_token = str(host_id)
    evidence = []
    for evaluation in release.health_evaluations.all():
        batch = (evaluation.batch_identity or '')
        host_ids = batch[len(prefix):].split(',') if batch.startswith(prefix) else []
        if host_token not in host_ids:
            continue
        evidence.append({
            'kind': 'deployment_health',
            'summary': evaluation.summary,
            'status': evaluation.status,
            'score': evaluation.score,
            'observed_at': _timestamp(evaluation.evaluated_at),
            'url': reverse('devops:deployment_detail', args=[release.id]),
        })
    return evidence


def _deployment_evidence(release, audits, host_id):
    evidence = [{
        'kind': 'deployment',
        'summary': '发布：%s %s（%s）' % (release.app.name, release.version, release.status),
        'observed_at': _timestamp(release.finished_at or release.created_at),
        'url': reverse('devops:deployment_detail', args=[release.id]),
    }]
    return evidence + _health_evidence(release, host_id) + _audit_evidence(audits)


def _revision_evidence(revision, audits):
    evidence = [{
        'kind': 'prometheus_rule_revision',
        'summary': 'PrometheusRule：%s/%s/%s（%s）' % (
            revision.cluster.name, revision.namespace, revision.name, revision.action,
        ),
        'observed_at': _timestamp(revision.published_at),
        'url': '%s?cluster=%s' % (reverse('devops:prometheus_rules'), revision.cluster_id),
    }]
    return evidence + _audit_evidence(audits)


def _signal_evidence(alerts, commands):
    evidence = []
    for alert in alerts:
        evidence.append({
            'kind': 'open_alert',
            'summary': '未恢复告警：%s%s' % (alert.level, (' / ' + alert.metric) if alert.metric else ''),
            'observed_at': _timestamp(alert.last_seen_at or alert.updated_at or alert.created_at),
            'url': reverse('devops:alert_events'),
        })
    for command in commands:
        # Never serialize command, output, or error; the detail URL applies
        # its own existing permission and host-scope checks.
        evidence.append({
            'kind': 'failed_command',
            'summary': '命令执行失败',
            'observed_at': _timestamp(command.finished_at or command.created_at),
            'url': reverse('devops:command_detail', args=[command.id]),
        })
    return evidence


def _recent_deployments(host_ids, cutoff):
    if not host_ids:
        return []
    return list(
        DeploymentRelease.objects.filter(
            hosts__id__in=host_ids,
            created_at__gte=cutoff,
        ).exclude(
            status__in=(DeploymentRelease.STATUS_PENDING, DeploymentRelease.STATUS_BLOCKED),
        ).select_related('app').prefetch_related('hosts', 'health_evaluations').distinct().order_by('-created_at', '-id')[:40]
    )


def _published_revisions(request, cutoff):
    if not has_role(request, DevOpsRole.ROLE_VIEWER, DevOpsModulePermission.MODULE_CLUSTER):
        return []
    return list(
        PrometheusRuleRevision.objects.filter(
            status=PrometheusRuleRevision.STATUS_PUBLISHED,
            published_at__gte=cutoff,
        ).select_related('cluster').order_by('-published_at', '-id')[:20]
    )


def _audits_for_targets(deployments, revisions, cutoff):
    target_pairs = []
    target_pairs.extend(('DeploymentRelease', str(item.id)) for item in deployments)
    target_pairs.extend(('PrometheusRuleRevision', str(item.id)) for item in revisions)
    if not target_pairs:
        return {}
    query = Q()
    for target_type, target_id in target_pairs:
        query |= Q(target_type=target_type, target_id=target_id)
    grouped = defaultdict(list)
    for audit in AuditLog.objects.filter(query, created_at__gte=cutoff).order_by('-created_at', '-id')[:80]:
        grouped[(audit.target_type, audit.target_id)].append(audit)
    return grouped


def build_change_impacts(request, open_alerts, failed_commands, hosts, now=None):
    """Build a bounded dashboard payload without any write or network path.

    Host-linked deployments are only correlated with hosts visible to the
    current request. Published PrometheusRule revisions are cluster-scoped, so
    they are represented as same-window evidence rather than asserted as a
    host-level dependency.
    """
    now = now or timezone.now()
    cutoff = now - timedelta(hours=DEFAULT_WINDOW_HOURS)
    visible_host_ids = {host.id for host in hosts}
    signals = defaultdict(lambda: {'alerts': [], 'commands': []})
    host_map = {host.id: host for host in hosts}

    for alert in open_alerts:
        if alert.host_id in visible_host_ids:
            signals[alert.host_id]['alerts'].append(alert)
    for command in failed_commands:
        if command.host_id in visible_host_ids:
            signals[command.host_id]['commands'].append(command)

    deployments = _recent_deployments(visible_host_ids, cutoff)
    revisions = _published_revisions(request, cutoff)
    audits = _audits_for_targets(deployments, revisions, cutoff)
    deployments_by_host = defaultdict(list)
    for deployment in deployments:
        for host in deployment.hosts.all():
            if host.id in visible_host_ids:
                deployments_by_host[host.id].append(deployment)

    impacts = []
    for host_id, host_signals in signals.items():
        host_deployments = deployments_by_host.get(host_id, [])
        # A change-impact record requires a time-windowed change. Signals on
        # their own continue to appear in the existing correlation payload.
        if not host_deployments and not revisions:
            continue
        evidence = _signal_evidence(host_signals['alerts'], host_signals['commands'])
        for deployment in host_deployments:
            evidence.extend(_deployment_evidence(
                deployment, audits.get(('DeploymentRelease', str(deployment.id)), []), host_id,
            ))
        for revision in revisions:
            evidence.extend(_revision_evidence(
                revision, audits.get(('PrometheusRuleRevision', str(revision.id)), []),
            ))
        score = min(99, 35 + len(host_signals['alerts']) * 12 + len(host_signals['commands']) * 10
                    + len(host_deployments) * 15 + min(2, len(revisions)) * 8)
        impacts.append({
            'score': score,
            'target': _host_name(host_map[host_id]),
            'observed_at': _timestamp(now),
            'evidence': evidence,
        })
    return sorted(impacts, key=lambda item: (-item['score'], item['target']))[:MAX_IMPACTS]
