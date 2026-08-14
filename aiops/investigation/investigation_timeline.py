"""Safe, deterministic evidence timelines for the AIOps workbench."""

from collections import defaultdict

from django.utils import timezone

from devops.models import AlertEvent, AlertQualityFeedback, CommandExecution, DeploymentHealthEvaluation, Incident


MAX_ENTRIES_PER_HOST = 16


def _timestamp(value):
    return timezone.localtime(value).strftime('%Y-%m-%d %H:%M:%S') if value else None


def build_investigation_timelines(hosts, now=None):
    host_map = {host.id: host for host in hosts}
    if not host_map:
        return []
    entries = defaultdict(list)
    host_ids = list(host_map)
    for incident in Incident.objects.filter(host_id__in=host_ids).order_by('-updated_at', '-id')[:80]:
        entries[incident.host_id].append({'kind': 'incident', 'summary': '事件状态：%s' % incident.status, 'observed_at': _timestamp(incident.updated_at)})
    for alert in AlertEvent.objects.filter(host_id__in=host_ids).order_by('-updated_at', '-id')[:120]:
        entries[alert.host_id].append({'kind': 'alert', 'summary': '告警：%s / %s' % (alert.level, alert.metric or '-'), 'observed_at': _timestamp(alert.updated_at)})
    for feedback in AlertQualityFeedback.objects.filter(alert__host_id__in=host_ids).select_related('alert').order_by('-created_at', '-id')[:120]:
        entries[feedback.alert.host_id].append({'kind': 'alert_quality_feedback', 'summary': '质量反馈：%s' % feedback.classification, 'observed_at': _timestamp(feedback.created_at)})
    for command in CommandExecution.objects.filter(host_id__in=host_ids, status=CommandExecution.STATUS_FAILED).order_by('-finished_at', '-id')[:80]:
        entries[command.host_id].append({'kind': 'failed_command', 'summary': '自动化执行失败', 'observed_at': _timestamp(command.finished_at or command.created_at)})
    for evaluation in DeploymentHealthEvaluation.objects.order_by('-evaluated_at', '-id')[:80]:
        batch = evaluation.batch_identity or ''
        ids = batch.split('=', 1)[1].split(',') if batch.startswith('host_ids=') else []
        for host_id in host_ids:
            if str(host_id) in ids:
                entries[host_id].append({'kind': 'deployment_health', 'summary': '发布健康：%s / %s 分' % (evaluation.status, evaluation.score), 'observed_at': _timestamp(evaluation.evaluated_at)})
    timelines = []
    for host_id, host in host_map.items():
        rows = sorted(entries[host_id], key=lambda item: item['observed_at'] or '', reverse=True)[:MAX_ENTRIES_PER_HOST]
        if rows:
            timelines.append({'host': host.linux_name or host.linux_ip or host.linux_hostname or '未命名主机', 'entries': rows})
    return timelines
