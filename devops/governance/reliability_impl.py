"""Safe, read-only health summaries for the platform scheduler and notifications."""

from datetime import timedelta

from django.conf import settings
from django.utils import timezone

from ..models import NotificationChannel, NotificationLog, ScheduledTaskRun


TASK_FRESHNESS_MULTIPLIER = 2
DEFAULT_NOTIFICATION_FRESHNESS_SECONDS = 3600


def _iso(value):
    if not value:
        return None
    return timezone.localtime(value).strftime('%Y-%m-%d %H:%M:%S')


def _task_intervals():
    # Keep this map static and bounded; it mirrors the built-in scheduler only.
    return {
        'monitor': getattr(settings, 'DEVOPS_SCHEDULER_MONITOR_INTERVAL_SECONDS', 60),
        'alertmanager': getattr(settings, 'DEVOPS_SCHEDULER_ALERTMANAGER_INTERVAL_SECONDS', 60),
        'oncall': getattr(settings, 'DEVOPS_SCHEDULER_ONCALL_INTERVAL_SECONDS', 60),
        'service_slo': getattr(settings, 'DEVOPS_SCHEDULER_SERVICE_SLO_INTERVAL_SECONDS', 300),
        'compliance': getattr(settings, 'DEVOPS_SCHEDULER_COMPLIANCE_INTERVAL_SECONDS', 86400),
        'agent_health': getattr(settings, 'DEVOPS_SCHEDULER_AGENT_HEALTH_INTERVAL_SECONDS', 60),
    }


def _task_summary(record, now, interval_seconds):
    if record is None:
        return {
            'task_name': None,
            'status': 'absent',
            'freshness': 'absent',
            'last_success_at': None,
            'last_finished_at': None,
            'next_run_at': None,
            'consecutive_failures': 0,
        }
    status = record.status
    if status == ScheduledTaskRun.STATUS_FAILED:
        freshness = 'failed'
        failures = 1
    elif status == ScheduledTaskRun.STATUS_SUCCESS:
        due_at = record.next_run_at
        stale_at = now - timedelta(seconds=interval_seconds * TASK_FRESHNESS_MULTIPLIER)
        freshness = 'stale' if (due_at and due_at < now) or (
            record.last_finished_at and record.last_finished_at < stale_at
        ) else 'healthy'
        failures = 0
    elif status == ScheduledTaskRun.STATUS_RUNNING:
        freshness = 'stale' if record.lease_expires_at and record.lease_expires_at < now else 'running'
        failures = 0
    else:
        freshness = 'stale' if record.updated_at < now - timedelta(seconds=interval_seconds * TASK_FRESHNESS_MULTIPLIER) else 'pending'
        failures = 0
    return {
        'task_name': record.task_name,
        'status': status,
        'freshness': freshness,
        'last_success_at': _iso(record.last_finished_at) if status == ScheduledTaskRun.STATUS_SUCCESS else None,
        'last_finished_at': _iso(record.last_finished_at),
        'next_run_at': _iso(record.next_run_at),
        'consecutive_failures': failures,
    }


def scheduler_reliability_summary(now=None):
    now = now or timezone.now()
    intervals = _task_intervals()
    records = {item.task_name: item for item in ScheduledTaskRun.objects.all()}
    names = list(intervals)
    names.extend(name for name in records if name not in intervals)
    return [_task_summary(records.get(name), now, int(intervals.get(name, 3600)))
            | {'task_name': name} for name in names]


def _notification_freshness(latest, now):
    if latest is None:
        return 'absent'
    if latest.status == NotificationLog.STATUS_FAILED:
        return 'failed'
    max_age = getattr(settings, 'DEVOPS_NOTIFICATION_FRESHNESS_SECONDS', DEFAULT_NOTIFICATION_FRESHNESS_SECONDS)
    return 'stale' if latest.created_at < now - timedelta(seconds=int(max_age)) else 'healthy'


def notification_reliability_summary(now=None):
    now = now or timezone.now()
    result = {}
    for channel in NotificationChannel.objects.all():
        result.setdefault(channel.channel_type, {
            'channel_type': channel.channel_type,
            'configured_count': 0,
            'total_count': 0,
            'success_count': 0,
            'failed_count': 0,
            'consecutive_failures': 0,
            'last_success_at': None,
            'last_failure_at': None,
            'last_attempt_at': None,
            'status': 'absent',
            'freshness': 'absent',
        })['configured_count'] += 1
    logs = NotificationLog.objects.filter(channel__isnull=False).select_related('channel').order_by('-created_at', '-id')
    for log in logs:
        channel_type = log.channel.channel_type
        item = result.setdefault(channel_type, {
            'channel_type': channel_type, 'configured_count': 0, 'total_count': 0,
            'success_count': 0, 'failed_count': 0, 'consecutive_failures': 0,
            'last_success_at': None, 'last_failure_at': None, 'last_attempt_at': None,
            'status': 'absent', 'freshness': 'absent',
        })
        item['total_count'] += 1
        if item['last_attempt_at'] is None:
            item['last_attempt_at'] = _iso(log.created_at)
            item['status'] = log.status
            item['freshness'] = _notification_freshness(log, now)
        if log.status == NotificationLog.STATUS_SUCCESS:
            item['success_count'] += 1
            item['last_success_at'] = item['last_success_at'] or _iso(log.created_at)
        else:
            item['failed_count'] += 1
            item['last_failure_at'] = item['last_failure_at'] or _iso(log.created_at)
    for item in result.values():
        failures = 0
        for log in logs.filter(channel__channel_type=item['channel_type']):
            if log.status != NotificationLog.STATUS_FAILED:
                break
            failures += 1
        item['consecutive_failures'] = failures
    return sorted(result.values(), key=lambda item: item['channel_type'])


def platform_reliability_summary(now=None):
    return {
        'scheduler': scheduler_reliability_summary(now=now),
        'notifications': notification_reliability_summary(now=now),
    }
