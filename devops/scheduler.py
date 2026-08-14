from datetime import timedelta

from django.conf import settings
from django.db import IntegrityError
from django.db.models import Q
from django.utils import timezone

from .models import ScheduledTaskRun


class ScheduledTask(object):
    def __init__(self, name, interval_seconds, callback):
        self.name = name
        self.interval_seconds = interval_seconds
        self.callback = callback


SAFE_RESULT_KEYS = (
    'alertmanagers', 'attempted', 'cancelled', 'checked', 'cleaned', 'errors', 'escalated',
    'evaluated', 'exhausted', 'firing', 'processed', 'pushed', 'received',
    'recovered', 'revoked', 'scanned', 'skipped', 'stale', 'offline', 'unavailable',
    'success', 'failed',
)


def scheduled_task_registry():
    """Return the fixed internal tasks; callers cannot register arbitrary work."""
    from monitor.crontab import (
        evaluate_service_slos_periodically,
        monitor_send_email,
        poll_alertmanager_notifications,
        process_due_oncall_escalations_periodically,
        scan_compliance_baselines_daily,
    )
    from .services import probe_configured_integrations, process_integration_health_escalations
    from RemoteLinux.agent_health import evaluate_host_agent_health
    from aiops.operator_mode import run_scheduled_operator_scan
    return (
        ScheduledTask('monitor', settings.DEVOPS_SCHEDULER_MONITOR_INTERVAL_SECONDS, monitor_send_email),
        ScheduledTask('alertmanager', settings.DEVOPS_SCHEDULER_ALERTMANAGER_INTERVAL_SECONDS, poll_alertmanager_notifications),
        ScheduledTask('oncall', settings.DEVOPS_SCHEDULER_ONCALL_INTERVAL_SECONDS, process_due_oncall_escalations_periodically),
        ScheduledTask('service_slo', settings.DEVOPS_SCHEDULER_SERVICE_SLO_INTERVAL_SECONDS, evaluate_service_slos_periodically),
        ScheduledTask('compliance', settings.DEVOPS_SCHEDULER_COMPLIANCE_INTERVAL_SECONDS, scan_compliance_baselines_daily),
        ScheduledTask('agent_health', settings.DEVOPS_SCHEDULER_AGENT_HEALTH_INTERVAL_SECONDS, evaluate_host_agent_health),
        ScheduledTask('integration_health', settings.DEVOPS_SCHEDULER_INTEGRATION_HEALTH_INTERVAL_SECONDS, probe_configured_integrations),
        ScheduledTask('integration_health_escalation', settings.DEVOPS_SCHEDULER_INTEGRATION_HEALTH_INTERVAL_SECONDS, process_integration_health_escalations),
        ScheduledTask('operator_scan', settings.DEVOPS_SCHEDULER_OPERATOR_SCAN_INTERVAL_SECONDS, run_scheduled_operator_scan),
    )


def _safe_summary(result):
    if not isinstance(result, dict):
        return 'completed'
    values = []
    for key in SAFE_RESULT_KEYS:
        value = result.get(key)
        if isinstance(value, int) and not isinstance(value, bool):
            values.append('%s=%s' % (key, value))
    return 'completed' if not values else 'completed: %s' % ', '.join(values[:6])


def _state_for_task(task_name):
    try:
        state, _created = ScheduledTaskRun.objects.get_or_create(task_name=task_name)
    except IntegrityError:
        state = ScheduledTaskRun.objects.get(task_name=task_name)
    return state


def _claim_due_task(task, now):
    """Claim only a due or abandoned task using a database conditional update."""
    _state_for_task(task.name)
    lease_expires_at = now + timedelta(seconds=settings.DEVOPS_SCHEDULER_LEASE_SECONDS)
    due = Q(next_run_at__isnull=True) | Q(next_run_at__lte=now)
    available = Q(lease_expires_at__isnull=True) | Q(lease_expires_at__lte=now)
    abandoned = Q(status=ScheduledTaskRun.STATUS_RUNNING, lease_expires_at__lte=now)
    updated = ScheduledTaskRun.objects.filter(task_name=task.name).filter(
        (due & available) | abandoned
    ).update(
        status=ScheduledTaskRun.STATUS_RUNNING,
        last_started_at=now,
        lease_expires_at=lease_expires_at,
        updated_at=now,
    )
    return lease_expires_at if updated else None


def _finish_task(task, lease_expires_at, now, status, summary):
    ScheduledTaskRun.objects.filter(
        task_name=task.name,
        status=ScheduledTaskRun.STATUS_RUNNING,
        lease_expires_at=lease_expires_at,
    ).update(
        status=status,
        last_summary=summary[:200],
        last_finished_at=now,
        next_run_at=now + timedelta(seconds=task.interval_seconds),
        lease_expires_at=None,
        updated_at=now,
    )


def run_due_scheduled_tasks(task_specs=None):
    """Run due built-in tasks once and return only bounded status counts/names."""
    task_specs = scheduled_task_registry() if task_specs is None else task_specs
    result = {'started': [], 'leased': [], 'failed': []}
    for task in task_specs:
        now = timezone.now()
        lease_expires_at = _claim_due_task(task, now)
        if not lease_expires_at:
            result['leased'].append(task.name)
            continue
        result['started'].append(task.name)
        try:
            callback_result = task.callback()
        except Exception as exc:
            _finish_task(task, lease_expires_at, timezone.now(), ScheduledTaskRun.STATUS_FAILED,
                         'failed: %s' % exc.__class__.__name__)
            result['failed'].append(task.name)
            continue
        _finish_task(task, lease_expires_at, timezone.now(), ScheduledTaskRun.STATUS_SUCCESS,
                     _safe_summary(callback_result))
    return result
