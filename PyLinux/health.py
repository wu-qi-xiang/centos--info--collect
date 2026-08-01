from django.db import DatabaseError, connection
from django.db.models import Count
from django.http import HttpResponse, JsonResponse
from django.views.decorators.http import require_GET


def database_is_ready():
    try:
        cursor = connection.cursor()
        cursor.execute('SELECT 1')
        cursor.fetchone()
        return True
    except DatabaseError:
        return False


@require_GET
def liveness(request):
    return JsonResponse({'ok': True, 'status': 'alive'})


@require_GET
def readiness(request):
    if not database_is_ready():
        return JsonResponse({'ok': False, 'status': 'not_ready'}, status=503)
    return JsonResponse({'ok': True, 'status': 'ready'})


def runtime_counts():
    from RemoteLinux.models import NewLinux
    from devops.models import (
        AlertEvent,
        ApprovalRequest,
        BatchTask,
        CommandExecution,
        DeploymentRelease,
        FileDistribution,
    )

    active_alert_statuses = (AlertEvent.STATUS_OPEN, AlertEvent.STATUS_PROCESSING)
    queued_statuses = (CommandExecution.STATUS_PENDING, CommandExecution.STATUS_RUNNING)
    return {
        'hosts': NewLinux.objects.count(),
        'active_alerts': AlertEvent.objects.filter(status__in=active_alert_statuses).count(),
        'pending_approvals': ApprovalRequest.objects.filter(
            status=ApprovalRequest.STATUS_PENDING,
        ).count(),
        'queued_work': (
            CommandExecution.objects.filter(status__in=queued_statuses).count()
            + BatchTask.objects.filter(status__in=queued_statuses).count()
            + FileDistribution.objects.filter(status__in=queued_statuses).count()
            + DeploymentRelease.objects.filter(status__in=queued_statuses).count()
        ),
    }


def _status_counts(model, statuses):
    counts = dict.fromkeys(statuses, 0)
    for row in model.objects.values('status').annotate(total=Count('id')):
        status = row['status']
        if status in counts:
            counts[status] = int(row['total'])
    return counts


def prometheus_metric_values():
    """Return status-only aggregates suitable for authenticated Prometheus scrapes."""
    from devops import models as devops_models

    background_job = devops_models.BackgroundJob
    integration_health = devops_models.IntegrationHealthEvent
    scheduled_task_run = getattr(devops_models, 'ScheduledTaskRun', None)
    values = {
        'background_jobs': _status_counts(background_job, (
            background_job.STATUS_PENDING,
            background_job.STATUS_RUNNING,
            background_job.STATUS_SUCCESS,
            background_job.STATUS_FAILED,
        )),
        'integration_health': _status_counts(integration_health, (
            integration_health.STATUS_SUCCESS,
            integration_health.STATUS_FAILED,
        )),
        'scheduled_task_runs': None,
    }
    if scheduled_task_run is not None:
        statuses = tuple(
            status for status, _label in getattr(scheduled_task_run, 'STATUS_CHOICES', ())
        )
        if statuses:
            values['scheduled_task_runs'] = _status_counts(scheduled_task_run, statuses)
    return values


def prometheus_metrics_text(values):
    lines = [
        '# HELP pylinux_background_jobs Number of background jobs by status.',
        '# TYPE pylinux_background_jobs gauge',
    ]
    for status, total in values['background_jobs'].items():
        lines.append('pylinux_background_jobs{status="%s"} %d' % (status, total))
    lines.extend((
        '# HELP pylinux_integration_health_events Number of integration health events by status.',
        '# TYPE pylinux_integration_health_events gauge',
    ))
    for status, total in values['integration_health'].items():
        lines.append('pylinux_integration_health_events{status="%s"} %d' % (status, total))
    if values['scheduled_task_runs'] is not None:
        lines.extend((
            '# HELP pylinux_scheduled_task_runs Number of scheduled task runs by status.',
            '# TYPE pylinux_scheduled_task_runs gauge',
        ))
        for status, total in values['scheduled_task_runs'].items():
            lines.append('pylinux_scheduled_task_runs{status="%s"} %d' % (status, total))
    return '\n'.join(lines) + '\n'


@require_GET
def runtime_status(request):
    if not request.session.get('is_login') or not request.session.get('user_id'):
        return JsonResponse({'ok': False, 'code': 'unauthorized'}, status=401)

    from devops.services import has_explicit_admin_role, summarize_background_jobs

    try:
        if not has_explicit_admin_role(request):
            return JsonResponse({'ok': False, 'code': 'forbidden'}, status=403)
        if not database_is_ready():
            return JsonResponse({'ok': False, 'status': 'not_ready'}, status=503)
        counts = runtime_counts()
        worker = summarize_background_jobs()
    except DatabaseError:
        return JsonResponse({'ok': False, 'status': 'not_ready'}, status=503)

    return JsonResponse({
        'ok': True,
        'status': 'ready',
        'database': 'ready',
        'counts': counts,
        'worker': worker,
    })


@require_GET
def metrics(request):
    if not request.session.get('is_login') or not request.session.get('user_id'):
        return JsonResponse({'ok': False, 'code': 'unauthorized'}, status=401)

    from devops.services import has_explicit_admin_role

    try:
        if not has_explicit_admin_role(request):
            return JsonResponse({'ok': False, 'code': 'forbidden'}, status=403)
        if not database_is_ready():
            return JsonResponse({'ok': False, 'status': 'not_ready'}, status=503)
        values = prometheus_metric_values()
    except DatabaseError:
        return JsonResponse({'ok': False, 'status': 'not_ready'}, status=503)

    return HttpResponse(
        prometheus_metrics_text(values),
        content_type='text/plain; version=0.0.4; charset=utf-8',
    )
