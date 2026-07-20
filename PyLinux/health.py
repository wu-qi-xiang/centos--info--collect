from django.db import DatabaseError, connection
from django.http import JsonResponse
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
