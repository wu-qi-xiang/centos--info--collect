import json
from datetime import timedelta

from django.db import models
from django.http import JsonResponse
from django.shortcuts import get_object_or_404
from django.utils import timezone
from django.views.decorators.http import require_http_methods

from .models import (
    AlertEvent,
    ApprovalRequest,
    BatchTask,
    CommandExecution,
    DeploymentRelease,
    DevOpsModulePermission,
    DevOpsRole,
    FileDistribution,
    HostGroup,
    MetricSample,
    NotificationChannel,
    NotificationLog,
)
from .services import (
    COMMAND_ALLOWED,
    audit,
    can_access_host,
    can_access_hosts,
    command_denied_message,
    create_command_approval,
    enqueue_background_job,
    execute_batch_task,
    execute_command_record,
    evaluate_command_policy,
    has_role,
    latest_metric_map,
    user_role,
    visible_hosts_for_request,
)


MODULE_COMMAND = DevOpsModulePermission.MODULE_COMMAND
MODULE_TASK = DevOpsModulePermission.MODULE_TASK
MODULE_APPROVAL = DevOpsModulePermission.MODULE_APPROVAL
MODULE_METRIC = DevOpsModulePermission.MODULE_METRIC
MODULE_FILE = DevOpsModulePermission.MODULE_FILE
MODULE_DEPLOYMENT = DevOpsModulePermission.MODULE_DEPLOYMENT
MODULE_SECURITY = DevOpsModulePermission.MODULE_SECURITY
NOTIFICATION_RESPONSE_PREVIEW_LENGTH = 300


def api_error(message, status=400, code='bad_request'):
    return JsonResponse({'ok': False, 'code': code, 'message': message}, status=status)


def api_login_required(view_func):
    def wrapper(request, *args, **kwargs):
        if not request.session.get('is_login'):
            return api_error('未登录', status=401, code='unauthorized')
        return view_func(request, *args, **kwargs)
    return wrapper


def request_json(request):
    if not request.body:
        return {}
    try:
        return json.loads(request.body.decode('utf-8'))
    except (TypeError, ValueError):
        return None


def iso(dt):
    if not dt:
        return None
    return timezone.localtime(dt).strftime('%Y-%m-%d %H:%M:%S')


def label(obj, field):
    getter = getattr(obj, 'get_%s_display' % field, None)
    return getter() if getter else getattr(obj, field)


def metric_percent(value):
    try:
        number = float(value)
    except (TypeError, ValueError):
        return 0
    if number <= 1:
        number *= 100
    return number


def truncate_text(value, max_length=NOTIFICATION_RESPONSE_PREVIEW_LENGTH):
    value = value or ''
    if len(value) <= max_length:
        return value
    return '%s...' % value[:max_length]


def serialize_host(host):
    return {
        'id': host.id,
        'name': host.linux_name,
        'ip': host.linux_ip,
        'hostname': host.linux_hostname,
        'port': host.linux_port,
        'user': host.linux_user,
        'auth_type': getattr(host, 'linux_auth_type', 'password'),
        'app': host.linux_app,
    }


def serialize_command(record):
    return {
        'id': record.id,
        'host': serialize_host(record.host) if record.host else None,
        'command': record.command,
        'status': record.status,
        'status_label': label(record, 'status'),
        'output': record.output,
        'error': record.error,
        'duration_ms': record.duration_ms,
        'created_by': record.created_by,
        'created_at': iso(record.created_at),
        'finished_at': iso(record.finished_at),
    }


def visible_host_count(hosts, visible_hosts=None):
    if visible_hosts is None:
        return hosts.count()
    return hosts.filter(id__in=visible_hosts.values_list('id', flat=True)).count()


def scoped_alert_queryset(visible_hosts):
    return AlertEvent.objects.select_related('host').filter(
        models.Q(host__in=visible_hosts) | models.Q(host__isnull=True)
    )


def scoped_approval_queryset(visible_hosts):
    return ApprovalRequest.objects.select_related('host', 'deployment_release').filter(
        models.Q(host__in=visible_hosts) |
        models.Q(host__isnull=True, deployment_release__hosts__in=visible_hosts) |
        models.Q(host__isnull=True, deployment_release__isnull=True)
    ).distinct()


def serialize_task(task, visible_hosts=None):
    return {
        'id': task.id,
        'name': task.name,
        'command': task.command,
        'status': task.status,
        'status_label': label(task, 'status'),
        'summary': task.summary,
        'created_by': task.created_by,
        'created_at': iso(task.created_at),
        'finished_at': iso(task.finished_at),
        'host_count': visible_host_count(task.hosts, visible_hosts),
    }


def serialize_alert(alert):
    return {
        'id': alert.id,
        'host': serialize_host(alert.host) if alert.host else None,
        'level': alert.level,
        'level_label': label(alert, 'level'),
        'metric': alert.metric,
        'message': alert.message,
        'status': alert.status,
        'status_label': label(alert, 'status'),
        'repeat_count': alert.repeat_count,
        'handler': alert.handler,
        'remark': alert.remark,
        'created_at': iso(alert.created_at),
        'updated_at': iso(alert.updated_at),
    }


def serialize_approval(approval):
    return {
        'id': approval.id,
        'request_type': approval.request_type,
        'request_type_label': label(approval, 'request_type'),
        'status': approval.status,
        'status_label': label(approval, 'status'),
        'title': approval.title,
        'reason': approval.reason,
        'requester': approval.requester,
        'approver': approval.approver,
        'comment': approval.comment,
        'host': serialize_host(approval.host) if approval.host else None,
        'command': approval.command,
        'deployment_release_id': approval.deployment_release_id,
        'command_execution_id': approval.command_execution_id,
        'created_at': iso(approval.created_at),
        'decided_at': iso(approval.decided_at),
        'executed_at': iso(approval.executed_at),
    }


def serialize_release(release, visible_hosts=None):
    return {
        'id': release.id,
        'app': {'id': release.app_id, 'name': release.app.name if release.app_id else ''},
        'version': release.version,
        'description': release.description,
        'status': release.status,
        'status_label': label(release, 'status'),
        'summary': release.summary,
        'created_by': release.created_by,
        'created_at': iso(release.created_at),
        'finished_at': iso(release.finished_at),
        'host_count': visible_host_count(release.hosts, visible_hosts),
    }


def serialize_notification_log(log):
    return {
        'id': log.id,
        'channel': log.channel.name if log.channel else None,
        'channel_id': log.channel_id,
        'event_type': log.event_type,
        'event_type_label': label(log, 'event_type'),
        'title': log.title,
        'status': log.status,
        'status_label': label(log, 'status'),
        'response': truncate_text(log.response),
        'created_at': iso(log.created_at),
    }


def limit_queryset(request, queryset, default=50, maximum=200):
    try:
        limit = int(request.GET.get('limit', default))
    except (TypeError, ValueError):
        limit = default
    limit = max(1, min(limit, maximum))
    return queryset[:limit]


@api_login_required
@require_http_methods(['GET'])
def bootstrap(request):
    hosts = visible_hosts_for_request(request)
    scoped_alerts = scoped_alert_queryset(hosts)
    scoped_approvals = scoped_approval_queryset(hosts)
    return JsonResponse({
        'ok': True,
        'user': {
            'id': request.session.get('user_id'),
            'name': request.session.get('user_name'),
            'role': user_role(request),
        },
        'permissions': {
            'command': has_role(request, DevOpsRole.ROLE_OPERATOR, MODULE_COMMAND),
            'task': has_role(request, DevOpsRole.ROLE_OPERATOR, MODULE_TASK),
            'approval': has_role(request, DevOpsRole.ROLE_VIEWER, MODULE_APPROVAL),
            'approval_admin': has_role(request, DevOpsRole.ROLE_ADMIN, MODULE_APPROVAL),
            'metric': has_role(request, DevOpsRole.ROLE_VIEWER, MODULE_METRIC),
            'deployment': has_role(request, DevOpsRole.ROLE_VIEWER, MODULE_DEPLOYMENT),
            'file': has_role(request, DevOpsRole.ROLE_VIEWER, MODULE_FILE),
            'notification': has_role(request, DevOpsRole.ROLE_VIEWER, MODULE_SECURITY),
        },
        'counts': {
            'hosts': hosts.count(),
            'groups': HostGroup.objects.filter(hosts__in=hosts).distinct().count(),
            'open_alerts': scoped_alerts.filter(status=AlertEvent.STATUS_OPEN).count(),
            'pending_approvals': scoped_approvals.filter(status=ApprovalRequest.STATUS_PENDING).count(),
        },
    })


@api_login_required
@require_http_methods(['GET'])
def hosts(request):
    data = [serialize_host(host) for host in visible_hosts_for_request(request)]
    return JsonResponse({'ok': True, 'results': data})


@api_login_required
@require_http_methods(['GET'])
def dashboard(request):
    visible_hosts = visible_hosts_for_request(request)
    scoped_alerts = scoped_alert_queryset(visible_hosts)
    latest_map = latest_metric_map(list(visible_hosts))
    host_metrics = []
    for host in visible_hosts:
        host_metrics.append({
            'host': serialize_host(host),
            'cpu': metric_percent(latest_map[(host.id, MetricSample.METRIC_CPU)].value) if (host.id, MetricSample.METRIC_CPU) in latest_map else None,
            'memory': metric_percent(latest_map[(host.id, MetricSample.METRIC_MEMORY)].value) if (host.id, MetricSample.METRIC_MEMORY) in latest_map else None,
            'disk': metric_percent(latest_map[(host.id, MetricSample.METRIC_DISK)].value) if (host.id, MetricSample.METRIC_DISK) in latest_map else None,
        })
    return JsonResponse({
        'ok': True,
        'counts': {
            'hosts': visible_hosts.count(),
            'groups': HostGroup.objects.filter(hosts__in=visible_hosts).distinct().count(),
            'open_alerts': scoped_alerts.filter(status=AlertEvent.STATUS_OPEN).count(),
            'tasks': BatchTask.objects.filter(hosts__in=visible_hosts).distinct().count(),
        },
        'recent_commands': [serialize_command(item) for item in CommandExecution.objects.filter(host__in=visible_hosts)[:5]],
        'recent_alerts': [serialize_alert(item) for item in scoped_alerts[:5]],
        'host_metrics': host_metrics,
    })


@api_login_required
@require_http_methods(['GET', 'POST'])
def commands(request):
    visible_hosts = visible_hosts_for_request(request)
    if request.method == 'GET':
        queryset = CommandExecution.objects.select_related('host').filter(host__in=visible_hosts)
        return JsonResponse({'ok': True, 'results': [serialize_command(item) for item in limit_queryset(request, queryset)]})

    if not has_role(request, DevOpsRole.ROLE_OPERATOR, MODULE_COMMAND):
        return api_error('没有命令执行权限', status=403, code='forbidden')
    payload = request_json(request)
    if payload is None:
        return api_error('JSON 格式错误')
    host = get_object_or_404(visible_hosts, id=payload.get('host_id'))
    command = (payload.get('command') or '').strip()
    if not command:
        return api_error('命令不能为空')
    decision, policy = evaluate_command_policy(command, user_role(request))
    if decision != COMMAND_ALLOWED:
        approval = create_command_approval(host, command, request.session.get('user_name'), command_denied_message(decision, policy))
        audit(request, 'API高危命令转审批', 'ApprovalRequest', approval.id, approval.title)
        return JsonResponse({'ok': True, 'requires_approval': True, 'approval': serialize_approval(approval)}, status=202)
    record = CommandExecution.objects.create(host=host, command=command, created_by=request.session.get('user_name'))
    enqueue_background_job(execute_command_record, record, user_role(request))
    audit(request, 'API提交命令执行', 'CommandExecution', record.id, record.command)
    return JsonResponse({'ok': True, 'record': serialize_command(record)}, status=201)


@api_login_required
@require_http_methods(['GET'])
def command_detail(request, id):
    record = get_object_or_404(CommandExecution.objects.select_related('host'), id=id)
    if not can_access_host(request, record.host):
        return api_error('目标主机不在当前用户授权范围内', status=403, code='host_forbidden')
    return JsonResponse({'ok': True, 'record': serialize_command(record)})


@api_login_required
@require_http_methods(['GET', 'POST'])
def tasks(request):
    visible_hosts = visible_hosts_for_request(request)
    if request.method == 'GET':
        queryset = BatchTask.objects.filter(hosts__in=visible_hosts).distinct()
        return JsonResponse({'ok': True, 'results': [serialize_task(item, visible_hosts) for item in limit_queryset(request, queryset)]})

    if not has_role(request, DevOpsRole.ROLE_OPERATOR, MODULE_TASK):
        return api_error('没有批量任务权限', status=403, code='forbidden')
    payload = request_json(request)
    if payload is None:
        return api_error('JSON 格式错误')
    host_ids = payload.get('host_ids') or []
    hosts_qs = visible_hosts.filter(id__in=host_ids)
    hosts_list = list(hosts_qs)
    if not host_ids or len(hosts_list) != len(set(host_ids)):
        return api_error('目标主机不在当前用户授权范围内', status=403, code='host_forbidden')
    command = (payload.get('command') or '').strip()
    name = (payload.get('name') or '').strip()
    if not name or not command:
        return api_error('任务名称和命令不能为空')
    task = BatchTask.objects.create(name=name, command=command, created_by=request.session.get('user_name'), status=BatchTask.STATUS_PENDING)
    task.hosts.set(hosts_list)
    enqueue_background_job(execute_batch_task, task, user_role(request))
    audit(request, 'API提交批量任务', 'BatchTask', task.id, task.command)
    return JsonResponse({'ok': True, 'task': serialize_task(task)}, status=201)


@api_login_required
@require_http_methods(['GET'])
def metrics(request):
    if not has_role(request, DevOpsRole.ROLE_VIEWER, MODULE_METRIC):
        return api_error('没有监控历史权限', status=403, code='forbidden')
    visible_hosts = list(visible_hosts_for_request(request))
    selected_host_id = request.GET.get('host') or (str(visible_hosts[0].id) if visible_hosts else '')
    range_key = request.GET.get('range') or '24h'
    range_map = {
        '6h': timedelta(hours=6),
        '24h': timedelta(hours=24),
        '7d': timedelta(days=7),
        '30d': timedelta(days=30),
    }
    if range_key not in range_map:
        range_key = '24h'
    selected_host = None
    for host in visible_hosts:
        if str(host.id) == str(selected_host_id):
            selected_host = host
            break
    series = {
        MetricSample.METRIC_CPU: [],
        MetricSample.METRIC_MEMORY: [],
        MetricSample.METRIC_DISK: [],
    }
    labels = []
    if selected_host:
        since = timezone.now() - range_map[range_key]
        points = {}
        samples = MetricSample.objects.filter(host=selected_host, collected_at__gte=since).order_by('collected_at', 'metric')
        for sample in samples:
            sample_label = timezone.localtime(sample.collected_at).strftime('%m-%d %H:%M')
            points.setdefault(sample_label, {})[sample.metric] = metric_percent(sample.value)
        labels = list(points.keys())
        for sample_label in labels:
            for metric_name in series:
                series[metric_name].append(points[sample_label].get(metric_name))
    return JsonResponse({
        'ok': True,
        'host': serialize_host(selected_host) if selected_host else None,
        'range': range_key,
        'labels': labels,
        'series': series,
    })


@api_login_required
@require_http_methods(['GET'])
def alerts(request):
    queryset = scoped_alert_queryset(visible_hosts_for_request(request))
    return JsonResponse({'ok': True, 'results': [serialize_alert(item) for item in limit_queryset(request, queryset)]})


@api_login_required
@require_http_methods(['GET'])
def approvals(request):
    visible_hosts = visible_hosts_for_request(request)
    queryset = scoped_approval_queryset(visible_hosts)
    return JsonResponse({'ok': True, 'results': [serialize_approval(item) for item in limit_queryset(request, queryset, default=100)]})


@api_login_required
@require_http_methods(['GET'])
def deployments(request):
    visible_hosts = visible_hosts_for_request(request)
    queryset = DeploymentRelease.objects.select_related('app').filter(hosts__in=visible_hosts).distinct()
    return JsonResponse({'ok': True, 'results': [serialize_release(item, visible_hosts) for item in limit_queryset(request, queryset)]})


@api_login_required
@require_http_methods(['GET'])
def files(request):
    visible_hosts = visible_hosts_for_request(request)
    queryset = FileDistribution.objects.filter(hosts__in=visible_hosts).distinct()
    return JsonResponse({'ok': True, 'results': [{
        'id': item.id,
        'name': item.name,
        'remote_path': item.remote_path,
        'status': item.status,
        'status_label': label(item, 'status'),
        'summary': item.summary,
        'created_by': item.created_by,
        'created_at': iso(item.created_at),
        'finished_at': iso(item.finished_at),
        'host_count': visible_host_count(item.hosts, visible_hosts),
    } for item in limit_queryset(request, queryset)]})


@api_login_required
@require_http_methods(['GET'])
def notifications(request):
    channels = NotificationChannel.objects.all()
    logs = NotificationLog.objects.select_related('channel')
    channel_id = request.GET.get('channel')
    event_type = request.GET.get('event_type')
    status = request.GET.get('status')

    if channel_id:
        try:
            logs = logs.filter(channel_id=int(channel_id))
        except (TypeError, ValueError):
            return api_error('通知渠道参数无效', status=400, code='validation_error')
    if event_type:
        valid_events = [choice[0] for choice in NotificationLog.EVENT_CHOICES]
        if event_type not in valid_events:
            return api_error('通知事件类型无效', status=400, code='validation_error')
        logs = logs.filter(event_type=event_type)
    if status:
        valid_statuses = [choice[0] for choice in NotificationLog.STATUS_CHOICES]
        if status not in valid_statuses:
            return api_error('通知状态无效', status=400, code='validation_error')
        logs = logs.filter(status=status)

    return JsonResponse({
        'ok': True,
        'channels': [{
            'id': channel.id,
            'name': channel.name,
            'channel_type': channel.channel_type,
            'channel_type_label': label(channel, 'channel_type'),
            'notify_alert': channel.notify_alert,
            'notify_approval': channel.notify_approval,
            'notify_deployment': channel.notify_deployment,
            'enabled': channel.enabled,
        } for channel in channels],
        'logs': [serialize_notification_log(log) for log in limit_queryset(request, logs)],
    })
