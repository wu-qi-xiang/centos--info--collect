import json
import re
import math
from datetime import timedelta

from django.conf import settings
from django.db import models
from django.http import JsonResponse
from django.shortcuts import get_object_or_404
from django.utils import timezone
from django.views.decorators.http import require_http_methods

from RemoteLinux.models import NewLinux
from .forms import ServiceSloForm, RunbookTemplateForm
from .models import (
    AlertEvent,
    ApprovalRequest,
    AuditLog,
    BatchTask,
    CommandExecution,
    DeploymentRelease,
    DevOpsModulePermission,
    DevOpsRole,
    FileDistribution,
    HostGroup,
    Incident,
    IntegrationHealthEvent,
    MetricSample,
    MaintenanceWindow,
    K8sCluster,
    NotificationChannel,
    NotificationLog,
    ServiceCatalog,
    ServiceSlo,
    RunbookTemplate,
)
from .services import (
    COMMAND_ALLOWED,
    audit,
    can_access_host,
    can_access_hosts,
    can_decide_deployment_approval,
    command_denied_message,
    create_command_approval,
    enqueue_background_job,
    execute_approval_request,
    execute_batch_task,
    execute_command_record,
    can_access_incident,
    create_incident,
    add_incident_timeline_note,
    record_incident_postmortem,
    update_incident_status,
    evaluate_command_policy,
    forecast_host_capacity,
    has_role,
    latest_metric_map,
    notify_approval,
    user_role,
    visible_hosts_for_request,
    summarize_integration_health,
    evaluate_service_slo,
    initiate_runbook,
    list_prometheus_rules,
    get_prometheus_rule,
    replace_prometheus_rule,
    delete_prometheus_rule,
    normalize_prometheus_rule_resource_version,
    RunbookInitiationError,
)


MODULE_COMMAND = DevOpsModulePermission.MODULE_COMMAND
MODULE_TASK = DevOpsModulePermission.MODULE_TASK
MODULE_APPROVAL = DevOpsModulePermission.MODULE_APPROVAL
MODULE_METRIC = DevOpsModulePermission.MODULE_METRIC
MODULE_FILE = DevOpsModulePermission.MODULE_FILE
MODULE_DEPLOYMENT = DevOpsModulePermission.MODULE_DEPLOYMENT
MODULE_SECURITY = DevOpsModulePermission.MODULE_SECURITY
MODULE_AUDIT = DevOpsModulePermission.MODULE_AUDIT
MODULE_SERVICE = DevOpsModulePermission.MODULE_SERVICE
MODULE_ALERT = DevOpsModulePermission.MODULE_ALERT
MODULE_CLUSTER = DevOpsModulePermission.MODULE_CLUSTER
NOTIFICATION_RESPONSE_PREVIEW_LENGTH = 300
SENSITIVE_URL_RE = re.compile(r'https?://[^\s,;]+', re.IGNORECASE)
SENSITIVE_ENC_RE = re.compile(r'\benc:[^\s,;]+', re.IGNORECASE)
SENSITIVE_KV_RE = re.compile(
    r'(?i)(\b(?:secret|password|passwd|token|api[_-]?key|private[_-]?key|key)\b\s*[:=]\s*)([^\s,;&]+)'
)


def api_error(message, status=400, code='bad_request'):
    return JsonResponse({'ok': False, 'code': code, 'message': message}, status=status)


def invalid_json_error():
    return api_error('JSON 格式错误', status=400, code='invalid_json')


def api_login_required(view_func):
    def wrapper(request, *args, **kwargs):
        if not request.session.get('is_login') or not request.session.get('user_id'):
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
    result = {
        'id': record.id,
        'host': serialize_host(record.host) if record.host else None,
        'status': record.status,
        'status_label': label(record, 'status'),
        'duration_ms': record.duration_ms,
        'created_by': record.created_by,
        'created_at': iso(record.created_at),
        'finished_at': iso(record.finished_at),
    }
    if not record.runbook_template_id:
        result['command'] = record.command
        result['output'] = record.output
        result['error'] = record.error
    return result


def visible_host_count(hosts, visible_hosts=None):
    if visible_hosts is None:
        return hosts.count()
    return hosts.filter(id__in=visible_hosts.values_list('id', flat=True)).count()


def scoped_alert_queryset(visible_hosts):
    return AlertEvent.objects.select_related('host').filter(
        models.Q(host__in=visible_hosts) | models.Q(host__isnull=True)
    )


def scoped_approval_queryset(visible_hosts):
    return ApprovalRequest.objects.select_related('host', 'deployment_release', 'command_execution').filter(
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


def serialize_incident_reference(incident):
    command = None
    if incident.command_execution_id:
        command_payload = serialize_command(incident.command_execution)
        command = {'id': command_payload['id'], 'status': command_payload['status']}
        if 'command' in command_payload:
            command['command'] = command_payload['command']
    return {
        'host': serialize_host(incident.host) if incident.host_id else None,
        'alert': {
            'id': incident.alert_id,
            'message': incident.alert.message,
            'status': incident.alert.status,
        } if incident.alert_id else None,
        'deployment': {
            'id': incident.deployment_release_id,
            'app': incident.deployment_release.app.name,
            'version': incident.deployment_release.version,
            'status': incident.deployment_release.status,
        } if incident.deployment_release_id else None,
        # Command output and error are deliberately excluded from incident APIs.
        'command': command,
    }


def serialize_incident(incident, include_timeline=False):
    item = {
        'id': incident.id,
        'title': incident.title,
        'severity': incident.severity,
        'severity_label': label(incident, 'severity'),
        'description': incident.description,
        'status': incident.status,
        'status_label': label(incident, 'status'),
        'references': serialize_incident_reference(incident),
        'postmortem': {
            'root_cause': incident.root_cause,
            'resolution': incident.resolution,
            'follow_up': incident.follow_up,
        },
        'created_by': incident.created_by,
        'created_at': iso(incident.created_at),
        'updated_at': iso(incident.updated_at),
        'resolved_at': iso(incident.resolved_at),
    }
    if include_timeline:
        item['timeline'] = [{
            'id': entry.id,
            'note': entry.note,
            'created_by': entry.created_by,
            'created_at': iso(entry.created_at),
        } for entry in incident.timeline.all()]
    return item


def scoped_incidents(request):
    incidents = Incident.objects.select_related(
        'host', 'alert__host', 'deployment_release__app', 'command_execution__host'
    ).prefetch_related('deployment_release__hosts', 'timeline')
    return [incident for incident in incidents if can_access_incident(request, incident)]


def limit_items(request, items, default=50, maximum=200):
    try:
        limit = int(request.GET.get('limit', default))
    except (TypeError, ValueError):
        limit = default
    return items[:max(1, min(limit, maximum))]


def incident_from_payload(payload, field, model):
    value = payload.get(field)
    if value in (None, ''):
        return None, None
    try:
        return model.objects.get(id=int(value)), None
    except (TypeError, ValueError, model.DoesNotExist):
        return None, '%s 无效或不存在' % field


def serialize_approval(approval):
    result = {
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
        'deployment_release_id': approval.deployment_release_id,
        'command_execution_id': approval.command_execution_id,
        'created_at': iso(approval.created_at),
        'decided_at': iso(approval.decided_at),
        'executed_at': iso(approval.executed_at),
    }
    if not (approval.command_execution_id and approval.command_execution.runbook_template_id):
        result['command'] = approval.command
    return result


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


def serialize_maintenance_window(window, visible_hosts):
    visible_ids = set(visible_hosts.values_list('id', flat=True))
    hosts = [serialize_host(host) for host in window.hosts.all() if host.id in visible_ids]
    services = []
    for service in window.services.all():
        service_host_ids = set(service.hosts.values_list('id', flat=True))
        if service_host_ids.issubset(visible_ids):
            services.append({'id': service.id, 'name': service.name, 'environment': service.environment})
    return {
        'id': window.id,
        'name': window.name,
        'reason': window.reason,
        'starts_at': iso(window.starts_at),
        'ends_at': iso(window.ends_at),
        'enabled': window.enabled,
        'hosts': hosts,
        'services': services,
    }


def can_view_maintenance_window(request, window):
    targets = list(window.hosts.all())
    for service in window.services.all():
        service_hosts = list(service.hosts.all())
        if not service_hosts:
            return False
        targets.extend(service_hosts)
    return bool(targets) and can_access_hosts(request, targets)


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
        'response': truncate_text(redact_sensitive_text(log.response)),
        'failure_category': log.failure_category,
        'attempt_count': log.attempt_count,
        'created_at': iso(log.created_at),
    }


def notification_health_summary():
    """Aggregate delivery outcomes without reading notification content or secrets."""
    channels = [{
        'id': channel.id,
        'name': channel.name,
        'channel_type': channel.channel_type,
        'total_count': 0,
        'success_count': 0,
        'failed_count': 0,
        'last_sent_at': None,
        'last_success_at': None,
        'last_failure_at': None,
        'failure_categories': {},
    } for channel in NotificationChannel.objects.all()]
    by_id = dict((item['id'], item) for item in channels)
    logs = NotificationLog.objects.filter(channel__isnull=False).values(
        'channel_id', 'status', 'failure_category', 'created_at'
    )
    for log in logs:
        item = by_id.get(log['channel_id'])
        if not item:
            continue
        item['total_count'] += 1
        occurred_at = iso(log['created_at'])
        if item['last_sent_at'] is None or occurred_at > item['last_sent_at']:
            item['last_sent_at'] = occurred_at
        if log['status'] == NotificationLog.STATUS_SUCCESS:
            item['success_count'] += 1
            if item['last_success_at'] is None or occurred_at > item['last_success_at']:
                item['last_success_at'] = occurred_at
        else:
            item['failed_count'] += 1
            if item['last_failure_at'] is None or occurred_at > item['last_failure_at']:
                item['last_failure_at'] = occurred_at
            category = log['failure_category'] or 'uncategorized'
            item['failure_categories'][category] = item['failure_categories'].get(category, 0) + 1
    return channels


def configured_integration_health(configs, integration_type):
    """Serialize configured monitor integrations without their endpoint fields."""
    results = []
    for config in configs:
        summary = summarize_integration_health(integration_type, source=config)
        results.append({
            'id': config.id,
            'name': config.name,
            'enabled': config.enabled,
            'current_status': summary['current_status'],
            'latest_check': iso(summary['latest_check']),
            'latest_category': summary['latest_category'],
            'consecutive_failures': summary['consecutive_failures'],
            'recent_event_counts': summary['recent_event_counts'],
        })
    return results


def redact_sensitive_text(value):
    value = value or ''
    value = SENSITIVE_URL_RE.sub('[redacted-url]', value)
    value = SENSITIVE_ENC_RE.sub('enc:[redacted]', value)
    value = SENSITIVE_KV_RE.sub(lambda match: '%s[redacted]' % match.group(1), value)
    return value


def serialize_audit_log(log):
    return {
        'id': log.id,
        'user': log.user,
        'action': log.action,
        'target_type': log.target_type,
        'target_id': log.target_id,
        'detail': redact_sensitive_text(log.detail),
        'ip_address': log.ip_address,
        'created_at': iso(log.created_at),
    }


def serialize_topology_service(service, visible_host_ids, visible_service_ids):
    return {
        'id': service.id,
        'name': service.name,
        'owner': service.owner,
        'environment': service.environment,
        'environment_label': label(service, 'environment'),
        'description': service.description,
        'hosts': [serialize_host(host) for host in service.hosts.all() if host.id in visible_host_ids],
        'upstream_dependencies': [
            {'id': link.upstream_service.id, 'name': link.upstream_service.name}
            for link in service.upstream_links.all()
            if link.upstream_service_id in visible_service_ids
        ],
    }


def limit_queryset(request, queryset, default=50, maximum=200):
    try:
        limit = int(request.GET.get('limit', default))
    except (TypeError, ValueError):
        limit = default
    limit = max(1, min(limit, maximum))
    return queryset[:limit]


def _worker_alert_threshold(value, maximum=None):
    """Normalize a display-only Worker alert threshold without exposing config."""
    try:
        value = float(value)
    except (TypeError, ValueError):
        return None
    if not math.isfinite(value) or value <= 0:
        return None
    if maximum is not None and value > maximum:
        return None
    return value


def worker_observability_payload(summary=None):
    """Return the safe, read-only data consumed by the Worker status page/API."""
    from .services import summarize_background_jobs

    summary = summary if summary is not None else summarize_background_jobs()
    pending_threshold = _worker_alert_threshold(
        getattr(settings, 'DEVOPS_WORKER_ALERT_PENDING_THRESHOLD', 0)
    )
    failure_rate_threshold = _worker_alert_threshold(
        getattr(settings, 'DEVOPS_WORKER_ALERT_FAILURE_RATE_PERCENT', 0),
        maximum=100,
    )
    timed_out_threshold = _worker_alert_threshold(
        getattr(settings, 'DEVOPS_WORKER_ALERT_TIMED_OUT_THRESHOLD', 0)
    )
    failure_rate_percent = round(float(summary['recent_failure_rate']) * 100, 2)
    thresholds = {
        'pending': {
            'threshold': pending_threshold,
            'current': summary['pending'],
            'breached': pending_threshold is not None and summary['pending'] >= pending_threshold,
        },
        'failure_rate': {
            'threshold': failure_rate_threshold,
            'current': failure_rate_percent,
            'breached': failure_rate_threshold is not None and failure_rate_percent >= failure_rate_threshold,
        },
        'timed_out': {
            'threshold': timed_out_threshold,
            'current': summary['timed_out'],
            'breached': timed_out_threshold is not None and summary['timed_out'] >= timed_out_threshold,
        },
    }
    return {'summary': summary, 'thresholds': thresholds}


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
            'audit': has_role(request, DevOpsRole.ROLE_VIEWER, MODULE_AUDIT),
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


PROMETHEUS_RULE_SAFE_MESSAGES = {
    'conflict': '规则已被其他操作更新，请刷新后重试。',
    'forbidden': '当前集群权限不足，无法操作 PrometheusRule。',
    'crd_not_found': '集群未安装 PrometheusRule CRD，或规则不存在。',
    'timeout': '连接 Kubernetes 集群超时，请稍后重试。',
    'offline': '无法连接 Kubernetes 集群，请确认集群状态后重试。',
    'invalid_yaml': '规则 YAML 格式或资源身份无效。',
    'invalid_identity': '规则命名空间、名称或资源版本无效。',
    'dependency_missing': '缺少必要依赖，无法操作 PrometheusRule。',
}
PROMETHEUS_RULE_NAMESPACE_PATTERN = re.compile(r'^[a-z0-9]([-a-z0-9]*[a-z0-9])?$')
PROMETHEUS_RULE_NAME_PATTERN = re.compile(r'^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$')
PROMETHEUS_RULE_AUDIT_OUTCOMES = frozenset(('ok',) + tuple(PROMETHEUS_RULE_SAFE_MESSAGES))


def prometheus_rule_cluster_or_error(cluster_id):
    cluster = K8sCluster.objects.filter(id=cluster_id).first()
    if not cluster:
        return None, api_error('集群不存在', status=404, code='not_found')
    return cluster, None


def prometheus_rule_service_error(result):
    code = (result or {}).get('code', 'offline')
    status = {
        'invalid_yaml': 400,
        'invalid_identity': 400,
        'conflict': 409,
        'forbidden': 403,
        'crd_not_found': 404,
    }.get(code, 503)
    return api_error(
        PROMETHEUS_RULE_SAFE_MESSAGES.get(code, '无法操作 PrometheusRule，请稍后重试。'),
        status=status,
        code=code if code in PROMETHEUS_RULE_SAFE_MESSAGES else 'offline',
    )


def normalize_prometheus_rule_identity(namespace, name):
    namespace = (namespace or '').strip().lower()
    name = (name or '').strip()
    if (not namespace or len(namespace) > 63 or not PROMETHEUS_RULE_NAMESPACE_PATTERN.match(namespace)
            or not name or len(name) > 253 or not PROMETHEUS_RULE_NAME_PATTERN.match(name)):
        return None, None
    return namespace, name


def prometheus_rule_audit_detail(cluster, namespace, name, action, outcome, resource_version=''):
    return '集群=%s, 集群名称=%s, 命名空间=%s, 规则=%s, 操作=%s, 结果=%s, 资源版本=%s' % (
        cluster.id, cluster.name, namespace, name, action, outcome, resource_version or '-',
    )


def prometheus_rule_audit_outcome(result):
    if result and result.get('ok'):
        return 'ok'
    code = (result or {}).get('code')
    return code if code in PROMETHEUS_RULE_AUDIT_OUTCOMES else 'offline'


def prometheus_rule_update_summary(rule, namespace, name):
    metadata = (rule or {}).get('metadata') if isinstance(rule, dict) else {}
    metadata = metadata if isinstance(metadata, dict) else {}
    return {
        'namespace': namespace,
        'name': name,
        'resource_version': normalize_prometheus_rule_resource_version(metadata.get('resourceVersion')),
    }


def prometheus_rule_list_summary(rule):
    rule = rule if isinstance(rule, dict) else {}
    return {
        'namespace': str(rule.get('namespace') or ''),
        'name': str(rule.get('name') or ''),
        'resource_version': str(rule.get('resource_version') or ''),
        'created_at': str(rule.get('created_at') or ''),
    }


@api_login_required
@require_http_methods(['GET'])
def prometheus_rules(request, cluster_id):
    if not has_role(request, DevOpsRole.ROLE_VIEWER, MODULE_CLUSTER):
        return api_error('没有 PrometheusRule 查看权限', status=403, code='forbidden')
    cluster, error = prometheus_rule_cluster_or_error(cluster_id)
    if error:
        return error
    result = list_prometheus_rules(cluster)
    if not result.get('ok'):
        return prometheus_rule_service_error(result)
    return JsonResponse({
        'ok': True,
        'results': [prometheus_rule_list_summary(rule) for rule in result.get('rules', [])],
    })


@api_login_required
@require_http_methods(['GET'])
def prometheus_rule_detail(request, cluster_id, namespace, name):
    if not has_role(request, DevOpsRole.ROLE_VIEWER, MODULE_CLUSTER):
        return api_error('没有 PrometheusRule 查看权限', status=403, code='forbidden')
    cluster, error = prometheus_rule_cluster_or_error(cluster_id)
    if error:
        return error
    result = get_prometheus_rule(cluster, namespace, name)
    if not result.get('ok'):
        return prometheus_rule_service_error(result)
    return JsonResponse({'ok': True, 'yaml': result.get('yaml', '')})


@api_login_required
@require_http_methods(['POST'])
def prometheus_rule_update(request, cluster_id, namespace, name):
    if not has_role(request, DevOpsRole.ROLE_ADMIN, MODULE_CLUSTER):
        return api_error('没有 PrometheusRule 管理权限', status=403, code='forbidden')
    payload = request_json(request)
    if not isinstance(payload, dict):
        return invalid_json_error()
    yaml_text = payload.get('yaml')
    if not isinstance(yaml_text, str) or not yaml_text.strip():
        return api_error('规则 YAML 不能为空', status=400, code='validation_error')
    namespace, name = normalize_prometheus_rule_identity(namespace, name)
    if not namespace or not name:
        return api_error('规则命名空间或名称无效', status=400, code='validation_error')
    cluster, error = prometheus_rule_cluster_or_error(cluster_id)
    if error:
        return error
    result = replace_prometheus_rule(cluster, namespace, name, yaml_text)
    resource_version = prometheus_rule_update_summary(result.get('rule'), namespace, name)['resource_version']
    audit(request, 'API更新PrometheusRule', 'K8sCluster', cluster.id,
          prometheus_rule_audit_detail(cluster, namespace, name, 'update', prometheus_rule_audit_outcome(result),
                                       resource_version))
    if not result.get('ok'):
        return prometheus_rule_service_error(result)
    return JsonResponse({'ok': True, 'rule': prometheus_rule_update_summary(result.get('rule'), namespace, name)})


@api_login_required
@require_http_methods(['POST'])
def prometheus_rule_delete(request, cluster_id, namespace, name):
    if not has_role(request, DevOpsRole.ROLE_ADMIN, MODULE_CLUSTER):
        return api_error('没有 PrometheusRule 管理权限', status=403, code='forbidden')
    payload = request_json(request)
    if not isinstance(payload, dict):
        return invalid_json_error()
    resource_version = normalize_prometheus_rule_resource_version(payload.get('resource_version'))
    if payload.get('confirmation') != 'DELETE' or not resource_version:
        return api_error('请确认 DELETE 并提供资源版本', status=400, code='validation_error')
    namespace, name = normalize_prometheus_rule_identity(namespace, name)
    if not namespace or not name:
        return api_error('规则命名空间或名称无效', status=400, code='validation_error')
    cluster, error = prometheus_rule_cluster_or_error(cluster_id)
    if error:
        return error
    result = delete_prometheus_rule(cluster, namespace, name, resource_version)
    audit(request, 'API删除PrometheusRule', 'K8sCluster', cluster.id,
          prometheus_rule_audit_detail(cluster, namespace, name, 'delete', prometheus_rule_audit_outcome(result),
                                       resource_version))
    if not result.get('ok'):
        return prometheus_rule_service_error(result)
    return JsonResponse({'ok': True})


@api_login_required
@require_http_methods(['GET'])
def service_topology(request):
    if not has_role(request, DevOpsRole.ROLE_VIEWER, MODULE_SERVICE):
        return api_error('没有服务管理权限', status=403, code='forbidden')
    hosts = visible_hosts_for_request(request)
    visible_host_ids = set(hosts.values_list('id', flat=True))
    services = list(ServiceCatalog.objects.filter(
        models.Q(hosts__in=hosts) | models.Q(hosts__isnull=True)
    ).distinct().prefetch_related('hosts', 'upstream_links__upstream_service'))
    visible_service_ids = set(service.id for service in services)
    return JsonResponse({
        'ok': True,
        'results': [serialize_topology_service(service, visible_host_ids, visible_service_ids) for service in services],
    })


def serialize_service_slo(slo):
    """Expose only the configuration and safe evaluation summary, never query data."""
    return {
        'id': slo.id,
        'service': {'id': slo.service_id, 'name': slo.service.name},
        'metric_kind': slo.metric_kind,
        'metric_kind_label': label(slo, 'metric_kind'),
        'target': str(slo.target),
        'window_minutes': slo.window_minutes,
        'enabled': slo.enabled,
        'last_state': slo.last_state,
        'last_state_label': label(slo, 'last_state'),
        'last_summary': slo.last_summary,
        'last_evaluated_at': iso(slo.last_evaluated_at),
    }


@api_login_required
@require_http_methods(['GET', 'POST'])
def service_slos(request):
    can_manage = has_role(request, DevOpsRole.ROLE_ADMIN, MODULE_SECURITY)
    if request.method == 'POST':
        if not can_manage:
            return api_error('没有服务 SLO 管理权限', status=403, code='forbidden')
        payload = request_json(request)
        if not isinstance(payload, dict):
            return invalid_json_error()
        hosts = visible_hosts_for_request(request)
        services = ServiceCatalog.objects.filter(
            models.Q(hosts__in=hosts) | models.Q(hosts__isnull=True)
        ).distinct()
        form = ServiceSloForm(payload)
        form.fields['service'].queryset = services
        if not form.is_valid():
            return api_error('SLO 配置无效', status=400, code='validation_error')
        slo = form.save()
        audit(request, 'API创建服务SLO', 'ServiceSlo', slo.id, '%s:%s' % (slo.service.name, slo.metric_kind))
        return JsonResponse({'ok': True, 'slo': serialize_service_slo(slo)}, status=201)
    if not can_manage and not has_role(request, DevOpsRole.ROLE_VIEWER, MODULE_SERVICE):
        return api_error('没有服务 SLO 查看权限', status=403, code='forbidden')
    hosts = visible_hosts_for_request(request)
    services = ServiceCatalog.objects.filter(
        models.Q(hosts__in=hosts) | models.Q(hosts__isnull=True)
    ).distinct()
    slos = ServiceSlo.objects.select_related('service').filter(service__in=services)
    return JsonResponse({'ok': True, 'results': [serialize_service_slo(slo) for slo in slos]})


def scoped_service_slo_or_error(request, id):
    hosts = visible_hosts_for_request(request)
    services = ServiceCatalog.objects.filter(
        models.Q(hosts__in=hosts) | models.Q(hosts__isnull=True)
    ).distinct()
    try:
        return ServiceSlo.objects.select_related('service').get(id=id, service__in=services), None
    except ServiceSlo.DoesNotExist:
        return None, api_error('服务 SLO 不存在', status=404, code='not_found')


@api_login_required
@require_http_methods(['POST'])
def service_slo_update(request, id):
    if not has_role(request, DevOpsRole.ROLE_ADMIN, MODULE_SECURITY):
        return api_error('没有服务 SLO 管理权限', status=403, code='forbidden')
    payload = request_json(request)
    if not isinstance(payload, dict):
        return invalid_json_error()
    slo, error = scoped_service_slo_or_error(request, id)
    if error:
        return error
    form = ServiceSloForm(payload, instance=slo)
    form.fields['service'].queryset = ServiceCatalog.objects.filter(id=slo.service_id)
    if not form.is_valid():
        return api_error('SLO 配置无效', status=400, code='validation_error')
    slo = form.save()
    audit(request, 'API更新服务SLO', 'ServiceSlo', slo.id, '指标=%s, 启用=%s' % (slo.metric_kind, bool(slo.enabled)))
    return JsonResponse({'ok': True, 'slo': serialize_service_slo(slo)})


@api_login_required
@require_http_methods(['POST'])
def service_slo_evaluate(request, id):
    if not has_role(request, DevOpsRole.ROLE_ADMIN, MODULE_SECURITY):
        return api_error('没有服务 SLO 管理权限', status=403, code='forbidden')
    slo, error = scoped_service_slo_or_error(request, id)
    if error:
        return error
    result = evaluate_service_slo(slo)
    audit(request, 'API手动评估服务SLO', 'ServiceSlo', slo.id, '状态=%s' % result['state'])
    return JsonResponse({'ok': True, 'slo': serialize_service_slo(slo)})


def serialize_runbook(runbook):
    """Runbook command bodies remain server-side and never enter list payloads."""
    return {
        'id': runbook.id,
        'name': runbook.name,
        'version': runbook.version,
        'trigger_kind': runbook.trigger_kind,
        'trigger_kind_label': label(runbook, 'trigger_kind'),
        'service': {'id': runbook.service_id, 'name': runbook.service.name} if runbook.service_id else None,
        'enabled': runbook.enabled,
        'requires_approval': runbook.requires_approval,
        'updated_at': iso(runbook.updated_at),
    }


def scoped_runbook_queryset(request):
    return RunbookTemplate.objects.select_related('service').filter(
        allowed_hosts__in=visible_hosts_for_request(request)
    ).distinct()


def runbook_form(request, data, instance=None):
    form = RunbookTemplateForm(data, instance=instance)
    form.fields['allowed_hosts'].queryset = visible_hosts_for_request(request)
    form.fields['service'].queryset = ServiceCatalog.objects.filter(
        models.Q(hosts__in=visible_hosts_for_request(request)) | models.Q(hosts__isnull=True)
    ).distinct()
    return form


@api_login_required
@require_http_methods(['GET', 'POST'])
def runbooks(request):
    if request.method == 'GET':
        if not has_role(request, DevOpsRole.ROLE_VIEWER, MODULE_COMMAND):
            return api_error('没有运行手册查看权限', status=403, code='forbidden')
        return JsonResponse({'ok': True, 'results': [serialize_runbook(item) for item in scoped_runbook_queryset(request)]})
    if not has_role(request, DevOpsRole.ROLE_ADMIN, MODULE_SECURITY):
        return api_error('没有运行手册管理权限', status=403, code='forbidden')
    payload = request_json(request)
    if not isinstance(payload, dict):
        return invalid_json_error()
    form = runbook_form(request, payload)
    if not form.is_valid():
        return api_error('运行手册配置无效', status=400, code='validation_error')
    runbook = form.save(commit=False)
    runbook.created_by = request.session.get('user_name', '')
    runbook.save()
    form.save_m2m()
    audit(request, 'API创建受控运行手册', 'RunbookTemplate', runbook.id, '版本=%s, 启用=%s' % (runbook.version, bool(runbook.enabled)))
    return JsonResponse({'ok': True, 'runbook': serialize_runbook(runbook)}, status=201)


@api_login_required
@require_http_methods(['POST'])
def runbook_update(request, id):
    if not has_role(request, DevOpsRole.ROLE_ADMIN, MODULE_SECURITY):
        return api_error('没有运行手册管理权限', status=403, code='forbidden')
    try:
        runbook = scoped_runbook_queryset(request).get(id=id)
    except RunbookTemplate.DoesNotExist:
        return api_error('运行手册不存在', status=404, code='not_found')
    payload = request_json(request)
    if not isinstance(payload, dict):
        return invalid_json_error()
    form = runbook_form(request, payload, instance=runbook)
    if not form.is_valid():
        return api_error('运行手册配置无效', status=400, code='validation_error')
    runbook = form.save()
    audit(request, 'API更新受控运行手册', 'RunbookTemplate', runbook.id, '版本=%s, 启用=%s' % (runbook.version, bool(runbook.enabled)))
    return JsonResponse({'ok': True, 'runbook': serialize_runbook(runbook)})


@api_login_required
@require_http_methods(['POST'])
def runbook_initiate(request, id):
    if not has_role(request, DevOpsRole.ROLE_OPERATOR, MODULE_COMMAND):
        return api_error('没有命令执行权限', status=403, code='forbidden')
    payload = request_json(request)
    if not isinstance(payload, dict):
        return invalid_json_error()
    try:
        runbook = scoped_runbook_queryset(request).get(id=id)
    except RunbookTemplate.DoesNotExist:
        return api_error('运行手册不存在', status=404, code='not_found')
    try:
        host = visible_hosts_for_request(request).get(id=payload.get('host_id'))
    except (TypeError, ValueError, NewLinux.DoesNotExist):
        return api_error('目标主机不在当前用户授权范围内', status=403, code='host_forbidden')
    try:
        record, approval = initiate_runbook(request, runbook, host)
    except PermissionError:
        return api_error('目标主机不在当前用户授权范围内', status=403, code='host_forbidden')
    except RunbookInitiationError as exc:
        return api_error(str(exc), status=400, code='validation_error')
    return JsonResponse({
        'ok': True, 'requires_approval': True, 'runbook': serialize_runbook(runbook),
        'command_execution_id': record.id, 'approval': serialize_approval(approval),
    }, status=202)


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
        return invalid_json_error()
    try:
        host = visible_hosts.get(id=payload.get('host_id'))
    except (TypeError, ValueError, visible_hosts.model.DoesNotExist):
        return api_error('目标主机不在当前用户授权范围内', status=403, code='host_forbidden')
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
        return invalid_json_error()
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
def capacity_forecast(request):
    if not has_role(request, DevOpsRole.ROLE_VIEWER, MODULE_METRIC):
        return api_error('没有监控历史权限', status=403, code='forbidden')
    return JsonResponse({'ok': True, 'results': forecast_host_capacity(visible_hosts_for_request(request))})


@api_login_required
@require_http_methods(['GET'])
def alerts(request):
    queryset = scoped_alert_queryset(visible_hosts_for_request(request))
    return JsonResponse({'ok': True, 'results': [serialize_alert(item) for item in limit_queryset(request, queryset)]})


@api_login_required
@require_http_methods(['GET', 'POST'])
def incidents(request):
    if request.method == 'GET':
        if not has_role(request, DevOpsRole.ROLE_VIEWER, MODULE_ALERT):
            return api_error('没有事件查看权限', status=403, code='forbidden')
        return JsonResponse({
            'ok': True,
            'results': [serialize_incident(item) for item in limit_items(request, scoped_incidents(request))],
        })

    if not has_role(request, DevOpsRole.ROLE_OPERATOR, MODULE_ALERT):
        return api_error('没有事件操作权限', status=403, code='forbidden')
    payload = request_json(request)
    if payload is None:
        return invalid_json_error()
    if not isinstance(payload, dict):
        return api_error('请求参数无效', status=400, code='validation_error')
    title = payload.get('title')
    if not isinstance(title, str) or not title.strip() or len(title.strip()) > 200:
        return api_error('事件标题不能为空且不能超过 200 字符', status=400, code='validation_error')
    severity = payload.get('severity', Incident.SEVERITY_MEDIUM)
    if severity not in dict(Incident.SEVERITY_CHOICES):
        return api_error('事件级别无效', status=400, code='validation_error')
    description = payload.get('description', '')
    if not isinstance(description, str) or len(description) > 10000:
        return api_error('事件描述无效', status=400, code='validation_error')

    from RemoteLinux.models import NewLinux
    references = {}
    for field, model in (
        ('host_id', NewLinux),
        ('alert_id', AlertEvent),
        ('deployment_release_id', DeploymentRelease),
        ('command_execution_id', CommandExecution),
    ):
        value, error = incident_from_payload(payload, field, model)
        if error:
            return api_error(error, status=400, code='validation_error')
        references[field] = value
    incident = create_incident(
        request,
        title.strip(),
        severity,
        description,
        host=references['host_id'],
        alert=references['alert_id'],
        deployment_release=references['deployment_release_id'],
        command_execution=references['command_execution_id'],
    )
    if not incident:
        return api_error('关联资源不在当前用户授权范围内', status=403, code='host_forbidden')
    incident = Incident.objects.select_related(
        'host', 'alert__host', 'deployment_release__app', 'command_execution__host'
    ).prefetch_related('deployment_release__hosts', 'timeline').get(id=incident.id)
    return JsonResponse({'ok': True, 'incident': serialize_incident(incident, include_timeline=True)}, status=201)


def get_scoped_incident_or_error(request, id):
    for incident in scoped_incidents(request):
        if incident.id == id:
            return incident, None
    return None, api_error('事件不存在', status=404, code='not_found')


@api_login_required
@require_http_methods(['GET'])
def incident_detail(request, id):
    if not has_role(request, DevOpsRole.ROLE_VIEWER, MODULE_ALERT):
        return api_error('没有事件查看权限', status=403, code='forbidden')
    incident, error = get_scoped_incident_or_error(request, id)
    if error:
        return error
    return JsonResponse({'ok': True, 'incident': serialize_incident(incident, include_timeline=True)})


def incident_operator(request, id):
    if not has_role(request, DevOpsRole.ROLE_OPERATOR, MODULE_ALERT):
        return None, api_error('没有事件操作权限', status=403, code='forbidden')
    return get_scoped_incident_or_error(request, id)


@api_login_required
@require_http_methods(['POST'])
def incident_timeline(request, id):
    incident, error = incident_operator(request, id)
    if error:
        return error
    payload = request_json(request)
    if payload is None:
        return invalid_json_error()
    note = payload.get('note') if isinstance(payload, dict) else None
    if not isinstance(note, str) or not note.strip() or len(note.strip()) > 10000:
        return api_error('时间线内容不能为空且不能超过 10000 字符', status=400, code='validation_error')
    entry = add_incident_timeline_note(request, incident, note.strip())
    return JsonResponse({'ok': True, 'timeline': {
        'id': entry.id, 'note': entry.note, 'created_by': entry.created_by, 'created_at': iso(entry.created_at),
    }}, status=201)


@api_login_required
@require_http_methods(['POST'])
def incident_status(request, id):
    incident, error = incident_operator(request, id)
    if error:
        return error
    payload = request_json(request)
    if payload is None:
        return invalid_json_error()
    status = payload.get('status') if isinstance(payload, dict) else None
    if status not in dict(Incident.STATUS_CHOICES):
        return api_error('事件状态无效', status=400, code='validation_error')
    incident = update_incident_status(request, incident, status)
    return JsonResponse({'ok': True, 'incident': serialize_incident(incident)})


@api_login_required
@require_http_methods(['POST'])
def incident_postmortem(request, id):
    incident, error = incident_operator(request, id)
    if error:
        return error
    if incident.status not in (Incident.STATUS_RESOLVED, Incident.STATUS_CLOSED):
        return api_error('仅已解决或已关闭事件可记录复盘', status=400, code='validation_error')
    payload = request_json(request)
    if payload is None:
        return invalid_json_error()
    if not isinstance(payload, dict):
        return api_error('请求参数无效', status=400, code='validation_error')
    fields = []
    for field in ('root_cause', 'resolution', 'follow_up'):
        value = payload.get(field, '')
        if not isinstance(value, str) or len(value) > 10000:
            return api_error('%s 无效' % field, status=400, code='validation_error')
        fields.append(value.strip())
    incident = record_incident_postmortem(request, incident, *fields)
    return JsonResponse({'ok': True, 'incident': serialize_incident(incident)})


@api_login_required
@require_http_methods(['GET'])
def approvals(request):
    visible_hosts = visible_hosts_for_request(request)
    queryset = scoped_approval_queryset(visible_hosts)
    return JsonResponse({'ok': True, 'results': [serialize_approval(item) for item in limit_queryset(request, queryset, default=100)]})


@api_login_required
@require_http_methods(['POST'])
def approval_decide(request, id):
    if not has_role(request, DevOpsRole.ROLE_ADMIN, MODULE_APPROVAL):
        return api_error('没有审批管理权限', status=403, code='forbidden')
    payload = request_json(request)
    if payload is None:
        return invalid_json_error()
    if not isinstance(payload, dict):
        return api_error('请求参数无效', status=400, code='validation_error')
    action = (payload.get('action') or '').strip()
    if action not in ('approve', 'reject'):
        return api_error('审批动作无效', status=400, code='validation_error')
    comment = payload.get('comment') or ''
    if not isinstance(comment, str):
        comment = str(comment)
    comment = comment.strip()[:500]

    try:
        approval = scoped_approval_queryset(visible_hosts_for_request(request)).get(id=id)
    except ApprovalRequest.DoesNotExist:
        return api_error('审批不存在', status=404, code='not_found')

    if not can_decide_deployment_approval(request, approval):
        return api_error('审批不存在', status=404, code='not_found')

    if approval.status != ApprovalRequest.STATUS_PENDING:
        return api_error('只能处理待审批请求', status=400, code='validation_error')

    approver = request.session.get('user_name') or ''
    if approval.requester and approval.requester == approver:
        approval.comment = '申请人与审批人不能为同一人'
        approval.save(update_fields=['comment'])
        audit(request, 'API审批自审拦截', 'ApprovalRequest', approval.id, approval.title)
        return api_error('申请人与审批人不能为同一人', status=400, code='validation_error')

    approval.approver = approver
    approval.comment = comment
    approval.decided_at = timezone.now()
    if action == 'reject':
        approval.status = ApprovalRequest.STATUS_REJECTED
        approval.save(update_fields=['approver', 'comment', 'decided_at', 'status'])
        notify_approval(approval, '拒绝')
        audit(request, 'API拒绝审批', 'ApprovalRequest', approval.id, approval.title)
        return JsonResponse({'ok': True, 'approval': serialize_approval(approval)})

    approval.status = ApprovalRequest.STATUS_APPROVED
    approval.save(update_fields=['approver', 'comment', 'decided_at', 'status'])
    approval = execute_approval_request(approval, user_role(request))
    audit(request, 'API批准审批', 'ApprovalRequest', approval.id, approval.title)
    return JsonResponse({'ok': True, 'approval': serialize_approval(approval)})


@api_login_required
@require_http_methods(['GET'])
def deployments(request):
    visible_hosts = visible_hosts_for_request(request)
    queryset = DeploymentRelease.objects.select_related('app').filter(hosts__in=visible_hosts).distinct()
    return JsonResponse({'ok': True, 'results': [serialize_release(item, visible_hosts) for item in limit_queryset(request, queryset)]})


@api_login_required
@require_http_methods(['GET'])
def maintenance_windows(request):
    if not has_role(request, DevOpsRole.ROLE_ADMIN, MODULE_SECURITY):
        return api_error('没有维护窗口管理权限', status=403, code='forbidden')
    visible_hosts = visible_hosts_for_request(request)
    windows = MaintenanceWindow.objects.prefetch_related('hosts', 'services__hosts').all()[:100]
    return JsonResponse({'ok': True, 'results': [
        serialize_maintenance_window(item, visible_hosts) for item in windows
        if can_view_maintenance_window(request, item)
    ]})


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
    if not has_role(request, DevOpsRole.ROLE_VIEWER, MODULE_SECURITY):
        return api_error('没有通知管理权限', status=403, code='forbidden')
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


@api_login_required
@require_http_methods(['GET'])
def integration_health(request):
    """Admin-only health summaries for configured inbound and notification integrations."""
    if not has_role(request, DevOpsRole.ROLE_ADMIN, MODULE_SECURITY):
        return api_error('没有集成健康管理权限', status=403, code='forbidden')
    from monitor.models import AlertmanagerConfig, PrometheusConfig
    github = summarize_integration_health(
        IntegrationHealthEvent.TYPE_GITHUB_INBOUND,
        source_name=IntegrationHealthEvent.SOURCE_GITHUB_INBOUND,
    )
    github['latest_check'] = iso(github['latest_check'])
    github['recent_since'] = iso(github['recent_since'])
    return JsonResponse({
        'ok': True,
        'github_inbound': github,
        'prometheus': configured_integration_health(
            PrometheusConfig.objects.only('id', 'name', 'enabled').order_by('id'),
            IntegrationHealthEvent.TYPE_PROMETHEUS,
        ),
        'alertmanager': configured_integration_health(
            AlertmanagerConfig.objects.only('id', 'name', 'enabled').order_by('id'),
            IntegrationHealthEvent.TYPE_ALERTMANAGER,
        ),
        'notifications': notification_health_summary(),
    })


@api_login_required
@require_http_methods(['GET'])
def worker_observability(request):
    """Admin-only, read-only aggregate state for the durable Worker queue."""
    if not has_role(request, DevOpsRole.ROLE_ADMIN, MODULE_SECURITY):
        return api_error('没有 Worker 观测管理权限', status=403, code='forbidden')
    payload = worker_observability_payload()
    return JsonResponse({'ok': True, 'worker': payload})


@api_login_required
@require_http_methods(['GET'])
def audit_logs(request):
    if not has_role(request, DevOpsRole.ROLE_VIEWER, MODULE_AUDIT):
        return api_error('没有审计日志权限', status=403, code='forbidden')
    queryset = AuditLog.objects.all()
    keyword = request.GET.get('q', '').strip()
    user = request.GET.get('user', '').strip()
    action = request.GET.get('action', '').strip()
    target_type = request.GET.get('target_type', '').strip()
    if keyword:
        queryset = queryset.filter(
            models.Q(action__icontains=keyword)
            | models.Q(detail__icontains=keyword)
            | models.Q(target_type__icontains=keyword)
            | models.Q(target_id__icontains=keyword)
        )
    if user:
        queryset = queryset.filter(user__icontains=user)
    if action:
        queryset = queryset.filter(action__icontains=action)
    if target_type:
        queryset = queryset.filter(target_type__icontains=target_type)
    return JsonResponse({'ok': True, 'results': [serialize_audit_log(item) for item in limit_queryset(request, queryset)]})
