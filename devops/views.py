import csv
import json
import re
from datetime import datetime, timedelta
try:
    from urllib import parse as urlparse
except ImportError:
    import urllib.parse as urlparse

from django.conf import settings
from django.core.paginator import Paginator
from django.db import models
from django.http import Http404, HttpResponse, HttpResponseBadRequest, HttpResponseForbidden, HttpResponseNotAllowed
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils import timezone
try:
    from django.utils.http import url_has_allowed_host_and_scheme
except ImportError:
    from django.utils.http import is_safe_url as url_has_allowed_host_and_scheme

from RemoteLinux.models import NewLinux
from userprofile.decorators import session_login_required
from .forms import (
    AlertEventForm,
    AlertSilenceForm,
    ApprovalDecisionForm,
    BatchTaskForm,
    CommandApprovalForm,
    CommandExecutionForm,
    CommandPolicyForm,
    ComplianceBaselineForm,
    DevOpsHostScopeForm,
    DevOpsModulePermissionClearForm,
    DevOpsModulePermissionForm,
    DevOpsSettingForm,
    DeploymentAppForm,
    DeploymentReleaseForm,
    DevOpsRoleForm,
    FileDistributionForm,
    HostGroupForm,
    HostTagForm,
    K8sClusterConnectionForm,
    K8sClusterForm,
    PrometheusRuleDeleteForm,
    PrometheusRuleYamlForm,
    normalize_prometheus_rule_identity,
    normalize_prometheus_rule_resource_version,
    NotificationChannelForm,
    NotificationTemplateForm,
    AlertNotificationEscalationForm,
    ServiceOperationForm,
    ServiceCatalogForm,
    ServiceSloForm,
    RunbookTemplateForm,
    ProjectOnboardingForm,
)
from .models import (
    AlertEvent,
    AlertSilence,
    ApprovalRequest,
    AuditLog,
    BatchTask,
    BatchTaskResult,
    CommandExecution,
    CommandPolicy,
    DeploymentApp,
    DeploymentRelease,
    DevOpsSetting,
    DevOpsHostScope,
    DevOpsModulePermission,
    DevOpsRole,
    FileDistribution,
    HostGroup,
    HostTag,
    K8sCluster,
    MetricSample,
    NotificationChannel,
    NotificationLog,
    NotificationTemplate,
    AlertNotificationEscalation,
    ServiceOperation,
    ServiceCatalog,
    ServiceSlo,
    RunbookTemplate,
    ServiceDependency,
    DevOpsProject,
    ComplianceBaseline,
    ComplianceResult,
    IntegrationHealthEvent,
    MaintenanceWindow,
)
from .services import (
    COMMAND_ALLOWED,
    audit,
    can_access_host,
    can_access_hosts,
    can_decide_deployment_approval,
    command_denied_message,
    create_command_approval,
    create_deployment_approval,
    create_rollback_approval,
    deployment_risk_preview,
    execute_approval_request,
    enqueue_background_job,
    execute_batch_task,
    execute_file_distribution,
    execute_deployment_release,
    execute_deployment_rollback,
    execute_command_record,
    evaluate_command_policy,
    has_role,
    update_alert_status,
    user_role,
    visible_hosts_for_request,
    service_command,
    latest_metric_map,
    require_deployment_maintenance_approval,
    require_deployment_slo_approval,
    evaluate_service_slo,
    clear_k8s_detail_cache,
    load_cached_k8s_cluster_detail,
    load_cached_k8s_node_detail,
    notify_approval,
    send_notification_channel,
    test_k8s_cluster_connection,
    scan_compliance_baseline,
    resolve_alert,
    create_project_onboarding,
    clear_module_permissions,
    revoke_module_permission,
    summarize_integration_health,
    initiate_runbook,
    RunbookInitiationError,
    delete_prometheus_rule,
    get_prometheus_rule,
    list_prometheus_rules,
    replace_prometheus_rule,
)


MODULE_COMMAND = DevOpsModulePermission.MODULE_COMMAND
MODULE_TASK = DevOpsModulePermission.MODULE_TASK
MODULE_SERVICE = DevOpsModulePermission.MODULE_SERVICE
MODULE_FILE = DevOpsModulePermission.MODULE_FILE
MODULE_DEPLOYMENT = DevOpsModulePermission.MODULE_DEPLOYMENT
MODULE_APPROVAL = DevOpsModulePermission.MODULE_APPROVAL
MODULE_ALERT = DevOpsModulePermission.MODULE_ALERT
MODULE_METRIC = DevOpsModulePermission.MODULE_METRIC
MODULE_SECURITY = DevOpsModulePermission.MODULE_SECURITY
MODULE_AUDIT = DevOpsModulePermission.MODULE_AUDIT
MODULE_CLUSTER = DevOpsModulePermission.MODULE_CLUSTER

K8S_WORKLOAD_RESOURCE_TABS = (
    ('deployments', '无状态负载'),
    ('statefulsets', '有状态负载'),
    ('daemonsets', '守护进程'),
    ('jobs', '普通服务'),
    ('cronjobs', '定时服务'),
)
K8S_SERVICE_RESOURCE_TABS = (
    ('services', 'Service'),
    ('ingresses', 'Ingress'),
)
K8S_STORAGE_RESOURCE_TABS = (
    ('persistentvolumeclaims', 'PVC'),
    ('persistentvolumes', 'PV'),
    ('storageclasses', 'SC'),
)
K8S_CONFIG_RESOURCE_TABS = (
    ('configmaps', 'ConfigMap'),
    ('secrets', 'Secret'),
)
K8S_GENERIC_RESOURCE_TYPES = (
    ('overview', '概览'),
    ('namespaces', 'Namespace'),
    ('nodes', 'Node'),
    ('services', '服务'),
    ('ingresses', 'Ingress'),
    ('persistentvolumeclaims', '存储'),
    ('persistentvolumes', 'PV'),
    ('storageclasses', 'SC'),
    ('configmaps', '配置'),
    ('secrets', 'Secret'),
)
K8S_DETAIL_RESOURCE_TYPES = K8S_WORKLOAD_RESOURCE_TABS + K8S_GENERIC_RESOURCE_TYPES
K8S_NAMESPACED_RESOURCE_KEYS = tuple(
    key for key, _label in (
        K8S_WORKLOAD_RESOURCE_TABS
        + K8S_SERVICE_RESOURCE_TABS
        + (('persistentvolumeclaims', 'PVC'),)
        + K8S_CONFIG_RESOURCE_TABS
    )
)
K8S_CLUSTER_SCOPED_RESOURCE_KEYS = (
    'overview', 'namespaces', 'nodes', 'persistentvolumes', 'storageclasses',
)
K8S_OVERVIEW_RESOURCE_COUNTS = (
    ('nodes', 'Node'),
    ('pods', 'Pod'),
    ('deployments', 'Deployment'),
    ('statefulsets', 'StatefulSet'),
    ('daemonsets', 'DaemonSet'),
    ('services', 'Service'),
    ('ingresses', 'Ingress'),
    ('persistentvolumeclaims', 'PVC'),
    ('persistentvolumes', 'PV'),
    ('storageclasses', 'StorageClass'),
    ('configmaps', 'ConfigMap'),
    ('secrets', 'Secret'),
)
K8S_SAFE_VIEW_FIELDS = (
    'kind', 'name', 'status', 'replicas', 'namespace', 'created_at', 'detail',
    'labels', 'annotations', 'ip_address',
)
K8S_OFFLINE_DETAIL_MESSAGE = '集群当前处于离线状态，请测试连接或强制刷新后重试。'


def clean_k8s_namespace(value, fallback='default'):
    fallback = (fallback or 'default').strip().lower()
    namespace = (value or '').strip().lower()
    if namespace and len(namespace) <= 63 and re.match(r'^[a-z0-9]([-a-z0-9]*[a-z0-9])?$', namespace):
        return namespace
    return fallback if re.match(r'^[a-z0-9]([-a-z0-9]*[a-z0-9])?$', fallback) else 'default'


def clean_k8s_created_at(value):
    return re.sub(r'\s+GMT[+-]\d{4}$', '', str(value or '-')).strip() or '-'


def safe_k8s_view_resource(resource):
    safe = {key: resource.get(key) for key in K8S_SAFE_VIEW_FIELDS if key in resource}
    if 'created_at' in safe:
        safe['created_at'] = clean_k8s_created_at(safe['created_at'])
    return safe


def attach_k8s_matched_resources(workloads, resource_matches, fallback_pods, fallback_services):
    rows = []
    for workload in workloads or []:
        row = safe_k8s_view_resource(workload)
        matched_pods = []
        matched_services = []
        for group in resource_matches or []:
            primary = group.get('primary') or {}
            if primary.get('name') == row.get('name') and primary.get('namespace') == row.get('namespace'):
                matched_pods = (group.get('resources') or {}).get('pods', []) or []
                matched_services = (group.get('resources') or {}).get('services', []) or []
                break
        if not matched_pods:
            prefix = (row.get('name') or '') + '-'
            matched_pods = [pod for pod in fallback_pods or [] if (pod.get('name') or '').startswith(prefix) and pod.get('namespace') == row.get('namespace')]
        if not matched_services:
            name = row.get('name') or ''
            matched_services = [service for service in fallback_services or [] if ((service.get('name') or '') == name or (service.get('name') or '').startswith(name + '-')) and service.get('namespace') == row.get('namespace')]
        else:
            name = row.get('name') or ''
            matched_services = [service for service in matched_services if ((service.get('name') or '') == name or (service.get('name') or '').startswith(name + '-')) and service.get('namespace') == row.get('namespace')]
        row['matched_pods'] = [safe_k8s_view_resource(pod) for pod in matched_pods]
        row['matched_services'] = [safe_k8s_view_resource(service) for service in matched_services]
        rows.append(row)
    return rows


def require_devops_role(request, minimum_role, module=''):
    if has_role(request, minimum_role, module):
        return None
    audit(request, '权限拒绝', 'DevOpsRole', '', minimum_role)
    return HttpResponseForbidden('没有足够的 DevOps 权限')


def host_forbidden(request, detail=''):
    audit(request, '主机范围拒绝', 'DevOpsHostScope', '', detail)
    return HttpResponseForbidden('目标主机不在当前用户授权范围内')


def apply_host_queryset(form, hosts):
    if 'host' in form.fields:
        form.fields['host'].queryset = hosts
    if 'hosts' in form.fields:
        form.fields['hosts'].queryset = hosts
    return form


def changed_label(created):
    return '创建' if created else '更新'


def role_audit_detail(role, created):
    return '%s 用户=%s, 角色=%s' % (
        changed_label(created),
        role.user.user,
        role.role,
    )


def module_permission_audit_detail(permission, created):
    return '%s 用户=%s, 模块=%s, 角色=%s' % (
        changed_label(created),
        permission.user.user,
        permission.module,
        permission.role,
    )


def host_scope_audit_detail(scope, created):
    groups = ','.join(scope.groups.values_list('name', flat=True)) or '-'
    tags = ','.join(scope.tags.values_list('name', flat=True)) or '-'
    return '%s 用户=%s, 主机组=%s, 标签=%s' % (
        changed_label(created),
        scope.user.user,
        groups,
        tags,
    )


def notification_channel_audit_detail(channel, action):
    return '%s 名称=%s, 类型=%s, 告警=%s, 审批=%s, 发布=%s, 启用=%s' % (
        action,
        channel.name,
        channel.channel_type,
        bool(channel.notify_alert),
        bool(channel.notify_approval),
        bool(channel.notify_deployment),
        bool(channel.enabled),
    )


def notification_governance_audit_detail(action, detail):
    return '%s %s' % (action, detail)


def csv_safe_cell(value):
    if value is None:
        return ''
    value = str(value)
    if value and value[0] in ('=', '+', '-', '@'):
        return "'" + value
    return value


def safe_next_url(request, next_url, fallback):
    if next_url and url_has_allowed_host_and_scheme(next_url, allowed_hosts={request.get_host()}):
        return next_url
    return fallback


@session_login_required
def dashboard(request):
    return render(request, 'devops/vue_app.html')


@session_login_required
def legacy_dashboard(request):
    visible_hosts = visible_hosts_for_request(request)
    content = {
        'host_count': visible_hosts.count(),
        'group_count': HostGroup.objects.count(),
        'open_alert_count': AlertEvent.objects.filter(status=AlertEvent.STATUS_OPEN).count(),
        'task_count': BatchTask.objects.count(),
        'recent_commands': CommandExecution.objects.filter(host__in=visible_hosts)[:5],
        'recent_alerts': AlertEvent.objects.all()[:5],
        'recent_audits': AuditLog.objects.all()[:8],
        'current_role': user_role(request),
    }
    return render(request, 'devops/dashboard.html', content)


ALERT_METRIC_LABELS = {
    'collector': '采集失败',
    'cpu': 'CPU',
    'memory': '内存',
    'disk': '磁盘',
}
ALERT_LEVEL_LABELS = {
    AlertEvent.LEVEL_INFO: '信息',
    AlertEvent.LEVEL_WARNING: '警告',
    AlertEvent.LEVEL_CRITICAL: '严重',
}
ALERT_STATUS_LABELS = {
    AlertEvent.STATUS_OPEN: '未处理',
    AlertEvent.STATUS_PROCESSING: '处理中',
    AlertEvent.STATUS_RESOLVED: '已恢复',
    AlertEvent.STATUS_CLOSED: '已关闭',
    AlertEvent.STATUS_SILENCED: '已静默',
}


def alert_metric_label(metric):
    return ALERT_METRIC_LABELS.get(metric or '', metric or '未知')


def decorate_alert_event(alert):
    metric_label = alert_metric_label(alert.metric)
    alert.display_name = '%s告警' % metric_label
    alert.display_type = metric_label
    alert.display_level = ALERT_LEVEL_LABELS.get(alert.level, alert.level)
    alert.display_status = ALERT_STATUS_LABELS.get(alert.status, alert.status)
    alert.display_creator = '系统采集'
    return alert


@session_login_required
def vue_app(request):
    return render(request, 'devops/vue_app.html')


@session_login_required
def group_list(request):
    return render(request, 'devops/groups.html', {
        'groups': HostGroup.objects.all(),
        'form': HostGroupForm(),
        'tags': HostTag.objects.all(),
        'tag_form': HostTagForm(),
    })


@session_login_required
def group_create(request):
    denied = require_devops_role(request, DevOpsRole.ROLE_OPERATOR, MODULE_SECURITY)
    if denied:
        return denied
    if request.method != 'POST':
        return HttpResponseNotAllowed(['POST'])
    form = HostGroupForm(request.POST)
    if form.is_valid():
        group = form.save(commit=False)
        group.created_by = request.session.get('user_name')
        group.save()
        form.save_m2m()
        audit(request, '创建主机分组', 'HostGroup', group.id, group.name)
    return redirect('devops:group_list')


@session_login_required
def group_delete(request, id):
    denied = require_devops_role(request, DevOpsRole.ROLE_ADMIN, MODULE_SECURITY)
    if denied:
        return denied
    if request.method != 'POST':
        return HttpResponseNotAllowed(['POST'])
    group = get_object_or_404(HostGroup, id=id)
    audit(request, '删除主机分组', 'HostGroup', group.id, group.name)
    group.delete()
    return redirect('devops:group_list')


@session_login_required
def group_update(request, id):
    denied = require_devops_role(request, DevOpsRole.ROLE_OPERATOR, MODULE_SECURITY)
    if denied:
        return denied
    if request.method != 'POST':
        return HttpResponseNotAllowed(['POST'])
    group = get_object_or_404(HostGroup, id=id)
    form = HostGroupForm(request.POST, instance=group)
    if form.is_valid():
        group = form.save()
        audit(request, '更新主机分组', 'HostGroup', group.id, group.name)
    return redirect('devops:group_list')


@session_login_required
def tag_create(request):
    denied = require_devops_role(request, DevOpsRole.ROLE_OPERATOR, MODULE_SECURITY)
    if denied:
        return denied
    if request.method != 'POST':
        return HttpResponseNotAllowed(['POST'])
    form = HostTagForm(request.POST)
    if form.is_valid():
        tag = form.save(commit=False)
        tag.created_by = request.session.get('user_name')
        tag.save()
        form.save_m2m()
        audit(request, '创建主机标签', 'HostTag', tag.id, tag.name)
    return redirect('devops:group_list')


@session_login_required
def tag_update(request, id):
    denied = require_devops_role(request, DevOpsRole.ROLE_OPERATOR, MODULE_SECURITY)
    if denied:
        return denied
    if request.method != 'POST':
        return HttpResponseNotAllowed(['POST'])
    tag = get_object_or_404(HostTag, id=id)
    form = HostTagForm(request.POST, instance=tag)
    if form.is_valid():
        tag = form.save()
        audit(request, '更新主机标签', 'HostTag', tag.id, tag.name)
    return redirect('devops:group_list')


@session_login_required
def tag_delete(request, id):
    denied = require_devops_role(request, DevOpsRole.ROLE_ADMIN, MODULE_SECURITY)
    if denied:
        return denied
    if request.method != 'POST':
        return HttpResponseNotAllowed(['POST'])
    tag = get_object_or_404(HostTag, id=id)
    audit(request, '删除主机标签', 'HostTag', tag.id, tag.name)
    tag.delete()
    return redirect('devops:group_list')


@session_login_required
def command_center(request):
    hosts = visible_hosts_for_request(request)
    form = apply_host_queryset(CommandExecutionForm(), hosts)
    result = None
    if request.method == 'POST':
        denied = require_devops_role(request, DevOpsRole.ROLE_OPERATOR, MODULE_COMMAND)
        if denied:
            return denied
        form = apply_host_queryset(CommandExecutionForm(request.POST), hosts)
        if form.is_valid():
            decision, policy = evaluate_command_policy(form.cleaned_data['command'], user_role(request))
            if decision != COMMAND_ALLOWED:
                approval = create_command_approval(
                    form.cleaned_data['host'],
                    form.cleaned_data['command'],
                    request.session.get('user_name'),
                    command_denied_message(decision, policy),
                )
                audit(request, '高危命令转审批', 'ApprovalRequest', approval.id, approval.title)
                return redirect('devops:approvals')
            result = CommandExecution.objects.create(
                host=form.cleaned_data['host'],
                command=form.cleaned_data['command'],
                created_by=request.session.get('user_name'),
            )
            enqueue_background_job(execute_command_record, result, user_role(request))
            audit(request, '提交命令执行', 'CommandExecution', result.id, result.command)
    return render(request, 'devops/commands.html', {
        'form': form,
        'result': result,
        'records': CommandExecution.objects.filter(host__in=hosts)[:30],
    })


@session_login_required
def command_approval_create(request):
    denied = require_devops_role(request, DevOpsRole.ROLE_OPERATOR, MODULE_APPROVAL)
    if denied:
        return denied
    if request.method != 'POST':
        return HttpResponseNotAllowed(['POST'])
    form = apply_host_queryset(CommandApprovalForm(request.POST), visible_hosts_for_request(request))
    if form.is_valid():
        approval = create_command_approval(
            form.cleaned_data['host'],
            form.cleaned_data['command'],
            request.session.get('user_name'),
            form.cleaned_data['reason'],
        )
        audit(request, '提交命令审批', 'ApprovalRequest', approval.id, approval.title)
    return redirect('devops:approvals')


@session_login_required
def command_detail(request, id):
    record = get_object_or_404(CommandExecution, id=id)
    if not can_access_host(request, record.host):
        return host_forbidden(request, record.host.linux_name)
    return render(request, 'devops/command_detail.html', {
        'record': record,
        'runtime_config': {
            'retry_count': settings.DEVOPS_TASK_RETRY_COUNT,
            'ssh_timeout': settings.DEVOPS_SSH_CONNECT_TIMEOUT_SECONDS,
            'command_timeout': settings.DEVOPS_COMMAND_TIMEOUT_SECONDS,
        },
    })


@session_login_required
def batch_tasks(request):
    hosts = visible_hosts_for_request(request)
    form = apply_host_queryset(BatchTaskForm(), hosts)
    if request.method == 'POST':
        denied = require_devops_role(request, DevOpsRole.ROLE_OPERATOR, MODULE_TASK)
        if denied:
            return denied
        form = apply_host_queryset(BatchTaskForm(request.POST), hosts)
        if form.is_valid():
            task = BatchTask.objects.create(
                name=form.cleaned_data['name'],
                command=form.cleaned_data['command'],
                created_by=request.session.get('user_name'),
                status=BatchTask.STATUS_PENDING,
            )
            task.hosts.set(form.cleaned_data['hosts'])
            enqueue_background_job(execute_batch_task, task, user_role(request))
            audit(request, '提交批量任务', 'BatchTask', task.id, task.command)
            return redirect('devops:batch_tasks')
    return render(request, 'devops/tasks.html', {
        'form': form,
        'tasks': BatchTask.objects.filter(hosts__in=hosts).distinct()[:30],
    })


@session_login_required
def batch_task_detail(request, id):
    task = get_object_or_404(BatchTask, id=id)
    if not can_access_hosts(request, task.hosts.all()):
        return host_forbidden(request, task.name)
    return render(request, 'devops/task_detail.html', {
        'task': task,
        'results': task.results.select_related('host', 'command_execution'),
        'runtime_config': {
            'retry_count': settings.DEVOPS_TASK_RETRY_COUNT,
            'ssh_timeout': settings.DEVOPS_SSH_CONNECT_TIMEOUT_SECONDS,
            'command_timeout': settings.DEVOPS_COMMAND_TIMEOUT_SECONDS,
        },
    })


@session_login_required
def service_manage(request):
    hosts = visible_hosts_for_request(request)
    form = apply_host_queryset(ServiceOperationForm(), hosts)
    result = None
    if request.method == 'POST':
        denied = require_devops_role(request, DevOpsRole.ROLE_OPERATOR, MODULE_SERVICE)
        if denied:
            return denied
        form = apply_host_queryset(ServiceOperationForm(request.POST), hosts)
        if form.is_valid():
            command = service_command(form.cleaned_data['action'], form.cleaned_data['service_name'])
            command_record = CommandExecution.objects.create(
                host=form.cleaned_data['host'],
                command=command,
                created_by=request.session.get('user_name'),
            )
            command_record = execute_command_record(command_record, user_role(request))
            result = ServiceOperation.objects.create(
                host=form.cleaned_data['host'],
                service_name=form.cleaned_data['service_name'],
                action=form.cleaned_data['action'],
                status=command_record.status,
                output=command_record.output or command_record.error,
                created_by=request.session.get('user_name'),
            )
            audit(request, '服务操作', 'ServiceOperation', result.id, command)
    return render(request, 'devops/services.html', {
        'form': form,
        'result': result,
        'records': ServiceOperation.objects.filter(host__in=hosts)[:30],
    })


def topology_services_queryset(request):
    hosts = visible_hosts_for_request(request)
    services = ServiceCatalog.objects.filter(
        models.Q(hosts__in=hosts) | models.Q(hosts__isnull=True)
    ).distinct()
    return services.prefetch_related(
        models.Prefetch('hosts', queryset=hosts, to_attr='visible_hosts'),
        models.Prefetch(
            'upstream_links',
            queryset=ServiceDependency.objects.filter(
                upstream_service__in=services
            ).select_related('upstream_service'),
            to_attr='visible_upstream_links',
        ),
    )


def topology_service_choices(request):
    hosts = visible_hosts_for_request(request)
    return ServiceCatalog.objects.filter(
        models.Q(hosts__in=hosts) | models.Q(hosts__isnull=True)
    ).distinct()


def service_slo_queryset(request):
    return ServiceSlo.objects.select_related('service').filter(
        service__in=topology_service_choices(request)
    )


def service_slo_form(request, *args, **kwargs):
    form = ServiceSloForm(*args, **kwargs)
    form.fields['service'].queryset = topology_service_choices(request)
    return form


@session_login_required
def service_slos(request):
    can_manage = has_role(request, DevOpsRole.ROLE_ADMIN, DevOpsModulePermission.MODULE_SECURITY)
    if not can_manage:
        denied = require_devops_role(request, DevOpsRole.ROLE_VIEWER, MODULE_SERVICE)
        if denied:
            return denied
    if request.method == 'POST':
        if not can_manage:
            return HttpResponseForbidden('没有 SLO 管理权限')
        form = service_slo_form(request, request.POST)
        if form.is_valid():
            slo = form.save()
            audit(request, '创建服务SLO', 'ServiceSlo', slo.id, '%s:%s' % (slo.service.name, slo.metric_kind))
            return redirect('devops:service_slos')
        return render(request, 'devops/service_slos.html', {
            'slos': service_slo_queryset(request), 'form': form, 'can_manage': can_manage,
        }, status=400)
    if request.method != 'GET':
        return HttpResponseNotAllowed(['GET', 'POST'])
    editing_slo = None
    if can_manage and request.GET.get('edit'):
        editing_slo = get_object_or_404(service_slo_queryset(request), id=request.GET.get('edit'))
    return render(request, 'devops/service_slos.html', {
        'slos': service_slo_queryset(request),
        'form': service_slo_form(request, instance=editing_slo),
        'editing_slo': editing_slo,
        'can_manage': can_manage,
    })


@session_login_required
def service_slo_update(request, id):
    if request.method != 'POST':
        return HttpResponseNotAllowed(['POST'])
    denied = require_devops_role(request, DevOpsRole.ROLE_ADMIN, DevOpsModulePermission.MODULE_SECURITY)
    if denied:
        return denied
    slo = get_object_or_404(service_slo_queryset(request), id=id)
    form = service_slo_form(request, request.POST, instance=slo)
    if form.is_valid():
        slo = form.save()
        audit(request, '更新服务SLO', 'ServiceSlo', slo.id, '指标=%s, 启用=%s' % (slo.metric_kind, bool(slo.enabled)))
        return redirect('devops:service_slos')
    return render(request, 'devops/service_slos.html', {
        'slos': service_slo_queryset(request), 'form': form, 'editing_slo': slo, 'can_manage': True,
    }, status=400)


@session_login_required
def service_slo_evaluate(request, id):
    if request.method != 'POST':
        return HttpResponseNotAllowed(['POST'])
    denied = require_devops_role(request, DevOpsRole.ROLE_ADMIN, DevOpsModulePermission.MODULE_SECURITY)
    if denied:
        return denied
    slo = get_object_or_404(service_slo_queryset(request), id=id)
    result = evaluate_service_slo(slo)
    audit(request, '手动评估服务SLO', 'ServiceSlo', slo.id, '状态=%s' % result['state'])
    return redirect('devops:service_slos')


def runbook_queryset(request):
    return RunbookTemplate.objects.select_related('service').filter(
        allowed_hosts__in=visible_hosts_for_request(request)
    ).distinct()


def runbook_form(request, *args, **kwargs):
    form = RunbookTemplateForm(*args, **kwargs)
    form.fields['allowed_hosts'].queryset = visible_hosts_for_request(request)
    form.fields['service'].queryset = topology_service_choices(request)
    return form


@session_login_required
def runbooks(request):
    can_manage = has_role(request, DevOpsRole.ROLE_ADMIN, MODULE_SECURITY)
    can_initiate = has_role(request, DevOpsRole.ROLE_OPERATOR, MODULE_COMMAND)
    if not can_manage and not can_initiate:
        denied = require_devops_role(request, DevOpsRole.ROLE_VIEWER, MODULE_COMMAND)
        if denied:
            return denied
    if request.method == 'POST':
        if not can_manage:
            return HttpResponseForbidden('没有运行手册管理权限')
        form = runbook_form(request, request.POST)
        if form.is_valid():
            runbook = form.save(commit=False)
            runbook.created_by = request.session.get('user_name', '')
            runbook.save()
            form.save_m2m()
            audit(request, '创建受控运行手册', 'RunbookTemplate', runbook.id, '版本=%s, 启用=%s' % (runbook.version, bool(runbook.enabled)))
            return redirect('devops:runbooks')
        return render(request, 'devops/runbooks.html', {
            'runbooks': runbook_queryset(request), 'form': form, 'can_manage': can_manage, 'can_initiate': can_initiate,
        }, status=400)
    if request.method != 'GET':
        return HttpResponseNotAllowed(['GET', 'POST'])
    editing_runbook = None
    if can_manage and request.GET.get('edit'):
        editing_runbook = get_object_or_404(runbook_queryset(request), id=request.GET.get('edit'))
    return render(request, 'devops/runbooks.html', {
        'runbooks': runbook_queryset(request), 'form': runbook_form(request, instance=editing_runbook),
        'editing_runbook': editing_runbook, 'can_manage': can_manage, 'can_initiate': can_initiate,
        'visible_host_ids': set(visible_hosts_for_request(request).values_list('id', flat=True)),
    })


@session_login_required
def runbook_update(request, id):
    if request.method != 'POST':
        return HttpResponseNotAllowed(['POST'])
    denied = require_devops_role(request, DevOpsRole.ROLE_ADMIN, MODULE_SECURITY)
    if denied:
        return denied
    runbook = get_object_or_404(runbook_queryset(request), id=id)
    form = runbook_form(request, request.POST, instance=runbook)
    if form.is_valid():
        runbook = form.save()
        audit(request, '更新受控运行手册', 'RunbookTemplate', runbook.id, '版本=%s, 启用=%s' % (runbook.version, bool(runbook.enabled)))
        return redirect('devops:runbooks')
    return render(request, 'devops/runbooks.html', {
        'runbooks': runbook_queryset(request), 'form': form, 'editing_runbook': runbook,
        'can_manage': True, 'can_initiate': has_role(request, DevOpsRole.ROLE_OPERATOR, MODULE_COMMAND),
    }, status=400)


@session_login_required
def runbook_initiate(request, id):
    if request.method != 'POST':
        return HttpResponseNotAllowed(['POST'])
    runbook = get_object_or_404(runbook_queryset(request), id=id)
    try:
        host = visible_hosts_for_request(request).get(id=request.POST.get('host_id'))
        initiate_runbook(request, runbook, host)
    except (NewLinux.DoesNotExist, TypeError, ValueError, PermissionError):
        return HttpResponseForbidden('无法发起该运行手册')
    return redirect('devops:approvals')


def topology_service_form(request, *args, **kwargs):
    form = ServiceCatalogForm(
        *args,
        upstream_services_queryset=topology_service_choices(request),
        **kwargs
    )
    return apply_host_queryset(form, visible_hosts_for_request(request))


def save_service_topology_dependencies(service, upstream_services):
    ServiceDependency.objects.filter(service=service).delete()
    ServiceDependency.objects.bulk_create([
        ServiceDependency(service=service, upstream_service=upstream)
        for upstream in upstream_services
        if upstream.id != service.id
    ])


@session_login_required
def service_topology(request):
    denied = require_devops_role(request, DevOpsRole.ROLE_VIEWER, MODULE_SERVICE)
    if denied:
        return denied
    return render(request, 'devops/service_topology.html', {
        'services': topology_services_queryset(request),
        'create_form': topology_service_form(request),
        'can_manage': has_role(request, DevOpsRole.ROLE_OPERATOR, MODULE_SERVICE),
    })


@session_login_required
def service_topology_create(request):
    if request.method != 'POST':
        return HttpResponseNotAllowed(['POST'])
    denied = require_devops_role(request, DevOpsRole.ROLE_OPERATOR, MODULE_SERVICE)
    if denied:
        return denied
    form = topology_service_form(request, request.POST)
    if form.is_valid():
        service = form.save(commit=False)
        service.created_by = request.session.get('user_name')
        service.save()
        form.save_m2m()
        save_service_topology_dependencies(service, form.cleaned_data['upstream_services'])
        audit(request, '创建服务拓扑', 'ServiceCatalog', service.id, service.name)
        return redirect('devops:service_topology')
    return render(request, 'devops/service_topology.html', {
        'services': topology_services_queryset(request),
        'create_form': form,
        'can_manage': True,
    }, status=400)


@session_login_required
def service_topology_update(request, id):
    service = get_object_or_404(topology_services_queryset(request), id=id)
    if request.method == 'GET':
        denied = require_devops_role(request, DevOpsRole.ROLE_OPERATOR, MODULE_SERVICE)
        if denied:
            return denied
        return render(request, 'devops/service_topology.html', {
            'services': topology_services_queryset(request),
            'create_form': topology_service_form(request),
            'editing_service': service,
            'edit_form': topology_service_form(request, instance=service),
            'can_manage': True,
        })
    if request.method != 'POST':
        return HttpResponseNotAllowed(['GET', 'POST'])
    denied = require_devops_role(request, DevOpsRole.ROLE_OPERATOR, MODULE_SERVICE)
    if denied:
        return denied
    form = topology_service_form(request, request.POST, instance=service)
    if not form.is_valid():
        return render(request, 'devops/service_topology.html', {
            'services': topology_services_queryset(request),
            'create_form': topology_service_form(request),
            'editing_service': service,
            'edit_form': form,
            'can_manage': True,
        }, status=400)
    service = form.save()
    save_service_topology_dependencies(service, form.cleaned_data['upstream_services'])
    audit(request, '更新服务拓扑', 'ServiceCatalog', service.id, service.name)
    return redirect('devops:service_topology')


@session_login_required
def service_topology_delete(request, id):
    if request.method != 'POST':
        return HttpResponseNotAllowed(['POST'])
    denied = require_devops_role(request, DevOpsRole.ROLE_OPERATOR, MODULE_SERVICE)
    if denied:
        return denied
    service = get_object_or_404(topology_services_queryset(request), id=id)
    name = service.name
    service.delete()
    audit(request, '删除服务拓扑', 'ServiceCatalog', id, name)
    return redirect('devops:service_topology')


def project_onboarding_form(request, *args, **kwargs):
    form = ProjectOnboardingForm(*args, **kwargs)
    hosts = visible_hosts_for_request(request)
    form.fields['hosts'].queryset = hosts
    form.fields['groups'].queryset = HostGroup.objects.filter(
        models.Q(hosts__in=hosts) | models.Q(hosts__isnull=True)
    ).distinct()
    form.fields['tags'].queryset = HostTag.objects.filter(
        models.Q(hosts__in=hosts) | models.Q(hosts__isnull=True)
    ).distinct()
    form.fields['services'].queryset = topology_service_choices(request)
    form.fields['deployment_apps'].queryset = DeploymentApp.objects.all()
    return form


def visible_projects_queryset(request):
    hosts = visible_hosts_for_request(request)
    return DevOpsProject.objects.filter(
        models.Q(hosts__in=hosts) | models.Q(hosts__isnull=True)
    ).distinct().prefetch_related('hosts', 'groups', 'tags', 'services', 'deployment_apps')


@session_login_required
def project_onboarding(request):
    denied = require_devops_role(request, DevOpsRole.ROLE_ADMIN, MODULE_SECURITY)
    if denied:
        return denied
    if request.method == 'POST':
        form = project_onboarding_form(request, request.POST)
        if form.is_valid():
            create_project_onboarding(request, form.cleaned_data)
            return redirect('devops:project_onboarding')
        return render(request, 'devops/project_onboarding.html', {
            'form': form,
            'projects': visible_projects_queryset(request),
        }, status=400)
    if request.method != 'GET':
        return HttpResponseNotAllowed(['GET', 'POST'])
    return render(request, 'devops/project_onboarding.html', {
        'form': project_onboarding_form(request),
        'projects': visible_projects_queryset(request),
    })


def metric_percent(value):
    try:
        number = float(value)
    except (TypeError, ValueError):
        return 0
    if number <= 1:
        number *= 100
    return number


@session_login_required
def metrics_history(request):
    denied = require_devops_role(request, DevOpsRole.ROLE_VIEWER, MODULE_METRIC)
    if denied:
        return denied
    hosts = list(visible_hosts_for_request(request))
    selected_host_id = request.GET.get('host') or (str(hosts[0].id) if hosts else '')
    range_key = request.GET.get('range') or '24h'
    range_map = {
        '6h': ('最近 6 小时', timedelta(hours=6)),
        '24h': ('最近 24 小时', timedelta(hours=24)),
        '7d': ('最近 7 天', timedelta(days=7)),
        '30d': ('最近 30 天', timedelta(days=30)),
    }
    if range_key not in range_map:
        range_key = '24h'
    range_label, range_delta = range_map[range_key]
    since = timezone.now() - range_delta

    latest_map = latest_metric_map(hosts)
    host_metrics = []
    for host in hosts:
        cpu = latest_map.get((host.id, MetricSample.METRIC_CPU))
        memory = latest_map.get((host.id, MetricSample.METRIC_MEMORY))
        disk = latest_map.get((host.id, MetricSample.METRIC_DISK))
        host_metrics.append({
            'host': host,
            'cpu': cpu,
            'cpu_percent': metric_percent(cpu.value) if cpu else None,
            'memory': memory,
            'memory_percent': metric_percent(memory.value) if memory else None,
            'disk': disk,
            'disk_percent': metric_percent(disk.value) if disk else None,
        })
    samples = MetricSample.objects.select_related('host').filter(host__in=hosts)[:100]
    sample_rows = []
    for sample in samples:
        sample_rows.append({
            'sample': sample,
            'value_percent': metric_percent(sample.value),
        })

    selected_host = None
    for host in hosts:
        if str(host.id) == str(selected_host_id):
            selected_host = host
            break

    chart_data = {
        'labels': [],
        'series': {
            MetricSample.METRIC_CPU: [],
            MetricSample.METRIC_MEMORY: [],
            MetricSample.METRIC_DISK: [],
        },
        'range_label': range_label,
        'host_name': selected_host.linux_name if selected_host else '',
    }
    if selected_host:
        trend_samples = MetricSample.objects.filter(
            host=selected_host,
            collected_at__gte=since,
        ).order_by('collected_at', 'metric')
        points = {}
        for sample in trend_samples:
            label = timezone.localtime(sample.collected_at).strftime('%m-%d %H:%M')
            if label not in points:
                points[label] = {}
            points[label][sample.metric] = metric_percent(sample.value)
        chart_data['labels'] = list(points.keys())
        for label in chart_data['labels']:
            values = points[label]
            for metric in chart_data['series']:
                chart_data['series'][metric].append(values.get(metric))

    return render(request, 'devops/metrics.html', {
        'hosts': hosts,
        'selected_host_id': selected_host_id,
        'range_key': range_key,
        'range_options': [
            ('6h', '最近 6 小时'),
            ('24h', '最近 24 小时'),
            ('7d', '最近 7 天'),
            ('30d', '最近 30 天'),
        ],
        'host_metrics': host_metrics,
        'sample_rows': sample_rows,
        'chart_json': json.dumps(chart_data),
    })


@session_login_required
def file_distributions(request):
    hosts = visible_hosts_for_request(request)
    form = apply_host_queryset(FileDistributionForm(), hosts)
    if request.method == 'POST':
        denied = require_devops_role(request, DevOpsRole.ROLE_OPERATOR, MODULE_FILE)
        if denied:
            return denied
        form = apply_host_queryset(FileDistributionForm(request.POST, request.FILES), hosts)
        if form.is_valid():
            distribution = form.save(commit=False)
            distribution.created_by = request.session.get('user_name')
            distribution.status = FileDistribution.STATUS_PENDING
            distribution.save()
            form.save_m2m()
            enqueue_background_job(execute_file_distribution, distribution)
            audit(request, '提交文件分发', 'FileDistribution', distribution.id, distribution.remote_path)
            return redirect('devops:file_distributions')
    return render(request, 'devops/files.html', {
        'form': form,
        'records': FileDistribution.objects.filter(hosts__in=hosts).distinct()[:30],
    })


@session_login_required
def file_distribution_detail(request, id):
    distribution = get_object_or_404(FileDistribution, id=id)
    if not can_access_hosts(request, distribution.hosts.all()):
        return host_forbidden(request, distribution.name)
    return render(request, 'devops/file_detail.html', {
        'distribution': distribution,
        'results': distribution.results.select_related('host'),
    })


@session_login_required
def deployments(request):
    app_form = DeploymentAppForm()
    hosts = visible_hosts_for_request(request)
    release_form = apply_host_queryset(DeploymentReleaseForm(), hosts)
    preview = None
    if request.method == 'POST':
        denied = require_devops_role(request, DevOpsRole.ROLE_OPERATOR, MODULE_DEPLOYMENT)
        if denied:
            return denied
        if request.POST.get('form_type') == 'app':
            app_form = DeploymentAppForm(request.POST)
            if app_form.is_valid():
                app = app_form.save(commit=False)
                app.created_by = request.session.get('user_name')
                app.save()
                audit(request, '创建部署应用', 'DeploymentApp', app.id, app.name)
                return redirect('devops:deployments')
        else:
            release_form = apply_host_queryset(DeploymentReleaseForm(request.POST), hosts)
            if release_form.is_valid():
                if request.POST.get('submit_mode') == 'preview':
                    preview = deployment_risk_preview(release_form.cleaned_data['hosts'])
                else:
                    settings_obj = DevOpsSetting.current()
                    submit_for_approval = request.POST.get('submit_mode') == 'approval' or settings_obj.force_deploy_approval
                    release = release_form.save(commit=False)
                    release.created_by = request.session.get('user_name')
                    release.status = (
                        DeploymentRelease.STATUS_PENDING
                        if submit_for_approval
                        else DeploymentRelease.STATUS_RUNNING
                    )
                    release.save()
                    release_form.save_m2m()
                    maintenance_approval = require_deployment_maintenance_approval(
                        release,
                        requester=request.session.get('user_name'),
                    )
                    slo_approval = require_deployment_slo_approval(
                        release,
                        requester=request.session.get('user_name'),
                    )
                    approval_required = maintenance_approval or slo_approval
                    if submit_for_approval or approval_required:
                        if approval_required and release.status != DeploymentRelease.STATUS_PENDING:
                            release.status = DeploymentRelease.STATUS_PENDING
                            release.save(update_fields=['status'])
                        approval = create_deployment_approval(
                            release,
                            request.session.get('user_name'),
                            release.description,
                        ) if not approval_required else approval_required
                        audit(request, '提交发布审批', 'ApprovalRequest', approval.id, approval.title)
                    else:
                        enqueue_background_job(execute_deployment_release, release, user_role(request))
                        audit(request, '提交发布', 'DeploymentRelease', release.id, release.version)
                    return redirect('devops:deployments')
    return render(request, 'devops/deployments.html', {
        'app_form': app_form,
        'release_form': release_form,
        'apps': DeploymentApp.objects.all(),
        'releases': DeploymentRelease.objects.select_related('app').filter(hosts__in=hosts).distinct()[:30],
        'preview': preview,
    })


@session_login_required
def deployment_detail(request, id):
    release = get_object_or_404(DeploymentRelease, id=id)
    if not can_access_hosts(request, release.hosts.all()):
        return host_forbidden(request, str(release))
    return render(request, 'devops/deployment_detail.html', {
        'release': release,
        'results': release.results.select_related('host', 'command_execution'),
    })


@session_login_required
def deployment_rollback(request, id):
    denied = require_devops_role(request, DevOpsRole.ROLE_OPERATOR, MODULE_DEPLOYMENT)
    if denied:
        return denied
    if request.method != 'POST':
        return HttpResponseNotAllowed(['POST'])
    release = get_object_or_404(DeploymentRelease, id=id)
    if not can_access_hosts(request, release.hosts.all()):
        return host_forbidden(request, str(release))
    settings_obj = DevOpsSetting.current()
    if settings_obj.force_rollback_approval:
        approval = create_rollback_approval(
            release,
            request.session.get('user_name'),
            '回滚需要审批',
        )
        audit(request, '提交回滚审批', 'ApprovalRequest', approval.id, approval.title)
        return redirect('devops:approvals')
    enqueue_background_job(execute_deployment_rollback, release, user_role(request))
    audit(request, '提交回滚', 'DeploymentRelease', release.id, release.version)
    return redirect('devops:deployment_detail', id=release.id)


def maintenance_window_datetime(value):
    """Parse the browser's local datetime input without accepting offsets."""
    try:
        parsed = datetime.strptime(value or '', '%Y-%m-%dT%H:%M')
    except (TypeError, ValueError):
        return None
    return timezone.make_aware(parsed, timezone.get_current_timezone())


def maintenance_window_scope(request, posted_hosts, posted_services):
    """Resolve selected targets and ensure each remains in the caller's scope."""
    try:
        host_ids = [int(item) for item in posted_hosts]
        service_ids = [int(item) for item in posted_services]
    except (TypeError, ValueError):
        return None, None
    if len(set(host_ids)) != len(host_ids) or len(set(service_ids)) != len(service_ids):
        return None, None
    hosts = list(NewLinux.objects.filter(id__in=host_ids))
    services = list(ServiceCatalog.objects.filter(id__in=service_ids).prefetch_related('hosts'))
    if len(hosts) != len(host_ids) or len(services) != len(service_ids):
        return None, None
    if not can_access_hosts(request, hosts):
        return None, None
    for service in services:
        if not can_access_hosts(request, service.hosts.all()):
            return None, None
    return hosts, services


def can_manage_maintenance_window(request, window):
    targets = list(window.hosts.all())
    for service in window.services.prefetch_related('hosts'):
        service_hosts = list(service.hosts.all())
        # A service without topology cannot be safely scoped to this user.
        if not service_hosts:
            return False
        targets.extend(service_hosts)
    return bool(targets) and can_access_hosts(request, targets)


@session_login_required
def maintenance_windows(request):
    denied = require_devops_role(request, DevOpsRole.ROLE_ADMIN, MODULE_SECURITY)
    if denied:
        return denied
    hosts = visible_hosts_for_request(request)
    if request.method == 'POST':
        starts_at = maintenance_window_datetime(request.POST.get('starts_at'))
        ends_at = maintenance_window_datetime(request.POST.get('ends_at'))
        name = (request.POST.get('name') or '').strip()
        reason = (request.POST.get('reason') or '').strip()
        selected_hosts, selected_services = maintenance_window_scope(
            request, request.POST.getlist('hosts'), request.POST.getlist('services'))
        if (not name or len(name) > 120 or len(reason) > 500 or not starts_at or
                not ends_at or ends_at <= starts_at or not (selected_hosts or selected_services)):
            return HttpResponseBadRequest('维护窗口参数无效')
        window = MaintenanceWindow(
            name=name,
            reason=reason,
            starts_at=starts_at,
            ends_at=ends_at,
            enabled=request.POST.get('enabled') == 'on',
            created_by=request.session.get('user_name', ''),
        )
        window.full_clean()
        window.save()
        window.hosts.set(selected_hosts)
        window.services.set(selected_services)
        audit(request, '创建维护窗口', 'MaintenanceWindow', window.id, window.name)
        return redirect('devops:maintenance_windows')
    return render(request, 'devops/maintenance_windows.html', {
        'windows': [window for window in MaintenanceWindow.objects.prefetch_related(
            'hosts', 'services__hosts').all() if can_manage_maintenance_window(request, window)][:100],
        'hosts': hosts,
        'services': ServiceCatalog.objects.prefetch_related('hosts').all(),
    })


@session_login_required
def maintenance_window_toggle(request, id):
    denied = require_devops_role(request, DevOpsRole.ROLE_ADMIN, MODULE_SECURITY)
    if denied:
        return denied
    if request.method != 'POST':
        return HttpResponseNotAllowed(['POST'])
    window = get_object_or_404(MaintenanceWindow, id=id)
    if not can_manage_maintenance_window(request, window):
        return host_forbidden(request, window.name)
    window.enabled = not window.enabled
    window.save(update_fields=['enabled', 'updated_at'])
    audit(request, '切换维护窗口', 'MaintenanceWindow', window.id, window.name)
    return redirect('devops:maintenance_windows')


@session_login_required
def approvals(request):
    denied = require_devops_role(request, DevOpsRole.ROLE_VIEWER, MODULE_APPROVAL)
    if denied:
        return denied
    hosts = visible_hosts_for_request(request)
    approvals_qs = ApprovalRequest.objects.select_related('host', 'deployment_release').filter(
        models.Q(host__in=hosts) |
        models.Q(host__isnull=True, deployment_release__hosts__in=hosts) |
        models.Q(host__isnull=True, deployment_release__isnull=True)
    ).distinct()
    return render(request, 'devops/approvals.html', {
        'command_form': apply_host_queryset(CommandApprovalForm(), hosts),
        'decision_form': ApprovalDecisionForm(),
        'approvals': approvals_qs[:100],
    })


@session_login_required
def approval_decide(request, id):
    denied = require_devops_role(request, DevOpsRole.ROLE_ADMIN, MODULE_APPROVAL)
    if denied:
        return denied
    if request.method != 'POST':
        return HttpResponseNotAllowed(['POST'])
    approval = get_object_or_404(ApprovalRequest, id=id)
    if not can_decide_deployment_approval(request, approval):
        return host_forbidden(request, approval.title)
    if approval.status != ApprovalRequest.STATUS_PENDING:
        return redirect('devops:approvals')
    current_user = request.session.get('user_name', '')
    if approval.requester and approval.requester == current_user:
        approval.comment = '申请人与审批人不能为同一人'
        approval.save(update_fields=['comment'])
        audit(request, '审批拒绝：申请人自审', 'ApprovalRequest', approval.id, approval.title)
        return redirect('devops:approvals')
    form = ApprovalDecisionForm(request.POST)
    if form.is_valid():
        approval.approver = current_user
        approval.comment = form.cleaned_data['comment']
        approval.decided_at = timezone.now()
        if form.cleaned_data['action'] == 'reject':
            approval.status = ApprovalRequest.STATUS_REJECTED
            approval.save()
            notify_approval(approval, '拒绝')
            audit(request, '拒绝审批', 'ApprovalRequest', approval.id, approval.title)
            return redirect('devops:approvals')
        approval.status = ApprovalRequest.STATUS_APPROVED
        approval.save()
        execute_approval_request(approval, user_role(request))
        audit(request, '批准审批并执行', 'ApprovalRequest', approval.id, approval.title)
    return redirect('devops:approvals')


@session_login_required
def alert_events(request):
    denied = require_devops_role(request, DevOpsRole.ROLE_VIEWER, MODULE_ALERT)
    if denied:
        return denied
    alerts = AlertEvent.objects.select_related('host').all()
    metric = request.GET.get('metric', '').strip()
    status = request.GET.get('status', '').strip()
    level = request.GET.get('level', '').strip()
    host = request.GET.get('host', '').strip()
    keyword = request.GET.get('q', '').strip()
    if metric:
        alerts = alerts.filter(metric=metric)
    if status:
        alerts = alerts.filter(status=status)
    if level:
        alerts = alerts.filter(level=level)
    if host:
        alerts = alerts.filter(host_id=host)
    if keyword:
        metric_matches = [
            key for key, value in ALERT_METRIC_LABELS.items()
            if (
                keyword.lower() in value.lower()
                or keyword.lower() in ('%s告警' % value).lower()
                or keyword.lower() in key.lower()
            )
        ]
        level_matches = [
            key for key, value in ALERT_LEVEL_LABELS.items()
            if keyword.lower() in value.lower() or keyword.lower() in key.lower()
        ]
        status_matches = [
            key for key, value in ALERT_STATUS_LABELS.items()
            if keyword.lower() in value.lower() or keyword.lower() in key.lower()
        ]
        creator_query = models.Q()
        if keyword.lower() in '系统采集':
            creator_query = models.Q(id__isnull=False)
        alerts = alerts.filter(
            models.Q(message__icontains=keyword)
            | models.Q(metric__icontains=keyword)
            | models.Q(metric__in=metric_matches)
            | models.Q(level__in=level_matches)
            | models.Q(status__in=status_matches)
            | models.Q(handler__icontains=keyword)
            | models.Q(host__linux_name__icontains=keyword)
            | models.Q(host__linux_ip__icontains=keyword)
            | creator_query
        )
    alert_items = [decorate_alert_event(alert) for alert in alerts[:100]]
    return render(request, 'devops/alerts.html', {
        'alerts': alert_items,
        'silences': AlertSilence.objects.all()[:20],
        'silence_form': AlertSilenceForm(),
        'hosts': NewLinux.objects.all().order_by('linux_name', 'linux_ip'),
        'filters': {
            'metric': metric,
            'status': status,
            'level': level,
            'host': host,
            'q': keyword,
        },
        'total': alerts.count(),
        'open_count': AlertEvent.objects.filter(status=AlertEvent.STATUS_OPEN).count(),
        'processing_count': AlertEvent.objects.filter(status=AlertEvent.STATUS_PROCESSING).count(),
        'resolved_count': AlertEvent.objects.filter(status=AlertEvent.STATUS_RESOLVED).count(),
        'collector_open_count': AlertEvent.objects.filter(
            metric='collector',
            status__in=[AlertEvent.STATUS_OPEN, AlertEvent.STATUS_PROCESSING, AlertEvent.STATUS_SILENCED],
        ).count(),
    })


@session_login_required
def incidents_page(request):
    denied = require_devops_role(request, DevOpsRole.ROLE_VIEWER, MODULE_ALERT)
    if denied:
        return denied
    return render(request, 'devops/incidents.html', {
        'can_operate_incidents': has_role(request, DevOpsRole.ROLE_OPERATOR, MODULE_ALERT),
    })


@session_login_required
def alert_update(request, id):
    alert = get_object_or_404(AlertEvent, id=id)
    if request.method == 'POST':
        denied = require_devops_role(request, DevOpsRole.ROLE_OPERATOR, MODULE_ALERT)
        if denied:
            return denied
        form = AlertEventForm(request.POST, instance=alert)
        if form.is_valid():
            from_status = AlertEvent.objects.get(id=alert.id).status
            alert = update_alert_status(
                alert,
                form.cleaned_data['status'],
                form.cleaned_data['handler'],
                form.cleaned_data['remark'],
                from_status=from_status,
            )
            audit(request, '更新告警事件', 'AlertEvent', alert.id, alert.status)
    next_url = request.POST.get('next')
    return redirect(safe_next_url(request, next_url, 'devops:alert_events'))


@session_login_required
def silence_create(request):
    denied = require_devops_role(request, DevOpsRole.ROLE_OPERATOR, MODULE_ALERT)
    if denied:
        return denied
    if request.method != 'POST':
        return HttpResponseNotAllowed(['POST'])
    form = AlertSilenceForm(request.POST)
    if form.is_valid():
        silence = form.save(commit=False)
        silence.created_by = request.session.get('user_name')
        silence.save()
        audit(request, '创建告警静默', 'AlertSilence', silence.id, silence.reason)
    return redirect('devops:alert_events')


@session_login_required
def silence_delete(request, id):
    denied = require_devops_role(request, DevOpsRole.ROLE_ADMIN, MODULE_ALERT)
    if denied:
        return denied
    if request.method != 'POST':
        return HttpResponseNotAllowed(['POST'])
    silence = get_object_or_404(AlertSilence, id=id)
    audit(request, '删除告警静默', 'AlertSilence', silence.id, silence.reason)
    silence.delete()
    return redirect('devops:alert_events')


@session_login_required
def security_settings(request):
    denied = require_devops_role(request, DevOpsRole.ROLE_VIEWER, MODULE_SECURITY)
    if denied:
        return denied
    settings_obj = DevOpsSetting.current()
    visible_hosts = visible_hosts_for_request(request)
    can_manage = has_role(request, DevOpsRole.ROLE_ADMIN, MODULE_SECURITY)
    edit_baseline = None
    if can_manage and request.GET.get('edit'):
        edit_baseline = get_object_or_404(ComplianceBaseline, id=request.GET.get('edit'))
    results = ComplianceResult.objects.select_related('baseline', 'host').filter(host__in=visible_hosts)
    return render(request, 'devops/security.html', {
        'policy_form': CommandPolicyForm(),
        'role_form': DevOpsRoleForm(),
        'module_permission_form': DevOpsModulePermissionForm(),
        'module_permission_clear_form': DevOpsModulePermissionClearForm(),
        'host_scope_form': DevOpsHostScopeForm(),
        'setting_form': DevOpsSettingForm(instance=settings_obj),
        'settings_obj': settings_obj,
        'policies': CommandPolicy.objects.all(),
        'roles': DevOpsRole.objects.select_related('user'),
        'module_permissions': DevOpsModulePermission.objects.select_related('user'),
        'host_scopes': DevOpsHostScope.objects.select_related('user').prefetch_related('groups', 'tags'),
        'compliance_form': ComplianceBaselineForm(instance=edit_baseline) if can_manage else None,
        'compliance_edit_baseline': edit_baseline,
        'compliance_baselines': ComplianceBaseline.objects.prefetch_related('hosts') if can_manage else (),
        'compliance_results': results,
        'can_manage_compliance': can_manage,
        'can_manage_security': can_manage,
    })


@session_login_required
def compliance_baseline_create(request):
    denied = require_devops_role(request, DevOpsRole.ROLE_ADMIN, MODULE_SECURITY)
    if denied:
        return denied
    if request.method != 'POST':
        return HttpResponseNotAllowed(['POST'])
    form = ComplianceBaselineForm(request.POST)
    if form.is_valid():
        baseline = form.save(commit=False)
        baseline.created_by = request.session.get('user_name', '')
        baseline.save()
        form.save_m2m()
        audit(request, '创建合规基线', 'ComplianceBaseline', baseline.id, baseline.name)
    return redirect('devops:security_settings')


@session_login_required
def compliance_baseline_delete(request, id):
    denied = require_devops_role(request, DevOpsRole.ROLE_ADMIN, MODULE_SECURITY)
    if denied:
        return denied
    if request.method != 'POST':
        return HttpResponseNotAllowed(['POST'])
    baseline = get_object_or_404(ComplianceBaseline, id=id)
    for host in baseline.hosts.all():
        resolve_alert(host, 'compliance:%s' % baseline.id, '合规基线已删除')
    audit(request, '删除合规基线', 'ComplianceBaseline', baseline.id, baseline.name)
    baseline.delete()
    return redirect('devops:security_settings')


@session_login_required
def compliance_baseline_update(request, id):
    denied = require_devops_role(request, DevOpsRole.ROLE_ADMIN, MODULE_SECURITY)
    if denied:
        return denied
    if request.method != 'POST':
        return HttpResponseNotAllowed(['POST'])
    baseline = get_object_or_404(ComplianceBaseline, id=id)
    form = ComplianceBaselineForm(request.POST, instance=baseline)
    if form.is_valid():
        form.save()
        audit(request, '更新合规基线', 'ComplianceBaseline', baseline.id, baseline.name)
    return redirect('devops:security_settings')


@session_login_required
def compliance_baseline_scan(request, id):
    denied = require_devops_role(request, DevOpsRole.ROLE_ADMIN, MODULE_SECURITY)
    if denied:
        return denied
    if request.method != 'POST':
        return HttpResponseNotAllowed(['POST'])
    baseline = get_object_or_404(ComplianceBaseline, id=id)
    scan_compliance_baseline(baseline)
    audit(request, '手动扫描合规基线', 'ComplianceBaseline', baseline.id, baseline.name)
    return redirect('devops:security_settings')


@session_login_required
def setting_update(request):
    denied = require_devops_role(request, DevOpsRole.ROLE_ADMIN, MODULE_SECURITY)
    if denied:
        return denied
    if request.method != 'POST':
        return HttpResponseNotAllowed(['POST'])
    settings_obj = DevOpsSetting.current()
    form = DevOpsSettingForm(request.POST, instance=settings_obj)
    if form.is_valid():
        settings_obj = form.save(commit=False)
        settings_obj.updated_by = request.session.get('user_name')
        settings_obj.save()
        audit(request, '更新DevOps审批策略', 'DevOpsSetting', settings_obj.id, '')
    return redirect('devops:security_settings')


@session_login_required
def policy_create(request):
    denied = require_devops_role(request, DevOpsRole.ROLE_ADMIN, MODULE_SECURITY)
    if denied:
        return denied
    if request.method != 'POST':
        return HttpResponseNotAllowed(['POST'])
    form = CommandPolicyForm(request.POST)
    if form.is_valid():
        policy = form.save(commit=False)
        policy.created_by = request.session.get('user_name')
        policy.save()
        audit(request, '创建命令策略', 'CommandPolicy', policy.id, policy.pattern)
    return redirect('devops:security_settings')


@session_login_required
def policy_update(request, id):
    denied = require_devops_role(request, DevOpsRole.ROLE_ADMIN, MODULE_SECURITY)
    if denied:
        return denied
    if request.method != 'POST':
        return HttpResponseNotAllowed(['POST'])
    policy = get_object_or_404(CommandPolicy, id=id)
    form = CommandPolicyForm(request.POST, instance=policy)
    if form.is_valid():
        policy = form.save()
        audit(request, '更新命令策略', 'CommandPolicy', policy.id, policy.pattern)
    return redirect('devops:security_settings')


@session_login_required
def role_set(request):
    denied = require_devops_role(request, DevOpsRole.ROLE_ADMIN, MODULE_SECURITY)
    if denied:
        return denied
    if request.method != 'POST':
        return HttpResponseNotAllowed(['POST'])
    form = DevOpsRoleForm(request.POST)
    if form.is_valid():
        role, created = DevOpsRole.objects.update_or_create(
            user=form.cleaned_data['user'],
            defaults={'role': form.cleaned_data['role']},
        )
        audit(request, '设置DevOps角色', 'DevOpsRole', role.id, role_audit_detail(role, created))
    return redirect('devops:security_settings')


@session_login_required
def module_permission_set(request):
    denied = require_devops_role(request, DevOpsRole.ROLE_ADMIN, MODULE_SECURITY)
    if denied:
        return denied
    if request.method != 'POST':
        return HttpResponseNotAllowed(['POST'])
    form = DevOpsModulePermissionForm(request.POST)
    if form.is_valid():
        permission, created = DevOpsModulePermission.objects.update_or_create(
            user=form.cleaned_data['user'],
            module=form.cleaned_data['module'],
            defaults={
                'role': form.cleaned_data['role'],
                'created_by': request.session.get('user_name'),
            },
        )
        audit(request, '设置模块权限', 'DevOpsModulePermission', permission.id, module_permission_audit_detail(permission, created))
    return redirect('devops:security_settings')


@session_login_required
def module_permission_revoke(request, id):
    denied = require_devops_role(request, DevOpsRole.ROLE_ADMIN, MODULE_SECURITY)
    if denied:
        return denied
    if request.method != 'POST':
        return HttpResponseNotAllowed(['POST'])
    permission = get_object_or_404(DevOpsModulePermission, id=id)
    revoke_module_permission(request, permission)
    return redirect('devops:security_settings')


@session_login_required
def module_permissions_clear(request):
    denied = require_devops_role(request, DevOpsRole.ROLE_ADMIN, MODULE_SECURITY)
    if denied:
        return denied
    if request.method != 'POST':
        return HttpResponseNotAllowed(['POST'])
    form = DevOpsModulePermissionClearForm(request.POST)
    if form.is_valid():
        clear_module_permissions(request, form.cleaned_data['user'])
    return redirect('devops:security_settings')


@session_login_required
def host_scope_set(request):
    denied = require_devops_role(request, DevOpsRole.ROLE_ADMIN, MODULE_SECURITY)
    if denied:
        return denied
    if request.method != 'POST':
        return HttpResponseNotAllowed(['POST'])
    form = DevOpsHostScopeForm(request.POST)
    if form.is_valid():
        scope, created = DevOpsHostScope.objects.update_or_create(
            user=form.cleaned_data['user'],
            defaults={'created_by': request.session.get('user_name')},
        )
        scope.groups.set(form.cleaned_data['groups'])
        scope.tags.set(form.cleaned_data['tags'])
        audit(request, '设置主机范围', 'DevOpsHostScope', scope.id, host_scope_audit_detail(scope, created))
    return redirect('devops:security_settings')


@session_login_required
def notification_channels(request):
    denied = require_devops_role(request, DevOpsRole.ROLE_VIEWER, MODULE_SECURITY)
    if denied:
        return denied
    logs = NotificationLog.objects.select_related('channel')
    channel_id = request.GET.get('channel')
    event_type = request.GET.get('event_type')
    status = request.GET.get('status')
    channels = NotificationChannel.objects.all()
    if channel_id:
        try:
            channel_id = int(channel_id)
        except (TypeError, ValueError):
            return HttpResponseBadRequest('通知渠道参数无效')
        if not channels.filter(id=channel_id).exists():
            return HttpResponseBadRequest('通知渠道参数无效')
        logs = logs.filter(channel_id=channel_id)
    valid_events = [choice[0] for choice in NotificationLog.EVENT_CHOICES]
    if event_type and event_type not in valid_events:
        return HttpResponseBadRequest('通知事件类型无效')
    if event_type:
        logs = logs.filter(event_type=event_type)
    valid_statuses = [choice[0] for choice in NotificationLog.STATUS_CHOICES]
    if status and status not in valid_statuses:
        return HttpResponseBadRequest('通知状态无效')
    if status:
        logs = logs.filter(status=status)
    templates = {}
    for item in NotificationTemplate.objects.all():
        templates[item.event_type] = NotificationTemplateForm(instance=item)
    template_rows = []
    for event, label in NotificationTemplate.EVENT_CHOICES:
        if event not in templates:
            templates[event] = NotificationTemplateForm()
        template_rows.append({'event': event, 'label': label, 'form': templates[event]})
    escalation = AlertNotificationEscalation.current()
    return render(request, 'devops/notifications.html', {
        'form': NotificationChannelForm(),
        'channels': channels,
        'logs': logs[:50],
        'template_rows': template_rows,
        'template_events': NotificationTemplate.EVENT_CHOICES,
        'escalation_form': AlertNotificationEscalationForm(instance=escalation),
        'selected_channel': channel_id,
        'selected_event_type': event_type,
        'selected_status': status,
    })


@session_login_required
def integration_health(request):
    denied = require_devops_role(request, DevOpsRole.ROLE_ADMIN, MODULE_SECURITY)
    if denied:
        return denied
    from monitor.models import AlertmanagerConfig, PrometheusConfig
    from .api import configured_integration_health, notification_health_summary
    return render(request, 'devops/integration_health.html', {
        'github': summarize_integration_health(
            IntegrationHealthEvent.TYPE_GITHUB_INBOUND,
            source_name=IntegrationHealthEvent.SOURCE_GITHUB_INBOUND,
        ),
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


@session_login_required
def worker_observability(request):
    denied = require_devops_role(request, DevOpsRole.ROLE_ADMIN, MODULE_SECURITY)
    if denied:
        return denied
    from .api import worker_observability_payload
    return render(request, 'devops/worker_observability.html', {
        'worker': worker_observability_payload(),
    })


@session_login_required
def notification_create(request):
    denied = require_devops_role(request, DevOpsRole.ROLE_ADMIN, MODULE_SECURITY)
    if denied:
        return denied
    if request.method != 'POST':
        return HttpResponseNotAllowed(['POST'])
    form = NotificationChannelForm(request.POST)
    if form.is_valid():
        channel = form.save(commit=False)
        channel.created_by = request.session.get('user_name')
        channel.save()
        audit(request, '创建通知渠道', 'NotificationChannel', channel.id, notification_channel_audit_detail(channel, '创建'))
    return redirect('devops:notification_channels')


@session_login_required
def notification_update(request, id):
    denied = require_devops_role(request, DevOpsRole.ROLE_ADMIN, MODULE_SECURITY)
    if denied:
        return denied
    if request.method != 'POST':
        return HttpResponseNotAllowed(['POST'])
    channel = get_object_or_404(NotificationChannel, id=id)
    form = NotificationChannelForm(request.POST, instance=channel)
    if form.is_valid():
        channel = form.save()
        audit(request, '更新通知渠道', 'NotificationChannel', channel.id, notification_channel_audit_detail(channel, '更新'))
    return redirect('devops:notification_channels')


@session_login_required
def notification_delete(request, id):
    denied = require_devops_role(request, DevOpsRole.ROLE_ADMIN, MODULE_SECURITY)
    if denied:
        return denied
    if request.method != 'POST':
        return HttpResponseNotAllowed(['POST'])
    channel = get_object_or_404(NotificationChannel, id=id)
    audit(request, '删除通知渠道', 'NotificationChannel', channel.id, notification_channel_audit_detail(channel, '删除'))
    channel.delete()
    return redirect('devops:notification_channels')


@session_login_required
def notification_test(request, id):
    denied = require_devops_role(request, DevOpsRole.ROLE_ADMIN, MODULE_SECURITY)
    if denied:
        return denied
    if request.method != 'POST':
        return HttpResponseNotAllowed(['POST'])
    channel = get_object_or_404(NotificationChannel, id=id)
    send_notification_channel(
        channel,
        NotificationLog.EVENT_TEST,
        'DevOps 通知测试',
        '这是一条来自 DevOps 平台的测试消息',
    )
    audit(request, '测试通知渠道', 'NotificationChannel', channel.id, channel.name)
    return redirect('devops:notification_channels')


@session_login_required
def notification_template_update(request, event_type):
    denied = require_devops_role(request, DevOpsRole.ROLE_ADMIN, MODULE_SECURITY)
    if denied:
        return denied
    if request.method != 'POST':
        return HttpResponseNotAllowed(['POST'])
    valid_events = [choice[0] for choice in NotificationTemplate.EVENT_CHOICES]
    if event_type not in valid_events:
        raise Http404
    template, unused_created = NotificationTemplate.objects.get_or_create(event_type=event_type)
    form = NotificationTemplateForm(request.POST, instance=template)
    if form.is_valid():
        template = form.save(commit=False)
        template.updated_by = request.session.get('user_name')
        template.save()
        audit(request, '更新通知模板', 'NotificationTemplate', template.id,
              notification_governance_audit_detail('更新模板', '事件=%s' % event_type))
    return redirect('devops:notification_channels')


@session_login_required
def notification_escalation_update(request):
    denied = require_devops_role(request, DevOpsRole.ROLE_ADMIN, MODULE_SECURITY)
    if denied:
        return denied
    if request.method != 'POST':
        return HttpResponseNotAllowed(['POST'])
    escalation = AlertNotificationEscalation.current()
    form = AlertNotificationEscalationForm(request.POST, instance=escalation)
    if form.is_valid():
        escalation = form.save(commit=False)
        escalation.updated_by = request.session.get('user_name')
        escalation.save()
        audit(request, '更新告警升级规则', 'AlertNotificationEscalation', escalation.id,
              notification_governance_audit_detail('更新升级规则', '启用=%s, 最低级别=%s, 渠道=%s' % (
                  bool(escalation.enabled), escalation.minimum_level,
                  escalation.channel.name if escalation.channel else '-',
              )))
    return redirect('devops:notification_channels')


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


def _prometheus_rule_message(result):
    code = (result or {}).get('code', '')
    if code == 'ok':
        return (result or {}).get('message', '操作成功。')
    return PROMETHEUS_RULE_SAFE_MESSAGES.get(code, '无法操作 PrometheusRule，请稍后重试。')


def _prometheus_rule_failure_status(code):
    if code == 'crd_not_found':
        return 404
    if code in ('invalid_yaml', 'invalid_identity'):
        return 400
    if code == 'conflict':
        return 409
    return 503


def _prometheus_rule_audit_outcome(code):
    if code in PROMETHEUS_RULE_SAFE_MESSAGES:
        return code
    return 'offline'


def _prometheus_rule_audit_detail(cluster, namespace, name, action, outcome, resource_version=''):
    return '集群=%s, 集群名称=%s, 命名空间=%s, 规则=%s, 操作=%s, 结果=%s, 资源版本=%s' % (
        cluster.id, cluster.name, namespace, name, action, outcome, resource_version or '-',
    )


def _prometheus_rule_page_context(request, cluster=None, rules=None, selected_rule=None,
                                  yaml_text='', yaml_form=None, delete_form=None, error=''):
    return {
        'clusters': K8sCluster.objects.all(),
        'selected_cluster': cluster,
        'rules': rules or [],
        'selected_rule': selected_rule,
        'yaml_text': yaml_text,
        'yaml_form': yaml_form,
        'delete_form': delete_form,
        'error': error,
        'can_manage': has_role(request, DevOpsRole.ROLE_ADMIN, MODULE_CLUSTER),
    }


def _prometheus_rule_detail_context(request, cluster, namespace, name, yaml_text='', yaml_form=None,
                                    delete_form=None, error='', resource_version=''):
    selected_rule = {'namespace': namespace, 'name': name, 'resource_version': resource_version}
    return _prometheus_rule_page_context(
        request,
        cluster=cluster,
        selected_rule=selected_rule,
        yaml_text=yaml_text,
        yaml_form=yaml_form or PrometheusRuleYamlForm(initial={'yaml': yaml_text}),
        delete_form=delete_form or PrometheusRuleDeleteForm(),
        error=error,
    )


@session_login_required
def prometheus_rules(request):
    denied = require_devops_role(request, DevOpsRole.ROLE_VIEWER, MODULE_CLUSTER)
    if denied:
        return denied
    if request.method != 'GET':
        return HttpResponseNotAllowed(['GET'])
    cluster_id = request.GET.get('cluster')
    if not cluster_id:
        return render(request, 'devops/prometheus_rules.html', _prometheus_rule_page_context(request))
    try:
        cluster_id = int(cluster_id)
    except (TypeError, ValueError):
        return HttpResponseBadRequest('集群参数无效。')
    if cluster_id <= 0:
        return HttpResponseBadRequest('集群参数无效。')
    cluster = get_object_or_404(K8sCluster, id=cluster_id)
    result = list_prometheus_rules(cluster)
    error = '' if result.get('ok') else _prometheus_rule_message(result)
    return render(request, 'devops/prometheus_rules.html', _prometheus_rule_page_context(
        request, cluster=cluster, rules=result.get('rules', []), error=error,
    ), status=200 if result.get('ok') else _prometheus_rule_failure_status(result.get('code', 'offline')))


@session_login_required
def prometheus_rule_detail(request, cluster_id, namespace, name):
    denied = require_devops_role(request, DevOpsRole.ROLE_VIEWER, MODULE_CLUSTER)
    if denied:
        return denied
    if request.method != 'GET':
        return HttpResponseNotAllowed(['GET'])
    namespace, name = normalize_prometheus_rule_identity(namespace, name)
    if not namespace or not name:
        return HttpResponseBadRequest('规则命名空间或名称无效。')
    cluster = get_object_or_404(K8sCluster, id=cluster_id)
    result = get_prometheus_rule(cluster, namespace, name)
    if not result.get('ok'):
        return render(
            request, 'devops/prometheus_rules.html',
            _prometheus_rule_detail_context(request, cluster, namespace, name, error=_prometheus_rule_message(result)),
            status=_prometheus_rule_failure_status(result.get('code', 'offline')),
        )
    return render(
        request, 'devops/prometheus_rules.html',
        _prometheus_rule_detail_context(
            request, cluster, namespace, name, yaml_text=result.get('yaml', ''),
            resource_version=((result.get('rule') or {}).get('metadata') or {}).get('resourceVersion', ''),
        ),
    )


@session_login_required
def prometheus_rule_update(request, cluster_id, namespace, name):
    denied = require_devops_role(request, DevOpsRole.ROLE_ADMIN, MODULE_CLUSTER)
    if denied:
        return denied
    if request.method != 'POST':
        return HttpResponseNotAllowed(['POST'])
    namespace, name = normalize_prometheus_rule_identity(namespace, name)
    if not namespace or not name:
        return HttpResponseBadRequest('规则命名空间或名称无效。')
    cluster = get_object_or_404(K8sCluster, id=cluster_id)
    form = PrometheusRuleYamlForm(request.POST)
    if not form.is_valid():
        return render(
            request, 'devops/prometheus_rules.html',
            _prometheus_rule_detail_context(request, cluster, namespace, name, yaml_form=form),
            status=400,
        )
    yaml_text = form.cleaned_data['yaml']
    result = replace_prometheus_rule(cluster, namespace, name, yaml_text)
    code = result.get('code', 'offline')
    if result.get('ok'):
        resource_version = normalize_prometheus_rule_resource_version(
            ((result.get('rule') or {}).get('metadata') or {}).get('resourceVersion', ''),
        )
        audit(request, '更新PrometheusRule', 'K8sCluster', cluster.id,
              _prometheus_rule_audit_detail(cluster, namespace, name, 'update', 'ok', resource_version))
        return redirect('devops:prometheus_rule_detail', cluster_id=cluster.id, namespace=namespace, name=name)
    audit(request, '更新PrometheusRule', 'K8sCluster', cluster.id,
          _prometheus_rule_audit_detail(cluster, namespace, name, 'update', _prometheus_rule_audit_outcome(code)))
    status = _prometheus_rule_failure_status(code)
    return render(
        request, 'devops/prometheus_rules.html',
        _prometheus_rule_detail_context(request, cluster, namespace, name, yaml_text=yaml_text,
                                        yaml_form=form, error=_prometheus_rule_message(result)),
        status=status,
    )


@session_login_required
def prometheus_rule_delete(request, cluster_id, namespace, name):
    denied = require_devops_role(request, DevOpsRole.ROLE_ADMIN, MODULE_CLUSTER)
    if denied:
        return denied
    if request.method != 'POST':
        return HttpResponseNotAllowed(['POST'])
    namespace, name = normalize_prometheus_rule_identity(namespace, name)
    resource_version = normalize_prometheus_rule_resource_version(request.POST.get('resource_version'))
    if not namespace or not name or not resource_version:
        return HttpResponseBadRequest('规则命名空间、名称或资源版本无效。')
    cluster = get_object_or_404(K8sCluster, id=cluster_id)
    form = PrometheusRuleDeleteForm(request.POST)
    if not form.is_valid():
        return render(
            request, 'devops/prometheus_rules.html',
            _prometheus_rule_detail_context(
                request, cluster, namespace, name, delete_form=form,
                resource_version=request.POST.get('resource_version', ''),
            ),
            status=400,
        )
    resource_version = form.cleaned_data['resource_version']
    result = delete_prometheus_rule(cluster, namespace, name, resource_version)
    code = result.get('code', 'offline')
    audit(request, '删除PrometheusRule', 'K8sCluster', cluster.id,
          _prometheus_rule_audit_detail(cluster, namespace, name, 'delete',
                                        'ok' if result.get('ok') else _prometheus_rule_audit_outcome(code),
                                        resource_version))
    if result.get('ok'):
        return redirect('%s?cluster=%s' % (reverse('devops:prometheus_rules'), cluster.id))
    status = _prometheus_rule_failure_status(code)
    return render(
        request, 'devops/prometheus_rules.html',
        _prometheus_rule_detail_context(
            request, cluster, namespace, name, delete_form=form,
            error=_prometheus_rule_message(result), resource_version=resource_version,
        ),
        status=status,
    )


def cluster_count_context(request):
    clusters = K8sCluster.objects.all()
    return {
        'cluster_count': clusters.count(),
        'online_count': clusters.filter(status=K8sCluster.STATUS_ONLINE).count(),
        'offline_count': clusters.filter(status=K8sCluster.STATUS_OFFLINE).count(),
        'unknown_count': clusters.filter(status=K8sCluster.STATUS_UNKNOWN).count(),
        'can_manage': has_role(request, DevOpsRole.ROLE_ADMIN, MODULE_CLUSTER),
    }


def cluster_list_context(request, form=None, editing_cluster=None):
    context = cluster_count_context(request)
    context.update({
        'clusters': K8sCluster.objects.all(),
        'form': form,
        'editing_cluster': editing_cluster,
    })
    return context


def _save_k8s_cluster_connection(request, form):
    cluster = form.save(commit=False)
    cluster.created_by = request.session.get('user_name', '')
    cluster.save()
    audit(request, '创建K8s集群', 'K8sCluster', cluster.id, '名称=%s' % cluster.name)
    return cluster


@session_login_required
def clusters(request):
    denied = require_devops_role(request, DevOpsRole.ROLE_VIEWER, MODULE_CLUSTER)
    if denied:
        return denied
    if request.method != 'GET':
        return HttpResponseNotAllowed(['GET'])
    return render(request, 'devops/cluster_management.html', cluster_count_context(request))


@session_login_required
def cluster_connect(request):
    denied = require_devops_role(request, DevOpsRole.ROLE_ADMIN, MODULE_CLUSTER)
    if denied:
        return denied
    if request.method != 'GET':
        return HttpResponseNotAllowed(['GET'])
    return render(request, 'devops/cluster_connection.html', {
        'form': K8sClusterConnectionForm(),
        'can_manage': True,
    })


@session_login_required
def cluster_list(request):
    denied = require_devops_role(request, DevOpsRole.ROLE_VIEWER, MODULE_CLUSTER)
    if denied:
        return denied
    if request.method != 'GET':
        return HttpResponseNotAllowed(['GET'])
    return render(request, 'devops/cluster_list.html', cluster_list_context(request))


@session_login_required
def cluster_create(request):
    denied = require_devops_role(request, DevOpsRole.ROLE_ADMIN, MODULE_CLUSTER)
    if denied:
        return denied
    if request.method != 'POST':
        return HttpResponseNotAllowed(['POST'])
    form = K8sClusterConnectionForm(request.POST, request.FILES)
    if not form.is_valid():
        return render(request, 'devops/cluster_connection.html', {
            'form': form,
            'can_manage': True,
        }, status=400)
    _save_k8s_cluster_connection(request, form)
    return redirect('devops:cluster_list')


@session_login_required
def cluster_connect_test(request):
    denied = require_devops_role(request, DevOpsRole.ROLE_ADMIN, MODULE_CLUSTER)
    if denied:
        return denied
    if request.method != 'POST':
        return HttpResponseNotAllowed(['POST'])
    form = K8sClusterConnectionForm(request.POST, request.FILES)
    if not form.is_valid():
        return render(request, 'devops/cluster_connection.html', {
            'form': form,
            'can_manage': True,
        }, status=400)
    cluster = _save_k8s_cluster_connection(request, form)
    success, _message = test_k8s_cluster_connection(cluster)
    audit(
        request,
        '测试K8s集群连接',
        'K8sCluster',
        cluster.id,
        '名称=%s, 状态=%s' % (cluster.name, 'online' if success else 'offline'),
    )
    return redirect('devops:cluster_list')


@session_login_required
def cluster_update(request, id):
    denied = require_devops_role(request, DevOpsRole.ROLE_ADMIN, MODULE_CLUSTER)
    if denied:
        return denied
    if request.method != 'POST':
        return HttpResponseNotAllowed(['POST'])
    cluster = get_object_or_404(K8sCluster, id=id)
    old_kubeconfig = cluster.decrypted_kubeconfig
    form = K8sClusterForm(request.POST, instance=cluster)
    if not form.is_valid():
        return render(
            request,
            'devops/cluster_list.html',
            cluster_list_context(request, form, editing_cluster=cluster),
            status=400,
        )
    cluster = form.save()
    clear_k8s_detail_cache(cluster.id, old_kubeconfig)
    clear_k8s_detail_cache(cluster.id, cluster.decrypted_kubeconfig)
    audit(request, '更新K8s集群', 'K8sCluster', cluster.id, '名称=%s' % cluster.name)
    return redirect('devops:cluster_list')


@session_login_required
def cluster_delete(request, id):
    denied = require_devops_role(request, DevOpsRole.ROLE_ADMIN, MODULE_CLUSTER)
    if denied:
        return denied
    if request.method != 'POST':
        return HttpResponseNotAllowed(['POST'])
    cluster = get_object_or_404(K8sCluster, id=id)
    cluster_id = cluster.id
    cluster_name = cluster.name
    clear_k8s_detail_cache(cluster.id, cluster.decrypted_kubeconfig)
    cluster.delete()
    audit(request, '删除K8s集群', 'K8sCluster', cluster_id, '名称=%s' % cluster_name)
    return redirect('devops:cluster_list')


@session_login_required
def cluster_test(request, id):
    denied = require_devops_role(request, DevOpsRole.ROLE_ADMIN, MODULE_CLUSTER)
    if denied:
        return denied
    if request.method != 'POST':
        return HttpResponseNotAllowed(['POST'])
    cluster = get_object_or_404(K8sCluster, id=id)
    success, _message = test_k8s_cluster_connection(cluster)
    audit(
        request,
        '测试K8s集群连接',
        'K8sCluster',
        cluster.id,
        '名称=%s, 状态=%s' % (cluster.name, 'online' if success else 'offline'),
    )
    return redirect('devops:cluster_list')


@session_login_required
def k8s_cluster_detail(request, id):
    denied = require_devops_role(request, DevOpsRole.ROLE_VIEWER, MODULE_CLUSTER)
    if denied:
        return denied
    cluster = get_object_or_404(K8sCluster, id=id)
    active_resource = (request.GET.get('resource') or 'deployments').strip().lower()
    valid_resources = [key for key, _label in K8S_DETAIL_RESOURCE_TYPES]
    if active_resource not in valid_resources:
        active_resource = 'deployments'
    workload_resource_keys = [key for key, _label in K8S_WORKLOAD_RESOURCE_TABS]
    is_workload_resource = active_resource in workload_resource_keys
    is_overview_resource = active_resource == 'overview'
    is_namespace_resource = active_resource == 'namespaces'
    show_namespace_switcher = active_resource in K8S_NAMESPACED_RESOURCE_KEYS
    resource_group = ''
    secondary_tab_definitions = ()
    for group_key, group_tabs in (
        ('service', K8S_SERVICE_RESOURCE_TABS),
        ('storage', K8S_STORAGE_RESOURCE_TABS),
        ('config', K8S_CONFIG_RESOURCE_TABS),
    ):
        if active_resource in [key for key, _label in group_tabs]:
            resource_group = group_key
            secondary_tab_definitions = group_tabs
            break
    selected_namespace = clean_k8s_namespace(request.GET.get('namespace'), cluster.default_namespace)
    if active_resource in K8S_CLUSTER_SCOPED_RESOURCE_KEYS:
        selected_namespace = clean_k8s_namespace('', cluster.default_namespace)
    query = (request.GET.get('q') or '').strip()[:100]
    refresh_requested = request.GET.get('refresh') == '1'
    can_refresh = has_role(request, DevOpsRole.ROLE_ADMIN, MODULE_CLUSTER)
    if refresh_requested and not can_refresh:
        return HttpResponseForbidden('只有 K8s 集群管理员可以强制刷新数据')

    if cluster.status == K8sCluster.STATUS_OFFLINE and not refresh_requested:
        detail = {
            'overview': {
                'ok': False,
                'message': K8S_OFFLINE_DETAIL_MESSAGE,
                'version': '',
                'namespace': selected_namespace,
                'resources': {},
                'resource_errors': {},
                'resource_matches': [],
            },
            'namespace_result': {
                'ok': False,
                'message': K8S_OFFLINE_DETAIL_MESSAGE,
                'namespaces': [{'name': selected_namespace, 'status': 'Unknown'}],
            },
            'from_cache': False,
        }
    else:
        detail = load_cached_k8s_cluster_detail(
            cluster.id,
            cluster.decrypted_kubeconfig,
            selected_namespace,
            refresh=refresh_requested,
        )
    overview = detail.get('overview') or {}
    namespace_result = detail.get('namespace_result') or {}
    all_resources = overview.get('resources') or {}
    if is_namespace_resource:
        resources = [
            {
                'kind': 'Namespace',
                'name': item.get('name'),
                'status': item.get('status') or '-',
                'replicas': '-',
                'namespace': '-',
                'created_at': item.get('created_at') or '-',
                'detail': '集群级资源',
                'labels': item.get('labels') or '-',
            }
            for item in namespace_result.get('namespaces', []) or []
        ]
    else:
        resources = all_resources.get(active_resource, []) or []
    if is_workload_resource:
        resources = attach_k8s_matched_resources(
            resources,
            overview.get('resource_matches') or [],
            all_resources.get('pods', []) or [],
            all_resources.get('services', []) or [],
        )
    else:
        resources = [safe_k8s_view_resource(item) for item in resources]
    if query:
        lowered = query.lower()
        filtered = []
        for item in resources:
            search_values = [item.get(key) for key in K8S_SAFE_VIEW_FIELDS]
            if is_workload_resource:
                for pod in item.get('matched_pods', []) or []:
                    search_values.extend(pod.get(key) for key in K8S_SAFE_VIEW_FIELDS)
                for service in item.get('matched_services', []) or []:
                    search_values.extend(service.get(key) for key in K8S_SAFE_VIEW_FIELDS)
            if lowered in ' '.join(str(value or '') for value in search_values).lower():
                filtered.append(item)
        resources = filtered

    namespace_options = []
    for item in namespace_result.get('namespaces', []) or []:
        name = (item.get('name') or '').strip().lower()
        if (
            name
            and len(name) <= 63
            and re.match(r'^[a-z0-9]([-a-z0-9]*[a-z0-9])?$', name)
            and name not in namespace_options
        ):
            namespace_options.append(name)
    if selected_namespace not in namespace_options:
        namespace_options.insert(0, selected_namespace)

    overview_resource_counts = [
        {'key': key, 'label': label, 'count': len(all_resources.get(key, []) or [])}
        for key, label in K8S_OVERVIEW_RESOURCE_COUNTS
    ]
    cluster_summary = dict(overview.get('cluster_capacity') or {})
    cluster_summary.update({
        'namespace_count': len(namespace_options),
        'resource_count': sum(item['count'] for item in overview_resource_counts),
        'version': overview.get('version') or '-',
        'selected_namespace': selected_namespace,
    })

    paginator = Paginator(resources, 20)
    resource_page = paginator.get_page(request.GET.get('page'))
    resources = list(resource_page.object_list)

    resource_tabs = []
    active_tab_definitions = K8S_WORKLOAD_RESOURCE_TABS if is_workload_resource else secondary_tab_definitions
    for key, label in active_tab_definitions:
        resource_tabs.append({
            'key': key,
            'label': label,
            'count': len(all_resources.get(key, []) or []),
            'active': key == active_resource,
            'namespace': selected_namespace,
            'query': query,
        })
    refresh_params = {'resource': active_resource, 'namespace': selected_namespace, 'refresh': '1'}
    if query:
        refresh_params['q'] = query
    pagination_params = {'resource': active_resource, 'namespace': selected_namespace}
    if query:
        pagination_params['q'] = query
    load_message = (
        namespace_result.get('message') if is_namespace_resource
        else overview.get('message') or namespace_result.get('message')
    ) or ''
    from_cache = bool(detail.get('from_cache'))
    return render(request, 'devops/k8s_cluster_detail.html', {
        'cluster': cluster,
        'overview': overview,
        'resource_tabs': resource_tabs,
        'active_resource': active_resource,
        'active_resource_label': dict(K8S_DETAIL_RESOURCE_TYPES)[active_resource],
        'is_workload_resource': is_workload_resource,
        'is_overview_resource': is_overview_resource,
        'is_namespace_resource': is_namespace_resource,
        'show_namespace_switcher': show_namespace_switcher,
        'resource_group': resource_group,
        'show_resource_tabs': bool(active_tab_definitions),
        'workload_resource_keys': workload_resource_keys,
        'cluster_summary': cluster_summary,
        'overview_resource_counts': overview_resource_counts,
        'resources': resources,
        'workloads': resources,
        'resource_page': resource_page,
        'pagination_query': urlparse.urlencode(pagination_params),
        'query': query,
        'selected_namespace': selected_namespace,
        'namespace_options': namespace_options,
        'load_message': load_message,
        'from_cache': from_cache,
        'k8s_detail_from_cache': from_cache,
        'refresh_query': urlparse.urlencode(refresh_params),
        'resource_error': (
            namespace_result.get('message', '') if is_namespace_resource and not namespace_result.get('ok')
            else (overview.get('resource_errors') or {}).get(active_resource, '')
        ),
        'can_refresh': can_refresh,
    })


@session_login_required
def k8s_node_detail(request, id, node_name):
    denied = require_devops_role(request, DevOpsRole.ROLE_VIEWER, MODULE_CLUSTER)
    if denied:
        return denied
    if (
        not node_name
        or len(node_name) > 253
        or not re.match(r'^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$', node_name)
    ):
        raise Http404('Node 不存在')
    cluster = get_object_or_404(K8sCluster, id=id)
    refresh_requested = request.GET.get('refresh') == '1'
    can_refresh = has_role(request, DevOpsRole.ROLE_ADMIN, MODULE_CLUSTER)
    if refresh_requested and not can_refresh:
        return HttpResponseForbidden('只有 K8s 集群管理员可以强制刷新数据')

    if cluster.status == K8sCluster.STATUS_OFFLINE and not refresh_requested:
        detail = {
            'ok': False,
            'message': K8S_OFFLINE_DETAIL_MESSAGE,
            'metrics_message': '',
            'node': {'name': node_name},
            'summary': {'pod_total': 0},
            'pods': [],
            'from_cache': False,
        }
    else:
        detail = load_cached_k8s_node_detail(
            cluster.id,
            cluster.decrypted_kubeconfig,
            node_name,
            refresh=refresh_requested,
        )

    query = (request.GET.get('q') or '').strip()[:100]
    node = dict(detail.get('node') or {'name': node_name})
    node['created_at'] = clean_k8s_created_at(node.get('created_at'))
    pods = []
    for item in detail.get('pods') or []:
        pod = dict(item)
        pod['created_at'] = clean_k8s_created_at(pod.get('created_at'))
        pods.append(pod)
    if query:
        lowered = query.lower()
        pods = [
            item for item in pods
            if lowered in ' '.join(str(item.get(key) or '') for key in (
                'name', 'namespace', 'status', 'pod_ip', 'cpu_request', 'cpu_limit',
                'memory_request', 'memory_limit',
            )).lower()
        ]
    pod_page = Paginator(pods, 20).get_page(request.GET.get('page'))
    pagination_params = {}
    if query:
        pagination_params['q'] = query
    refresh_params = {'refresh': '1'}
    if query:
        refresh_params['q'] = query
    return render(request, 'devops/k8s_node_detail.html', {
        'cluster': cluster,
        'node_name': node_name,
        'node': node,
        'summary': detail.get('summary') or {'pod_total': 0},
        'pod_page': pod_page,
        'pods': list(pod_page.object_list),
        'query': query,
        'load_message': detail.get('message') or '',
        'metrics_message': detail.get('metrics_message') or '',
        'detail_ok': bool(detail.get('ok')),
        'from_cache': bool(detail.get('from_cache')),
        'can_refresh': can_refresh,
        'pagination_query': urlparse.urlencode(pagination_params),
        'refresh_query': urlparse.urlencode(refresh_params),
    })


@session_login_required
def audit_logs(request):
    denied = require_devops_role(request, DevOpsRole.ROLE_VIEWER, MODULE_AUDIT)
    if denied:
        return denied
    logs = AuditLog.objects.all()
    keyword = request.GET.get('q', '').strip()
    user = request.GET.get('user', '').strip()
    action = request.GET.get('action', '').strip()
    target_type = request.GET.get('target_type', '').strip()
    start = request.GET.get('start', '').strip()
    end = request.GET.get('end', '').strip()
    if keyword:
        logs = logs.filter(
            models.Q(action__icontains=keyword)
            | models.Q(target_type__icontains=keyword)
            | models.Q(target_id__icontains=keyword)
            | models.Q(detail__icontains=keyword)
            | models.Q(ip_address__icontains=keyword)
        )
    if user:
        logs = logs.filter(user__icontains=user)
    if action:
        logs = logs.filter(action__icontains=action)
    if target_type:
        logs = logs.filter(target_type__icontains=target_type)
    if start:
        logs = logs.filter(created_at__gte=start)
    if end:
        logs = logs.filter(created_at__lte=end)

    if request.GET.get('export') == 'csv':
        response = HttpResponse(content_type='text/csv; charset=utf-8')
        response['Content-Disposition'] = 'attachment; filename="audit-logs.csv"'
        response.write('\ufeff')
        writer = csv.writer(response)
        writer.writerow(['时间', '用户', '动作', '对象类型', '对象ID', '详情', 'IP'])
        for log in logs[:5000]:
            writer.writerow([
                csv_safe_cell(timezone.localtime(log.created_at).strftime('%Y-%m-%d %H:%M:%S')),
                csv_safe_cell(log.user),
                csv_safe_cell(log.action),
                csv_safe_cell(log.target_type),
                csv_safe_cell(log.target_id),
                csv_safe_cell(log.detail),
                csv_safe_cell(log.ip_address),
            ])
        return response

    return render(request, 'devops/audit.html', {
        'logs': logs[:100],
        'filters': {
            'q': keyword,
            'user': user,
            'action': action,
            'target_type': target_type,
            'start': start,
            'end': end,
        },
        'total': logs.count(),
    })
