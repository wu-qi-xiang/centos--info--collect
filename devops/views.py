import csv
import json
from datetime import timedelta

from django.conf import settings
from django.db import models
from django.http import HttpResponse, HttpResponseForbidden, HttpResponseNotAllowed
from django.shortcuts import get_object_or_404, redirect, render
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
    DevOpsHostScopeForm,
    DevOpsModulePermissionForm,
    DevOpsSettingForm,
    DeploymentAppForm,
    DeploymentReleaseForm,
    DevOpsRoleForm,
    FileDistributionForm,
    HostGroupForm,
    HostTagForm,
    NotificationChannelForm,
    ServiceOperationForm,
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
    MetricSample,
    NotificationChannel,
    NotificationLog,
    ServiceOperation,
)
from .services import (
    COMMAND_ALLOWED,
    audit,
    can_access_host,
    can_access_hosts,
    command_denied_message,
    create_command_approval,
    create_deployment_approval,
    create_rollback_approval,
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
    notify_approval,
    send_notification_channel,
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
                if submit_for_approval:
                    approval = create_deployment_approval(
                        release,
                        request.session.get('user_name'),
                        release.description,
                    )
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
        alerts = alerts.filter(
            models.Q(message__icontains=keyword)
            | models.Q(metric__icontains=keyword)
            | models.Q(host__linux_name__icontains=keyword)
            | models.Q(host__linux_ip__icontains=keyword)
        )
    return render(request, 'devops/alerts.html', {
        'alerts': alerts[:100],
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
        'collector_open_count': AlertEvent.objects.filter(
            metric='collector',
            status__in=[AlertEvent.STATUS_OPEN, AlertEvent.STATUS_PROCESSING, AlertEvent.STATUS_SILENCED],
        ).count(),
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
    return render(request, 'devops/security.html', {
        'policy_form': CommandPolicyForm(),
        'role_form': DevOpsRoleForm(),
        'module_permission_form': DevOpsModulePermissionForm(),
        'host_scope_form': DevOpsHostScopeForm(),
        'setting_form': DevOpsSettingForm(instance=settings_obj),
        'settings_obj': settings_obj,
        'policies': CommandPolicy.objects.all(),
        'roles': DevOpsRole.objects.select_related('user'),
        'module_permissions': DevOpsModulePermission.objects.select_related('user'),
        'host_scopes': DevOpsHostScope.objects.select_related('user').prefetch_related('groups', 'tags'),
    })


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
    return render(request, 'devops/notifications.html', {
        'form': NotificationChannelForm(),
        'channels': NotificationChannel.objects.all(),
        'logs': NotificationLog.objects.select_related('channel')[:50],
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
