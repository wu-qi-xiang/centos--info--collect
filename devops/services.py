import base64
import hashlib
import hmac
import json
import time
import posixpath
import shlex
from threading import Thread
try:
    from urllib import parse as urlparse
except ImportError:
    import urllib.parse as urlparse
try:
    from urllib import request as urlrequest
except ImportError:
    import urllib.request as urlrequest

from django.conf import settings
from django.db import models
from django.utils import timezone
try:
    import requests
except ImportError:
    class _UrlLibResponse(object):
        def __init__(self, response):
            self.status_code = response.getcode()
            self.text = response.read().decode('utf-8', errors='ignore')

    class _UrlLibRequests(object):
        @staticmethod
        def post(url, json=None, timeout=5):
            data = None
            if json is not None:
                data = globals()['json_module'].dumps(json).encode('utf-8')
            req = urlrequest.Request(
                url,
                data=data,
                headers={'Content-Type': 'application/json'},
            )
            return _UrlLibResponse(urlrequest.urlopen(req, timeout=timeout))

    requests = _UrlLibRequests()
json_module = json

from RemoteLinux.ssh_utils import create_host_ssh_client, describe_ssh_error
from .models import (
    AlertEvent,
    AlertHistory,
    AlertSilence,
    ApprovalRequest,
    AuditLog,
    BatchTask,
    BatchTaskResult,
    CommandExecution,
    CommandPolicy,
    DeploymentRelease,
    DeploymentResult,
    DevOpsHostScope,
    DevOpsModulePermission,
    DevOpsRole,
    FileDistribution,
    FileDistributionResult,
    MetricSample,
    NotificationChannel,
    NotificationLog,
)
from RemoteLinux.models import NewLinux


DANGEROUS_COMMANDS = (
    'mkfs',
    'dd if=',
    ':(){',
)

SYSTEM_POWER_COMMANDS = ('shutdown', 'reboot', 'halt', 'poweroff')

COMMAND_ALLOWED = 'allow'
COMMAND_BLOCKED = 'blocked'
COMMAND_ADMIN_REQUIRED = 'admin_required'


ROLE_RANKS = {
    DevOpsRole.ROLE_VIEWER: 1,
    DevOpsRole.ROLE_OPERATOR: 2,
    DevOpsRole.ROLE_ADMIN: 3,
}


def claim_pending_work(model_class, obj, running_status):
    updated = model_class.objects.filter(
        id=obj.id,
        status=model_class.STATUS_PENDING,
    ).update(status=running_status)
    obj.refresh_from_db()
    return bool(updated)


def claim_running_deployment_if_empty(release, action):
    if release.status != DeploymentRelease.STATUS_RUNNING:
        return False
    has_results = DeploymentResult.objects.filter(release=release, action=action).exists()
    if has_results:
        return False
    release.refresh_from_db()
    return release.status == DeploymentRelease.STATUS_RUNNING


def claim_deployment_rollback(release):
    rollbackable_statuses = (
        DeploymentRelease.STATUS_SUCCESS,
        DeploymentRelease.STATUS_PARTIAL,
        DeploymentRelease.STATUS_FAILED,
    )
    updated = DeploymentRelease.objects.filter(
        id=release.id,
        status__in=rollbackable_statuses,
    ).update(status=DeploymentRelease.STATUS_RUNNING)
    release.refresh_from_db()
    return bool(updated)


def enqueue_background_job(target, *args, **kwargs):
    if getattr(settings, 'DEVOPS_SYNC_TASKS', False):
        return target(*args, **kwargs)
    thread = Thread(target=run_background_job, args=(target, args, kwargs))
    thread.daemon = True
    thread.start()
    return thread


def mark_background_failure(target, args, exc):
    message = '后台任务异常：%s' % exc
    target_name = getattr(target, '__name__', str(target))
    obj = args[0] if args else None
    AuditLog.objects.create(
        user='system',
        action='后台任务异常',
        target_type=obj.__class__.__name__ if obj else target_name,
        target_id=str(getattr(obj, 'id', '') or ''),
        detail='%s: %s' % (target_name, message),
    )
    if isinstance(obj, CommandExecution):
        obj.status = CommandExecution.STATUS_FAILED
        obj.error = message
        obj.finished_at = timezone.now()
        obj.save(update_fields=['status', 'error', 'finished_at'])
        return
    if isinstance(obj, BatchTask):
        obj.status = BatchTask.STATUS_FAILED
        obj.summary = message[:300]
        obj.finished_at = timezone.now()
        obj.save(update_fields=['status', 'summary', 'finished_at'])
        return
    if isinstance(obj, FileDistribution):
        obj.status = FileDistribution.STATUS_FAILED
        obj.summary = message[:300]
        obj.finished_at = timezone.now()
        obj.save(update_fields=['status', 'summary', 'finished_at'])
        return
    if isinstance(obj, DeploymentRelease):
        obj.status = DeploymentRelease.STATUS_FAILED
        obj.summary = message[:300]
        obj.finished_at = timezone.now()
        obj.save(update_fields=['status', 'summary', 'finished_at'])
        return


def run_background_job(target, args, kwargs):
    try:
        return target(*args, **kwargs)
    except Exception as exc:
        mark_background_failure(target, args, exc)
        print('后台任务执行失败：%s' % exc)


def client_ip(request):
    forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if forwarded_for:
        return forwarded_for.split(',')[0].strip()
    return request.META.get('REMOTE_ADDR', '')


def audit(request, action, target_type='', target_id='', detail=''):
    AuditLog.objects.create(
        user=request.session.get('user_name', ''),
        action=action,
        target_type=target_type,
        target_id=str(target_id or ''),
        detail=detail,
        ip_address=client_ip(request),
    )


def cleanup_audit_logs(retention_days=None):
    days = retention_days
    if days is None:
        days = int(getattr(settings, 'AUDIT_LOG_RETENTION_DAYS', 0) or 0)
    days = int(days or 0)
    if days <= 0:
        return 0
    cutoff = timezone.now() - timezone.timedelta(days=days)
    deleted, details = AuditLog.objects.filter(created_at__lt=cutoff).delete()
    return deleted


def user_role(request):
	user_id = request.session.get('user_id')
	if not user_id:
		return DevOpsRole.ROLE_VIEWER
	try:
		return DevOpsRole.objects.get(user_id=user_id).role
	except DevOpsRole.DoesNotExist:
		return DevOpsRole.ROLE_ADMIN if not DevOpsRole.objects.exists() else DevOpsRole.ROLE_OPERATOR


def module_role(request, module=''):
	base_role = user_role(request)
	user_id = request.session.get('user_id')
	if not user_id or not module:
		return base_role
	try:
		return DevOpsModulePermission.objects.get(user_id=user_id, module=module).role
	except DevOpsModulePermission.DoesNotExist:
		return base_role


def has_role(request, minimum_role, module=''):
	if request.session.get('user_id') and not has_configured_role(request):
		return ROLE_RANKS.get(DevOpsRole.ROLE_OPERATOR, 0) >= ROLE_RANKS.get(minimum_role, 0)
	return ROLE_RANKS.get(module_role(request, module), 0) >= ROLE_RANKS.get(minimum_role, 0)


def host_scope_for_request(request):
    user_id = request.session.get('user_id')
    if not user_id:
        return None
    try:
        return DevOpsHostScope.objects.get(user_id=user_id)
    except DevOpsHostScope.DoesNotExist:
        return None


def has_explicit_admin_role(request):
	user_id = request.session.get('user_id')
	if not user_id:
		return False
	try:
		return DevOpsRole.objects.get(user_id=user_id).role == DevOpsRole.ROLE_ADMIN
	except DevOpsRole.DoesNotExist:
		return not DevOpsRole.objects.exists()


def has_configured_role(request):
	user_id = request.session.get('user_id')
	if not user_id:
		return False
	return DevOpsRole.objects.filter(user_id=user_id).exists()


def visible_hosts_for_request(request):
	scope = host_scope_for_request(request)
	if not scope:
		if has_explicit_admin_role(request):
			return NewLinux.objects.all()
		if not has_configured_role(request):
			return NewLinux.objects.all()
		return NewLinux.objects.none()
	group_ids = list(scope.groups.values_list('id', flat=True))
	tag_ids = list(scope.tags.values_list('id', flat=True))
	if not group_ids and not tag_ids:
		return NewLinux.objects.none()
	query = models.Q()
	if group_ids:
		query |= models.Q(hostgroup__id__in=group_ids)
	if tag_ids:
		query |= models.Q(hosttag__id__in=tag_ids)
	return NewLinux.objects.filter(query).distinct()


def can_access_host(request, host):
    if not host:
        return True
    return visible_hosts_for_request(request).filter(id=host.id).exists()


def can_access_hosts(request, hosts):
    host_ids = [host.id for host in hosts]
    if not host_ids:
        return True
    allowed_ids = set(visible_hosts_for_request(request).filter(id__in=host_ids).values_list('id', flat=True))
    return set(host_ids).issubset(allowed_ids)


def evaluate_command_policy(command, role=DevOpsRole.ROLE_OPERATOR):
    normalized = ' '.join(command.strip().lower().split())
    policies = CommandPolicy.objects.filter(enabled=True)
    for policy in policies:
        if policy.pattern.lower() in normalized:
            if policy.action == CommandPolicy.ACTION_ALLOW:
                return COMMAND_ALLOWED, policy
            if policy.action == CommandPolicy.ACTION_REQUIRE_ADMIN and role != DevOpsRole.ROLE_ADMIN:
                return COMMAND_ADMIN_REQUIRED, policy
            if policy.action == CommandPolicy.ACTION_BLOCK:
                return COMMAND_BLOCKED, policy

    if matches_default_dangerous_command(normalized):
        return COMMAND_BLOCKED, None
    return COMMAND_ALLOWED, None


def matches_default_dangerous_command(normalized_command):
    for pattern in DANGEROUS_COMMANDS:
        if pattern in normalized_command:
            return True
    try:
        tokens = shlex.split(normalized_command)
    except ValueError:
        tokens = normalized_command.split()
    if tokens and tokens[0] == 'sudo':
        tokens = tokens[1:]
    if not tokens:
        return False
    command_name = tokens[0].split('/')[-1]
    if command_name in SYSTEM_POWER_COMMANDS:
        return True
    if command_name == 'rm':
        flags = ''.join(token[1:] for token in tokens[1:] if token.startswith('-') and not token.startswith('--'))
        targets = [token for token in tokens[1:] if not token.startswith('-')]
        if 'r' in flags and 'f' in flags and any(target in ('/', '/*') for target in targets):
            return True
    return False


def command_denied_message(decision, policy=None):
    if decision == COMMAND_ADMIN_REQUIRED:
        reason = policy.reason if policy and policy.reason else '该命令需要管理员权限'
        return '命令需要管理员权限：%s' % reason
    reason = policy.reason if policy and policy.reason else '命令包含高危操作'
    return '%s，已被平台拦截' % reason


def is_dangerous_command(command):
    decision, policy = evaluate_command_policy(command)
    return decision in (COMMAND_BLOCKED, COMMAND_ADMIN_REQUIRED)


def task_retry_count():
    return max(0, int(getattr(settings, 'DEVOPS_TASK_RETRY_COUNT', 0) or 0))


def ssh_connect_timeout():
    return max(1, int(getattr(settings, 'DEVOPS_SSH_CONNECT_TIMEOUT_SECONDS', 10) or 10))


def command_timeout():
    return max(1, int(getattr(settings, 'DEVOPS_COMMAND_TIMEOUT_SECONDS', 60) or 60))


def command_output_max_bytes():
    return max(1, int(getattr(settings, 'DEVOPS_COMMAND_OUTPUT_MAX_BYTES', 204800) or 204800))


def read_limited_stream(stream, limit):
    data = stream.read()
    truncated = False
    if len(data) > limit:
        data = data[:limit]
        truncated = True
    text = data.decode(errors='ignore')
    if truncated:
        text += '\n[输出已截断，最多保留 %s 字节]' % limit
    return text


def execute_command_record(record, role=DevOpsRole.ROLE_OPERATOR):
    if not claim_pending_work(CommandExecution, record, CommandExecution.STATUS_RUNNING):
        return record

    decision, policy = evaluate_command_policy(record.command, role)
    if decision in (COMMAND_BLOCKED, COMMAND_ADMIN_REQUIRED):
        record.status = CommandExecution.STATUS_BLOCKED
        record.error = command_denied_message(decision, policy)
        record.finished_at = timezone.now()
        record.save()
        return record

    started = time.time()
    attempts = task_retry_count() + 1
    last_error = ''
    for attempt in range(1, attempts + 1):
        client = None
        try:
            client = create_host_ssh_client(record.host, timeout=ssh_connect_timeout())
            stdin, stdout, stderr = client.exec_command(record.command, timeout=command_timeout())
            output_limit = command_output_max_bytes()
            record.output = read_limited_stream(stdout, output_limit)
            record.error = read_limited_stream(stderr, output_limit)
            record.status = (
                CommandExecution.STATUS_FAILED
                if record.error and not record.output
                else CommandExecution.STATUS_SUCCESS
            )
            if record.status == CommandExecution.STATUS_SUCCESS:
                break
            last_error = record.error
        except Exception as exc:
            record.status = CommandExecution.STATUS_FAILED
            last_error = describe_ssh_error(exc)
            record.error = last_error
        finally:
            if client:
                client.close()
        if attempt < attempts:
            record.error = '%s，准备重试 %s/%s' % (last_error, attempt, attempts - 1)
            record.save(update_fields=['error', 'status'])
    if record.status == CommandExecution.STATUS_FAILED and attempts > 1 and last_error:
        record.error = '%s（已尝试 %s 次）' % (last_error, attempts)
    record.duration_ms = int((time.time() - started) * 1000)
    record.finished_at = timezone.now()
    record.save()
    return record


def execute_batch_task(task, role=DevOpsRole.ROLE_OPERATOR):
    if not claim_pending_work(BatchTask, task, BatchTask.STATUS_RUNNING):
        return task

    decision, policy = evaluate_command_policy(task.command, role)
    if decision != COMMAND_ALLOWED:
        task.status = BatchTask.STATUS_BLOCKED
        task.summary = command_denied_message(decision, policy)
        task.finished_at = timezone.now()
        task.save()
        for host in task.hosts.all():
            BatchTaskResult.objects.create(
                task=task,
                host=host,
                status=CommandExecution.STATUS_BLOCKED,
                error=task.summary,
            )
        return task

    success_count = 0
    failed_count = 0
    for host in task.hosts.all():
        record = CommandExecution.objects.create(
            host=host,
            command=task.command,
            created_by=task.created_by,
        )
        execute_command_record(record, role)
        BatchTaskResult.objects.create(
            task=task,
            host=host,
            command_execution=record,
            status=record.status,
            output=record.output,
            error=record.error,
            duration_ms=record.duration_ms,
        )
        if record.status == CommandExecution.STATUS_SUCCESS:
            success_count += 1
        else:
            failed_count += 1
    if success_count and failed_count:
        task.status = BatchTask.STATUS_PARTIAL
    elif success_count:
        task.status = BatchTask.STATUS_SUCCESS
    else:
        task.status = BatchTask.STATUS_FAILED
    task.summary = '成功 %s 台，失败 %s 台' % (success_count, failed_count)
    task.finished_at = timezone.now()
    task.save()
    return task


def service_command(action, service_name):
    return 'systemctl %s %s' % (action, service_name)


def alert_fingerprint(host, metric):
    host_id = host.id if host else 'none'
    return '%s:%s' % (host_id, metric or 'general')


def is_alert_silenced(host, metric, now=None):
    now = now or timezone.now()
    silences = AlertSilence.objects.filter(starts_at__lte=now, ends_at__gte=now)
    return silences.filter(host=host, metric__in=[metric, '']).exists() or silences.filter(host__isnull=True, metric__in=[metric, '']).exists()


def record_alert(host, metric, message, level=AlertEvent.LEVEL_WARNING):
    now = timezone.now()
    fingerprint = alert_fingerprint(host, metric)
    active_statuses = [
        AlertEvent.STATUS_OPEN,
        AlertEvent.STATUS_PROCESSING,
        AlertEvent.STATUS_SILENCED,
    ]
    alert = AlertEvent.objects.filter(fingerprint=fingerprint, status__in=active_statuses).first()
    if alert:
        alert.repeat_count += 1
        alert.last_seen_at = now
        alert.message = message
        if is_alert_silenced(host, metric):
            alert.status = AlertEvent.STATUS_SILENCED
            alert.remark = '命中静默规则'
        alert.save(update_fields=['repeat_count', 'last_seen_at', 'message', 'status', 'remark', 'updated_at'])
        return alert, False

    status = AlertEvent.STATUS_SILENCED if is_alert_silenced(host, metric) else AlertEvent.STATUS_OPEN
    alert = AlertEvent.objects.create(
        host=host,
        level=level,
        metric=metric,
        message=message,
        status=status,
        fingerprint=fingerprint,
        first_seen_at=now,
        last_seen_at=now,
        remark='命中静默规则' if status == AlertEvent.STATUS_SILENCED else '',
    )
    if alert.status != AlertEvent.STATUS_SILENCED:
        notify_alert(alert)
    return alert, True


def resolve_alert(host, metric, message='指标已恢复正常'):
    fingerprint = alert_fingerprint(host, metric)
    active_statuses = [
        AlertEvent.STATUS_OPEN,
        AlertEvent.STATUS_PROCESSING,
        AlertEvent.STATUS_SILENCED,
    ]
    alert = AlertEvent.objects.filter(fingerprint=fingerprint, status__in=active_statuses).first()
    if not alert:
        return None
    update_alert_status(
        alert,
        AlertEvent.STATUS_RESOLVED,
        handler='system',
        remark=message,
    )
    return alert


def dingtalk_signed_url(url, secret):
    if not secret:
        return url
    timestamp = str(int(time.time() * 1000))
    string_to_sign = '%s\n%s' % (timestamp, secret)
    digest = hmac.new(
        secret.encode('utf-8'),
        string_to_sign.encode('utf-8'),
        hashlib.sha256,
    ).digest()
    sign = urlparse.quote_plus(base64.b64encode(digest))
    separator = '&' if '?' in url else '?'
    return '%s%stimestamp=%s&sign=%s' % (url, separator, timestamp, sign)


def notification_payload(channel, event_type, title, content):
    if channel.channel_type in (NotificationChannel.TYPE_WECOM, NotificationChannel.TYPE_DINGTALK):
        return {
            'msgtype': 'text',
            'text': {
                'content': '%s\n%s' % (title, content),
            },
        }
    return {
        'event_type': event_type,
        'title': title,
        'content': content,
    }


def send_notification_channel(channel, event_type, title, content):
    dedup_seconds = getattr(settings, 'NOTIFICATION_DEDUP_SECONDS', 300)
    if dedup_seconds:
        since = timezone.now() - timezone.timedelta(seconds=dedup_seconds)
        recent = NotificationLog.objects.filter(
            channel=channel,
            event_type=event_type,
            title=title,
            content=content,
            created_at__gte=since,
        ).exists()
        if recent:
            return NotificationLog.objects.create(
                channel=channel,
                event_type=event_type,
                title=title,
                content=content,
                status=NotificationLog.STATUS_SUCCESS,
                response='deduped: %s秒内重复通知已跳过' % dedup_seconds,
            )

    url = channel.decrypted_webhook_url
    if not url:
        return NotificationLog.objects.create(
            channel=channel,
            event_type=event_type,
            title=title,
            content=content,
            status=NotificationLog.STATUS_FAILED,
            response='Webhook URL 为空或解密失败',
        )

    if channel.channel_type == NotificationChannel.TYPE_DINGTALK:
        url = dingtalk_signed_url(url, channel.decrypted_secret)

    payload = notification_payload(channel, event_type, title, content)
    attempts = max(1, int(getattr(settings, 'NOTIFICATION_RETRY_COUNT', 0) or 0) + 1)
    timeout = max(1, int(getattr(settings, 'NOTIFICATION_TIMEOUT_SECONDS', 5) or 5))
    status = NotificationLog.STATUS_FAILED
    response_message = ''
    for attempt in range(1, attempts + 1):
        try:
            response = requests.post(url, json=payload, timeout=timeout)
            response_text = response.text[:1000]
            response_message = 'HTTP %s %s' % (response.status_code, response_text)
            status = NotificationLog.STATUS_SUCCESS if response.status_code < 400 else NotificationLog.STATUS_FAILED
        except Exception as exc:
            response_message = str(exc)
            status = NotificationLog.STATUS_FAILED
        if status == NotificationLog.STATUS_SUCCESS:
            break
    if attempts > 1:
        response_message = '%s（已尝试 %s 次）' % (response_message, attempt)
    return NotificationLog.objects.create(
        channel=channel,
        event_type=event_type,
        title=title,
        content=content,
        status=status,
        response=response_message,
    )


def send_notifications(event_type, title, content):
    channels = NotificationChannel.objects.filter(enabled=True)
    if event_type == NotificationLog.EVENT_ALERT:
        channels = channels.filter(notify_alert=True)
    elif event_type == NotificationLog.EVENT_APPROVAL:
        channels = channels.filter(notify_approval=True)
    elif event_type == NotificationLog.EVENT_DEPLOYMENT:
        channels = channels.filter(notify_deployment=True)
    logs = []
    for channel in channels:
        logs.append(send_notification_channel(channel, event_type, title, content))
    return logs


def notify_alert(alert):
    host_name = alert.host.linux_name if alert.host else '-'
    title = '告警通知：%s %s' % (host_name, alert.metric or 'general')
    content = '级别：%s\n状态：%s\n内容：%s' % (
        alert.get_level_display() if hasattr(alert, 'get_level_display') else alert.level,
        alert.get_status_display() if hasattr(alert, 'get_status_display') else alert.status,
        alert.message,
    )
    return send_notifications(NotificationLog.EVENT_ALERT, title, content)


def notify_approval(approval, action):
    title = '审批%s：%s' % (action, approval.title)
    content = '类型：%s\n状态：%s\n申请人：%s\n审批人：%s\n原因：%s\n意见：%s' % (
        approval.get_request_type_display(),
        approval.get_status_display(),
        approval.requester or '-',
        approval.approver or '-',
        approval.reason or '-',
        approval.comment or '-',
    )
    return send_notifications(NotificationLog.EVENT_APPROVAL, title, content)


def notify_deployment(release, action='发布结果'):
    title = '%s：%s %s' % (action, release.app.name, release.version)
    content = '状态：%s\n摘要：%s\n提交人：%s' % (
        release.get_status_display(),
        release.summary or '-',
        release.created_by or '-',
    )
    return send_notifications(NotificationLog.EVENT_DEPLOYMENT, title, content)


def update_alert_status(alert, to_status, handler='', remark='', from_status=None):
    from_status = from_status if from_status is not None else alert.status
    alert.status = to_status
    alert.handler = handler
    alert.remark = remark
    alert.save()
    AlertHistory.objects.create(
        alert=alert,
        from_status=from_status,
        to_status=to_status,
        handler=handler,
        remark=remark,
    )
    return alert


def record_metric_sample(host, metric, value, collected_at=None, unit='percent'):
    return MetricSample.objects.create(
        host=host,
        metric=metric,
        value=float(value),
        unit=unit,
        collected_at=collected_at or timezone.now(),
    )


def cleanup_metric_samples(retention_days=None, now=None):
    days = retention_days
    if days is None:
        days = int(getattr(settings, 'METRIC_SAMPLE_RETENTION_DAYS', 0) or 0)
    days = int(days or 0)
    if days <= 0:
        return 0
    cutoff = (now or timezone.now()) - timezone.timedelta(days=days)
    deleted, details = MetricSample.objects.filter(collected_at__lt=cutoff).delete()
    return deleted


def latest_metric_map(hosts=None):
    hosts = hosts or []
    host_ids = [host.id for host in hosts]
    samples = MetricSample.objects.filter(host_id__in=host_ids) if host_ids else MetricSample.objects.none()
    result = {}
    for sample in samples.order_by('host_id', 'metric', '-collected_at'):
        key = (sample.host_id, sample.metric)
        if key not in result:
            result[key] = sample
    return result


def validate_remote_path(remote_path):
    if not remote_path or not remote_path.startswith('/'):
        return False, '远端路径必须是绝对路径'
    normalized = posixpath.normpath(remote_path)
    if normalized in ('/', '.', ''):
        return False, '不能分发到根目录'
    if '..' in remote_path.split('/'):
        return False, '远端路径不能包含 ..'
    return True, normalized


def execute_file_distribution(distribution):
    if not claim_pending_work(FileDistribution, distribution, FileDistribution.STATUS_RUNNING):
        return distribution

    valid, normalized_path = validate_remote_path(distribution.remote_path)
    if not valid:
        distribution.status = FileDistribution.STATUS_BLOCKED
        distribution.summary = normalized_path
        distribution.finished_at = timezone.now()
        distribution.save()
        for host in distribution.hosts.all():
            FileDistributionResult.objects.create(
                distribution=distribution,
                host=host,
                status=CommandExecution.STATUS_BLOCKED,
                message=normalized_path,
            )
        return distribution

    distribution.remote_path = normalized_path
    distribution.save(update_fields=['remote_path'])
    success_count = 0
    failed_count = 0
    local_path = distribution.source_file.path
    for host in distribution.hosts.all():
        started = time.time()
        status = CommandExecution.STATUS_SUCCESS
        message = '分发成功'
        attempts = task_retry_count() + 1
        last_message = ''
        for attempt in range(1, attempts + 1):
            client = None
            try:
                client = create_host_ssh_client(host, timeout=ssh_connect_timeout())
                sftp = client.open_sftp()
                try:
                    sftp.put(local_path, normalized_path)
                finally:
                    sftp.close()
                status = CommandExecution.STATUS_SUCCESS
                message = '分发成功'
                break
            except Exception as exc:
                status = CommandExecution.STATUS_FAILED
                last_message = describe_ssh_error(exc)
                message = last_message
            finally:
                if client:
                    client.close()
            if status == CommandExecution.STATUS_FAILED and attempt < attempts:
                message = '%s，准备重试 %s/%s' % (last_message, attempt, attempts - 1)
        if status == CommandExecution.STATUS_FAILED and attempts > 1 and last_message:
            message = '%s（已尝试 %s 次）' % (last_message, attempts)
        if status == CommandExecution.STATUS_SUCCESS:
            success_count += 1
        else:
            failed_count += 1
        FileDistributionResult.objects.create(
            distribution=distribution,
            host=host,
            status=status,
            message=message,
            duration_ms=int((time.time() - started) * 1000),
        )

    if success_count and failed_count:
        distribution.status = FileDistribution.STATUS_PARTIAL
    elif success_count:
        distribution.status = FileDistribution.STATUS_SUCCESS
    else:
        distribution.status = FileDistribution.STATUS_FAILED
    distribution.summary = '成功 %s 台，失败 %s 台' % (success_count, failed_count)
    distribution.finished_at = timezone.now()
    distribution.save()
    return distribution


def create_deployment_result(release, host, action, record):
    return DeploymentResult.objects.create(
        release=release,
        host=host,
        action=action,
        command_execution=record,
        status=record.status,
        output=record.output,
        error=record.error,
        duration_ms=record.duration_ms,
    )


def execute_deployment_release(release, role=DevOpsRole.ROLE_OPERATOR):
    claimed = claim_pending_work(DeploymentRelease, release, DeploymentRelease.STATUS_RUNNING)
    if not claimed and not claim_running_deployment_if_empty(release, DeploymentResult.ACTION_DEPLOY):
        return release

    decision, policy = evaluate_command_policy(release.deploy_script, role)
    if decision != COMMAND_ALLOWED:
        message = command_denied_message(decision, policy)
        release.status = DeploymentRelease.STATUS_BLOCKED
        release.summary = message
        release.finished_at = timezone.now()
        release.save()
        for host in release.hosts.all():
            DeploymentResult.objects.create(
                release=release,
                host=host,
                action=DeploymentResult.ACTION_DEPLOY,
                status=CommandExecution.STATUS_BLOCKED,
                error=message,
            )
        notify_deployment(release)
        return release

    success_count = 0
    failed_count = 0
    for host in release.hosts.all():
        record = CommandExecution.objects.create(
            host=host,
            command=release.deploy_script,
            created_by=release.created_by,
        )
        execute_command_record(record, role)
        create_deployment_result(release, host, DeploymentResult.ACTION_DEPLOY, record)
        if record.status == CommandExecution.STATUS_SUCCESS:
            success_count += 1
        else:
            failed_count += 1

    if success_count and failed_count:
        release.status = DeploymentRelease.STATUS_PARTIAL
    elif success_count:
        release.status = DeploymentRelease.STATUS_SUCCESS
    else:
        release.status = DeploymentRelease.STATUS_FAILED
    release.summary = '成功 %s 台，失败 %s 台' % (success_count, failed_count)
    release.finished_at = timezone.now()
    release.save()
    notify_deployment(release)
    return release


def execute_deployment_rollback(release, role=DevOpsRole.ROLE_OPERATOR):
    claimed = claim_deployment_rollback(release)
    if not claimed and not claim_running_deployment_if_empty(release, DeploymentResult.ACTION_ROLLBACK):
        return release

    if not release.rollback_script.strip():
        release.status = DeploymentRelease.STATUS_FAILED
        release.summary = '未配置回滚脚本'
        release.finished_at = timezone.now()
        release.save(update_fields=['status', 'summary', 'finished_at'])
        notify_deployment(release, '回滚结果')
        return release

    decision, policy = evaluate_command_policy(release.rollback_script, role)
    if decision != COMMAND_ALLOWED:
        message = command_denied_message(decision, policy)
        release.status = DeploymentRelease.STATUS_FAILED
        release.summary = message
        release.finished_at = timezone.now()
        release.save(update_fields=['status', 'summary', 'finished_at'])
        for host in release.hosts.all():
            DeploymentResult.objects.create(
                release=release,
                host=host,
                action=DeploymentResult.ACTION_ROLLBACK,
                status=CommandExecution.STATUS_BLOCKED,
                error=message,
            )
        notify_deployment(release, '回滚结果')
        return release

    success_count = 0
    failed_count = 0
    for host in release.hosts.all():
        record = CommandExecution.objects.create(
            host=host,
            command=release.rollback_script,
            created_by=release.created_by,
        )
        execute_command_record(record, role)
        create_deployment_result(release, host, DeploymentResult.ACTION_ROLLBACK, record)
        if record.status == CommandExecution.STATUS_SUCCESS:
            success_count += 1
        else:
            failed_count += 1
    release.status = DeploymentRelease.STATUS_ROLLED_BACK if success_count else DeploymentRelease.STATUS_FAILED
    release.summary = '回滚成功 %s 台，失败 %s 台' % (success_count, failed_count)
    release.finished_at = timezone.now()
    release.save()
    notify_deployment(release, '回滚结果')
    return release


def create_command_approval(host, command, requester='', reason=''):
    approval = ApprovalRequest.objects.create(
        request_type=ApprovalRequest.TYPE_COMMAND,
        title='命令执行审批：%s' % host,
        host=host,
        command=command,
        requester=requester,
        reason=reason,
    )
    notify_approval(approval, '创建')
    return approval


def create_deployment_approval(release, requester='', reason=''):
    approval = ApprovalRequest.objects.create(
        request_type=ApprovalRequest.TYPE_DEPLOYMENT,
        title='发布审批：%s %s' % (release.app.name, release.version),
        deployment_release=release,
        requester=requester,
        reason=reason,
    )
    notify_approval(approval, '创建')
    return approval


def create_rollback_approval(release, requester='', reason=''):
    approval = ApprovalRequest.objects.create(
        request_type=ApprovalRequest.TYPE_ROLLBACK,
        title='回滚审批：%s %s' % (release.app.name, release.version),
        deployment_release=release,
        requester=requester,
        reason=reason,
    )
    notify_approval(approval, '创建')
    return approval


def execute_approval_request(approval, role=DevOpsRole.ROLE_ADMIN):
    if approval.request_type == ApprovalRequest.TYPE_COMMAND:
        record = CommandExecution.objects.create(
            host=approval.host,
            command=approval.command,
            created_by=approval.requester,
        )
        execute_command_record(record, role)
        approval.command_execution = record
        approval.status = ApprovalRequest.STATUS_EXECUTED if record.status != CommandExecution.STATUS_FAILED else ApprovalRequest.STATUS_FAILED
        approval.executed_at = timezone.now()
        approval.save()
        notify_approval(approval, '执行')
        return approval

    if approval.request_type == ApprovalRequest.TYPE_DEPLOYMENT and approval.deployment_release:
        execute_deployment_release(approval.deployment_release, role)
        approval.status = ApprovalRequest.STATUS_EXECUTED
        if approval.deployment_release.status == DeploymentRelease.STATUS_FAILED:
            approval.status = ApprovalRequest.STATUS_FAILED
        approval.executed_at = timezone.now()
        approval.save()
        notify_approval(approval, '执行')
        return approval

    if approval.request_type == ApprovalRequest.TYPE_ROLLBACK and approval.deployment_release:
        execute_deployment_rollback(approval.deployment_release, role)
        approval.status = ApprovalRequest.STATUS_EXECUTED
        if approval.deployment_release.status == DeploymentRelease.STATUS_FAILED:
            approval.status = ApprovalRequest.STATUS_FAILED
        approval.executed_at = timezone.now()
        approval.save()
        notify_approval(approval, '执行')
        return approval

    approval.status = ApprovalRequest.STATUS_FAILED
    approval.comment = '审批目标不存在'
    approval.executed_at = timezone.now()
    approval.save()
    notify_approval(approval, '执行')
    return approval
