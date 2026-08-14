"""Restricted, signed WeCom ChatOps request handling."""

import hashlib
import hmac
import json
import re

from django.conf import settings
from django.db import models
from django.http import JsonResponse
from django.urls import reverse

from .models import AlertEvent, ApprovalRequest, ChatOpsIdentity, DevOpsModulePermission, DevOpsRole, NewLinux, RunbookTemplate, ServiceCatalog
from .services import audit, has_role, update_alert_status, visible_hosts_for_request


WECOM_USER_ID_RE = re.compile(r'^[A-Za-z0-9_.@-]{1,128}$')
SIGNATURE_RE = re.compile(r'^sha256=([0-9a-fA-F]{64})$')
ACTION_REQUIREMENTS = {
    'service_status': (DevOpsRole.ROLE_VIEWER, DevOpsModulePermission.MODULE_SERVICE),
    'pending_approvals': (DevOpsRole.ROLE_VIEWER, DevOpsModulePermission.MODULE_APPROVAL),
    'acknowledge_alert': (DevOpsRole.ROLE_OPERATOR, DevOpsModulePermission.MODULE_ALERT),
    'approval_link': (DevOpsRole.ROLE_VIEWER, DevOpsModulePermission.MODULE_APPROVAL),
    'runbook_link': (DevOpsRole.ROLE_VIEWER, DevOpsModulePermission.MODULE_COMMAND),
}
MAX_CHATOPS_BODY_BYTES = 8192


def _error(message, status, code):
    return JsonResponse({'ok': False, 'code': code, 'message': message}, status=status)


def _secret():
    value = getattr(settings, 'WECOM_CHATOPS_WEBHOOK_SECRET', '')
    return value if isinstance(value, str) else ''


def valid_wecom_signature(secret, body, signature):
    """Compare an HMAC SHA-256 signature before decoding untrusted content."""
    match = SIGNATURE_RE.match(signature or '') if isinstance(signature, str) else None
    if not secret or not match:
        return False
    expected = hmac.new(secret.encode('utf-8'), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, match.group(1).lower())


class _IdentityRequest(object):
    """Minimal server-built context consumed by existing permission helpers."""
    def __init__(self, request, user):
        self.session = {'is_login': True, 'user_id': user.id, 'user_name': user.user}
        self.META = {'REMOTE_ADDR': request.META.get('REMOTE_ADDR', '')}


def _visible_services(request):
    return ServiceCatalog.objects.filter(
        models.Q(hosts__in=visible_hosts_for_request(request)) | models.Q(hosts__isnull=True)
    ).distinct()


def _visible_approvals(request):
    hosts = visible_hosts_for_request(request)
    visible_host_ids = hosts.values_list('id', flat=True)
    hidden_release_hosts = NewLinux.objects.exclude(id__in=visible_host_ids).values_list('id', flat=True)
    return ApprovalRequest.objects.filter(
        models.Q(host__in=hosts) |
        models.Q(host__isnull=True, deployment_release__hosts__in=hosts) |
        models.Q(host__isnull=True, deployment_release__isnull=True)
    ).exclude(
        host__isnull=True,
        deployment_release__isnull=False,
        deployment_release__hosts__id__in=hidden_release_hosts,
    ).distinct()


def _visible_alerts(request):
    return AlertEvent.objects.filter(
        models.Q(host__in=visible_hosts_for_request(request)) | models.Q(host__isnull=True)
    )


def _visible_runbooks(request):
    return RunbookTemplate.objects.filter(allowed_hosts__in=visible_hosts_for_request(request)).distinct()


def _positive_id(payload):
    value = payload.get('target_id')
    if isinstance(value, bool):
        return None
    try:
        value = int(value)
    except (TypeError, ValueError):
        return None
    return value if value > 0 else None


def _service_status(request):
    return {'ok': True, 'action': 'service_status', 'results': [
        {'id': service.id, 'name': service.name, 'status': service.lifecycle}
        for service in _visible_services(request).order_by('name')[:100]
    ]}


def _pending_approvals(request):
    return {'ok': True, 'action': 'pending_approvals', 'results': [
        {
            'id': approval.id,
            'request_type': approval.request_type,
            'status': approval.status,
            'created_at': approval.created_at.isoformat() if approval.created_at else None,
        }
        for approval in _visible_approvals(request).filter(
            status=ApprovalRequest.STATUS_PENDING).order_by('-created_at')[:50]
    ]}


def _action_result(request, action, payload):
    if action == 'service_status':
        return _service_status(request), None, 'success'
    if action == 'pending_approvals':
        return _pending_approvals(request), None, 'success'
    target_id = _positive_id(payload)
    if target_id is None:
        return None, _error('目标标识无效', 400, 'validation_error'), 'validation_error'
    if action == 'acknowledge_alert':
        try:
            alert = _visible_alerts(request).get(id=target_id)
        except AlertEvent.DoesNotExist:
            return None, _error('告警不存在', 404, 'not_found'), 'not_found'
        if alert.status != AlertEvent.STATUS_OPEN:
            return None, _error('仅可确认未处理告警', 400, 'validation_error'), 'validation_error'
        update_alert_status(alert, AlertEvent.STATUS_PROCESSING, request.session['user_name'], 'ChatOps acknowledged')
        return {'ok': True, 'action': action, 'alert': {'id': alert.id, 'status': alert.status}}, None, 'success'
    if action == 'approval_link':
        if not _visible_approvals(request).filter(id=target_id).exists():
            return None, _error('审批不存在', 404, 'not_found'), 'not_found'
        return {'ok': True, 'action': action, 'url': reverse('devops:approvals')}, None, 'success'
    if action == 'runbook_link':
        if not _visible_runbooks(request).filter(id=target_id, enabled=True).exists():
            return None, _error('运行手册不存在', 404, 'not_found'), 'not_found'
        return {'ok': True, 'action': action, 'url': reverse('devops:runbooks')}, None, 'success'
    return None, _error('不支持的动作', 400, 'unsupported_action'), 'unsupported_action'


def handle_wecom_chatops(request):
    """Handle only signed, bounded messages without retaining request content."""
    body = request.body or b''
    if len(body) > MAX_CHATOPS_BODY_BYTES:
        return _error('请求体过大', 413, 'payload_too_large')
    if not valid_wecom_signature(_secret(), body, request.META.get('HTTP_X_WECOM_SIGNATURE', '')):
        return _error('签名无效', 403, 'invalid_signature')
    try:
        payload = json.loads(body.decode('utf-8'))
    except (TypeError, UnicodeDecodeError, ValueError):
        return _error('JSON 格式错误', 400, 'invalid_json')
    if not isinstance(payload, dict):
        return _error('请求参数无效', 400, 'validation_error')
    action = payload.get('action')
    wecom_user_id = payload.get('wecom_user_id')
    allowed_keys = {'action', 'wecom_user_id'}
    if action in ('acknowledge_alert', 'approval_link', 'runbook_link'):
        allowed_keys.add('target_id')
    if (action not in ACTION_REQUIREMENTS or not isinstance(wecom_user_id, str) or
            not WECOM_USER_ID_RE.match(wecom_user_id) or set(payload) != allowed_keys):
        return _error('请求参数无效', 400, 'validation_error')
    try:
        identity = ChatOpsIdentity.objects.select_related('user').get(wecom_user_id=wecom_user_id, enabled=True)
    except ChatOpsIdentity.DoesNotExist:
        return _error('身份未授权', 403, 'identity_forbidden')
    identity_request = _IdentityRequest(request, identity.user)
    required_role, module = ACTION_REQUIREMENTS[action]
    target_id = str(payload.get('target_id') or '')
    if not has_role(identity_request, required_role, module):
        audit(identity_request, '企业微信ChatOps', 'ChatOps', target_id, 'action=%s,outcome=forbidden' % action)
        return _error('没有执行该动作的权限', 403, 'forbidden')
    result, error_response, outcome = _action_result(identity_request, action, payload)
    audit(identity_request, '企业微信ChatOps', 'ChatOps', target_id, 'action=%s,outcome=%s' % (action, outcome))
    return error_response or JsonResponse(result)
