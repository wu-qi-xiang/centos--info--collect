import hashlib
import hmac
import json
import os
import re

from django.db import transaction
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt

from ..models import ApprovalRequest, AuditLog, DeploymentRelease, DevOpsSetting, IntegrationHealthEvent
from ..services import (
    enqueue_background_job,
    execute_deployment_release,
    record_integration_health_event,
    require_deployment_risk_approval,
    require_deployment_slo_approval,
)


MAX_WEBHOOK_BODY_BYTES = 1024 * 1024
DELIVERY_ID_RE = re.compile(r'^[A-Za-z0-9-]{1,100}$')
SHA_RE = re.compile(r'^[0-9a-f]{40,64}$')
QUEUE_AUDIT_ACTION = 'GitHub deployment queued'


def record_github_delivery_health(status, category, summary):
    """Store a fixed, non-sensitive delivery outcome for operational health."""
    try:
        record_integration_health_event(
            IntegrationHealthEvent.TYPE_GITHUB_INBOUND,
            status=status,
            category=category,
            summary=summary,
            source_name=IntegrationHealthEvent.SOURCE_GITHUB_INBOUND,
        )
    except Exception:
        # Telemetry is optional and must never alter webhook acceptance or queueing.
        return


def webhook_response(ok, status, code, **extra):
    payload = {'ok': ok, 'code': code}
    payload.update(extra)
    return JsonResponse(payload, status=status)


def normalized_repository(value):
    if not isinstance(value, str):
        return ''
    value = value.strip().lower()
    if not value or len(value) > 200 or value.count('/') != 1:
        return ''
    owner, name = value.split('/', 1)
    if not owner or not name:
        return ''
    return value


def valid_signature(secret, body, signature):
    if not signature or not signature.startswith('sha256='):
        return False
    provided = signature[7:]
    if len(provided) != 64 or not re.match(r'^[0-9a-fA-F]{64}$', provided):
        return False
    expected = hmac.new(secret.encode('utf-8'), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, provided.lower())


def workflow_run_values(payload):
    if not isinstance(payload, dict):
        return None
    workflow_run = payload.get('workflow_run')
    repository = payload.get('repository')
    if not isinstance(workflow_run, dict) or not isinstance(repository, dict):
        return None
    status = workflow_run.get('status')
    conclusion = workflow_run.get('conclusion')
    sha = workflow_run.get('head_sha')
    repo_name = normalized_repository(repository.get('full_name'))
    if not isinstance(status, str) or (conclusion is not None and not isinstance(conclusion, str)):
        return None
    if not isinstance(sha, str) or not SHA_RE.match(sha.lower()) or not repo_name:
        return None
    return status.lower(), (conclusion or '').lower(), repo_name, sha.lower()


@csrf_exempt
def github_workflow_run(request):
    if request.method != 'POST':
        return webhook_response(False, 405, 'method_not_allowed')

    secret = os.environ.get('GITHUB_WEBHOOK_SECRET', '')
    if not secret:
        return webhook_response(False, 503, 'webhook_not_configured')

    content_length = request.META.get('CONTENT_LENGTH', '')
    try:
        if content_length and int(content_length) > MAX_WEBHOOK_BODY_BYTES:
            record_github_delivery_health(
                IntegrationHealthEvent.STATUS_FAILED,
                IntegrationHealthEvent.CATEGORY_VALIDATION_ERROR,
                'Rejected GitHub delivery: payload too large.',
            )
            return webhook_response(False, 413, 'payload_too_large')
    except (TypeError, ValueError):
        record_github_delivery_health(
            IntegrationHealthEvent.STATUS_FAILED,
            IntegrationHealthEvent.CATEGORY_VALIDATION_ERROR,
            'Rejected GitHub delivery: invalid content length.',
        )
        return webhook_response(False, 400, 'invalid_content_length')

    body = request.body
    if len(body) > MAX_WEBHOOK_BODY_BYTES:
        record_github_delivery_health(
            IntegrationHealthEvent.STATUS_FAILED,
            IntegrationHealthEvent.CATEGORY_VALIDATION_ERROR,
            'Rejected GitHub delivery: payload too large.',
        )
        return webhook_response(False, 413, 'payload_too_large')
    if not valid_signature(secret, body, request.META.get('HTTP_X_HUB_SIGNATURE_256', '')):
        record_github_delivery_health(
            IntegrationHealthEvent.STATUS_FAILED,
            IntegrationHealthEvent.CATEGORY_REJECTED,
            'Rejected GitHub delivery: signature validation failed.',
        )
        return webhook_response(False, 401, 'invalid_signature')

    delivery_id = request.META.get('HTTP_X_GITHUB_DELIVERY', '')
    if not DELIVERY_ID_RE.match(delivery_id):
        record_github_delivery_health(
            IntegrationHealthEvent.STATUS_FAILED,
            IntegrationHealthEvent.CATEGORY_VALIDATION_ERROR,
            'Rejected GitHub delivery: invalid delivery identifier.',
        )
        return webhook_response(False, 400, 'invalid_delivery')
    if AuditLog.objects.filter(
            action='GitHub workflow_run delivery',
            target_type='GitHubDelivery',
            target_id=delivery_id).exists():
        record_github_delivery_health(
            IntegrationHealthEvent.STATUS_SUCCESS,
            IntegrationHealthEvent.CATEGORY_DUPLICATE,
            'Ignored duplicate GitHub delivery.',
        )
        return webhook_response(True, 202, 'duplicate_delivery')
    if request.META.get('HTTP_X_GITHUB_EVENT', '') != 'workflow_run':
        record_github_delivery_health(
            IntegrationHealthEvent.STATUS_SUCCESS,
            IntegrationHealthEvent.CATEGORY_OK,
            'Ignored unsupported GitHub event.',
        )
        return webhook_response(True, 202, 'ignored_event')

    try:
        payload = json.loads(body.decode('utf-8'))
    except (UnicodeDecodeError, ValueError):
        record_github_delivery_health(
            IntegrationHealthEvent.STATUS_FAILED,
            IntegrationHealthEvent.CATEGORY_VALIDATION_ERROR,
            'Rejected GitHub delivery: invalid JSON.',
        )
        return webhook_response(False, 400, 'invalid_json')
    values = workflow_run_values(payload)
    if not values:
        record_github_delivery_health(
            IntegrationHealthEvent.STATUS_FAILED,
            IntegrationHealthEvent.CATEGORY_VALIDATION_ERROR,
            'Rejected GitHub delivery: invalid workflow payload.',
        )
        return webhook_response(False, 400, 'invalid_payload')
    status, conclusion, repository, sha = values
    if status != 'completed' or conclusion != 'success':
        record_github_delivery_health(
            IntegrationHealthEvent.STATUS_SUCCESS,
            IntegrationHealthEvent.CATEGORY_OK,
            'Ignored GitHub workflow run without a successful completion.',
        )
        return webhook_response(True, 202, 'ignored_workflow_status')

    # Locking the matched release serializes duplicate deliveries while audit data
    # stores only the non-secret delivery ID and a fixed safe summary.
    with transaction.atomic():
        releases = list(DeploymentRelease.objects.select_for_update().filter(
            app__repository=repository,
            version=sha,
            status=DeploymentRelease.STATUS_PENDING,
        ).order_by('id')[:2])
        if not releases:
            record_github_delivery_health(
                IntegrationHealthEvent.STATUS_SUCCESS,
                IntegrationHealthEvent.CATEGORY_OK,
                'Ignored GitHub delivery without a matching pending release.',
            )
            return webhook_response(True, 202, 'release_not_found')
        if len(releases) != 1:
            record_github_delivery_health(
                IntegrationHealthEvent.STATUS_FAILED,
                IntegrationHealthEvent.CATEGORY_INTERNAL_ERROR,
                'Rejected GitHub delivery: pending release match is ambiguous.',
            )
            return webhook_response(False, 409, 'ambiguous_release')
        if AuditLog.objects.filter(
                action='GitHub workflow_run delivery',
                target_type='GitHubDelivery',
                target_id=delivery_id).exists():
            record_github_delivery_health(
                IntegrationHealthEvent.STATUS_SUCCESS,
                IntegrationHealthEvent.CATEGORY_DUPLICATE,
                'Ignored duplicate GitHub delivery.',
            )
            return webhook_response(True, 202, 'duplicate_delivery')
        release = releases[0]
        approval_pending = ApprovalRequest.objects.filter(
            request_type=ApprovalRequest.TYPE_DEPLOYMENT,
            deployment_release=release,
            status=ApprovalRequest.STATUS_PENDING,
        ).exists()
        slo_approval = require_deployment_slo_approval(release, requester='github')
        risk_approval = require_deployment_risk_approval(release, requester='github')
        approval_required = (
            approval_pending or slo_approval or risk_approval or DevOpsSetting.current().force_deploy_approval
        )
        AuditLog.objects.create(
            user='github',
            action='GitHub workflow_run delivery',
            target_type='GitHubDelivery',
            target_id=delivery_id,
            detail='Matched pending deployment release %s%s.' % (
                release.id,
                '; awaiting approval' if approval_required else '',
            ),
            ip_address='',
        )
        if approval_required:
            record_github_delivery_health(
                IntegrationHealthEvent.STATUS_SUCCESS,
                IntegrationHealthEvent.CATEGORY_OK,
                'Accepted GitHub delivery; deployment is awaiting approval.',
            )
            return webhook_response(True, 202, 'awaiting_approval', release_id=release.id)

        # A release row lock serializes deliveries.  Keep a safe per-release
        # marker so distinct GitHub delivery IDs cannot enqueue the same pending
        # release more than once.
        if AuditLog.objects.filter(
                action=QUEUE_AUDIT_ACTION,
                target_type='DeploymentRelease',
                target_id=str(release.id)).exists():
            record_github_delivery_health(
                IntegrationHealthEvent.STATUS_SUCCESS,
                IntegrationHealthEvent.CATEGORY_DUPLICATE,
                'Ignored duplicate deployment queue request.',
            )
            return webhook_response(True, 202, 'duplicate_delivery', release_id=release.id)
        AuditLog.objects.create(
            user='github',
            action=QUEUE_AUDIT_ACTION,
            target_type='DeploymentRelease',
            target_id=str(release.id),
            detail='Deployment queue claimed for GitHub workflow delivery.',
            ip_address='',
        )

    enqueue_background_job(execute_deployment_release, release)
    record_github_delivery_health(
        IntegrationHealthEvent.STATUS_SUCCESS,
        IntegrationHealthEvent.CATEGORY_OK,
        'Accepted GitHub delivery; deployment queued.',
    )
    return webhook_response(True, 202, 'deployment_queued', release_id=release.id)
