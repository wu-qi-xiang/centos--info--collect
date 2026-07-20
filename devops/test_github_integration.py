import hashlib
import hmac
import json
import os

try:
    from unittest import mock
except ImportError:
    import mock

from django.test import TestCase, override_settings
from django.urls import reverse

from .models import (
    ApprovalRequest, AuditLog, DeploymentApp, DeploymentRelease, DevOpsSetting,
    IntegrationHealthEvent,
)


@override_settings(ROOT_URLCONF='devops.github_urls', DEVOPS_SYNC_TASKS=True)
class GitHubWorkflowRunWebhookTests(TestCase):
    secret = 'test-github-webhook-secret'

    def setUp(self):
        self.app = DeploymentApp.objects.create(
            name='web', repository='example/web',
        )
        self.release = DeploymentRelease.objects.create(
            app=self.app,
            version='a' * 40,
            deploy_script='echo deploy',
        )

    def post_webhook(self, payload=None, **headers):
        payload = payload or {
            'repository': {'full_name': 'example/web'},
            'workflow_run': {
                'status': 'completed',
                'conclusion': 'success',
                'head_sha': 'a' * 40,
            },
        }
        body = json.dumps(payload).encode('utf-8')
        signature = 'sha256=' + hmac.new(
            self.secret.encode('utf-8'), body, hashlib.sha256,
        ).hexdigest()
        headers.setdefault('HTTP_X_HUB_SIGNATURE_256', signature)
        headers.setdefault('HTTP_X_GITHUB_DELIVERY', 'delivery-123')
        headers.setdefault('HTTP_X_GITHUB_EVENT', 'workflow_run')
        with mock.patch.dict(os.environ, {'GITHUB_WEBHOOK_SECRET': self.secret}):
            return self.client.post(
                reverse('workflow_run'), body,
                content_type='application/json', **headers
            )

    @mock.patch('devops.github_integration.enqueue_background_job')
    def test_successful_workflow_queues_exact_pending_release(self, enqueue):
        response = self.post_webhook()

        self.assertEqual(response.status_code, 202)
        self.assertEqual(response.json()['code'], 'deployment_queued')
        enqueue.assert_called_once()
        self.assertEqual(enqueue.call_args[0][1].id, self.release.id)
        log = AuditLog.objects.get(action='GitHub workflow_run delivery')
        self.assertEqual(log.target_id, 'delivery-123')
        self.assertNotIn(self.secret, log.detail)

    @mock.patch('devops.github_integration.record_integration_health_event', side_effect=RuntimeError('unavailable'))
    @mock.patch('devops.github_integration.enqueue_background_job')
    def test_health_write_failure_does_not_change_successful_delivery(self, enqueue, unused_health):
        response = self.post_webhook()

        self.assertEqual(response.status_code, 202)
        self.assertEqual(response.json()['code'], 'deployment_queued')
        enqueue.assert_called_once()

    @mock.patch('devops.github_integration.enqueue_background_job')
    def test_duplicate_delivery_is_not_queued_twice(self, enqueue):
        self.post_webhook()
        response = self.post_webhook()

        self.assertEqual(response.status_code, 202)
        self.assertEqual(response.json()['code'], 'duplicate_delivery')
        self.assertEqual(enqueue.call_count, 1)

    @mock.patch('devops.github_integration.enqueue_background_job')
    def test_invalid_signature_cannot_queue_deployment(self, enqueue):
        response = self.post_webhook(HTTP_X_HUB_SIGNATURE_256='sha256=' + ('0' * 64))

        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json()['code'], 'invalid_signature')
        self.assertFalse(enqueue.called)
        self.assertFalse(AuditLog.objects.exists())
        health = IntegrationHealthEvent.objects.get()
        self.assertEqual(health.status, IntegrationHealthEvent.STATUS_FAILED)
        self.assertEqual(health.category, IntegrationHealthEvent.CATEGORY_REJECTED)
        self.assertNotIn(self.secret, health.summary)

    @mock.patch('devops.github_integration.enqueue_background_job')
    def test_non_successful_run_is_ignored(self, enqueue):
        response = self.post_webhook({
            'repository': {'full_name': 'example/web'},
            'workflow_run': {
                'status': 'in_progress',
                'conclusion': None,
                'head_sha': 'a' * 40,
            },
        })

        self.assertEqual(response.status_code, 202)
        self.assertEqual(response.json()['code'], 'ignored_workflow_status')
        self.assertFalse(enqueue.called)
        health = IntegrationHealthEvent.objects.get()
        self.assertEqual(health.status, IntegrationHealthEvent.STATUS_SUCCESS)
        self.assertEqual(health.category, IntegrationHealthEvent.CATEGORY_OK)

    @mock.patch('devops.github_integration.enqueue_background_job')
    def test_non_matching_repository_does_not_queue(self, enqueue):
        response = self.post_webhook({
            'repository': {'full_name': 'other/web'},
            'workflow_run': {
                'status': 'completed',
                'conclusion': 'success',
                'head_sha': 'a' * 40,
            },
        })

        self.assertEqual(response.status_code, 202)
        self.assertEqual(response.json()['code'], 'release_not_found')
        self.assertFalse(enqueue.called)

    @mock.patch('devops.github_integration.enqueue_background_job')
    def test_pending_or_forced_deployment_approval_prevents_webhook_queueing(self, enqueue):
        ApprovalRequest.objects.create(
            request_type=ApprovalRequest.TYPE_DEPLOYMENT,
            title='deployment approval',
            deployment_release=self.release,
        )

        response = self.post_webhook(HTTP_X_GITHUB_DELIVERY='delivery-awaiting-pending')

        self.assertEqual(response.status_code, 202)
        self.assertEqual(response.json()['code'], 'awaiting_approval')
        self.assertFalse(enqueue.called)
        self.assertIn('awaiting approval', AuditLog.objects.get(
            target_id='delivery-awaiting-pending',
        ).detail)

        ApprovalRequest.objects.all().delete()
        setting = DevOpsSetting.current()
        setting.force_deploy_approval = True
        setting.save()
        response = self.post_webhook(HTTP_X_GITHUB_DELIVERY='delivery-awaiting-forced')
        self.assertEqual(response.status_code, 202)
        self.assertEqual(response.json()['code'], 'awaiting_approval')
        self.assertFalse(enqueue.called)
