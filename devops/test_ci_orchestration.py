import hashlib
import hmac
import json
import os

try:
    from unittest import mock
except ImportError:
    import mock

from django.test import SimpleTestCase, TestCase
from django.urls import reverse

from .ci_orchestration import (
    CIValidationError,
    delivery_fingerprint,
    parse_ci_delivery,
)
from .models import CIDelivery, DeploymentApp, DeploymentRelease
from .services import execute_deployment_release


class CIOrchestrationTests(SimpleTestCase):
    def test_parses_whitelisted_gitlab_delivery_into_safe_summary(self):
        delivery = parse_ci_delivery('gitlab', {
            'repository': 'Platform/API',
            'status': 'success',
            'delivery_id': 'pipeline-42',
            'revision': 'a' * 40,
            'ignored_metadata': {'stage': 'build'},
        })

        self.assertEqual(delivery['provider'], 'gitlab')
        self.assertEqual(delivery['repository'], 'platform/api')
        self.assertEqual(delivery['status'], 'success')
        self.assertEqual(delivery['delivery_id'], 'pipeline-42')
        self.assertEqual(delivery['revision'], 'a' * 40)
        self.assertEqual(
            delivery['summary'],
            'GitLab CI status success for platform/api.',
        )
        self.assertEqual(set(delivery), {
            'provider', 'repository', 'status', 'delivery_id', 'revision',
            'fingerprint', 'summary',
        })

    def test_parses_allowed_jenkins_status(self):
        delivery = parse_ci_delivery('jenkins', {
            'repository': 'team/service',
            'status': 'failed',
            'delivery_id': 'job-8-build-19',
        })

        self.assertEqual(delivery['provider'], 'jenkins')
        self.assertEqual(delivery['status'], 'failed')
        self.assertEqual(delivery['revision'], '')

    def test_rejects_unknown_provider(self):
        with self.assertRaisesRegex(CIValidationError, 'unsupported_provider'):
            parse_ci_delivery('github', {
                'repository': 'team/service',
                'status': 'success',
                'delivery_id': 'run-1',
            })

    def test_rejects_malformed_repository_identity(self):
        with self.assertRaisesRegex(CIValidationError, 'invalid_repository'):
            parse_ci_delivery('gitlab', {
                'repository': 'team/../../service',
                'status': 'success',
                'delivery_id': 'pipeline-42',
            })

    def test_rejects_disallowed_status(self):
        with self.assertRaisesRegex(CIValidationError, 'invalid_status'):
            parse_ci_delivery('jenkins', {
                'repository': 'team/service',
                'status': 'unstable',
                'delivery_id': 'job-8',
            })

    def test_rejects_payload_containing_sensitive_or_executable_fields(self):
        for field in ('token', 'webhook_url', 'build_log', 'deploy_command'):
            with self.subTest(field=field):
                with self.assertRaisesRegex(CIValidationError, 'unsafe_payload'):
                    parse_ci_delivery('gitlab', {
                        'repository': 'team/service',
                        'status': 'success',
                        'delivery_id': 'pipeline-42',
                        field: 'sensitive value',
                    })

    def test_delivery_fingerprint_is_stable_and_provider_scoped(self):
        first = delivery_fingerprint('gitlab', 'team/service', 'pipeline-42')
        second = delivery_fingerprint('gitlab', 'TEAM/SERVICE', 'pipeline-42')
        other_provider = delivery_fingerprint('jenkins', 'team/service', 'pipeline-42')

        self.assertEqual(first, second)
        self.assertNotEqual(first, other_provider)
        self.assertRegex(first, r'^[0-9a-f]{64}$')


class CIDeliveryWebhookTests(TestCase):
    secret = 'ci-webhook-test-secret'

    def setUp(self):
        self.app = DeploymentApp.objects.create(
            name='CI app', repository='team/service',
        )
        self.release = DeploymentRelease.objects.create(
            app=self.app, version='a' * 40, deploy_script='echo deploy',
        )

    def post_delivery(self, provider='gitlab', payload=None, signature=None):
        payload = payload or {
            'repository': 'team/service',
            'status': 'success',
            'delivery_id': 'pipeline-42',
            'revision': 'a' * 40,
        }
        body = json.dumps(payload).encode('utf-8')
        signature = signature or 'sha256=' + hmac.new(
            self.secret.encode('utf-8'), body, hashlib.sha256,
        ).hexdigest()
        secret_name = '%s_CI_WEBHOOK_SECRET' % provider.upper()
        with mock.patch.dict(os.environ, {secret_name: self.secret}, clear=False):
            return self.client.post(
                reverse('devops:api_ci_deliveries', args=[provider]), body,
                content_type='application/json', HTTP_X_CI_SIGNATURE=signature,
            )

    @mock.patch('devops.api.enqueue_background_job')
    def test_signed_successful_delivery_persists_safe_summary_without_queueing_release(self, enqueue):
        response = self.post_delivery()

        self.assertEqual(response.status_code, 202)
        self.assertEqual(response.json()['code'], 'delivery_recorded')
        enqueue.assert_not_called()
        delivery = CIDelivery.objects.get()
        self.assertEqual(delivery.provider, CIDelivery.PROVIDER_GITLAB)
        self.assertEqual(delivery.repository, 'team/service')
        self.assertEqual(delivery.release_id, self.release.id)
        self.assertNotIn(self.secret, delivery.summary)
        self.assertNotIn('echo deploy', delivery.summary)

    def test_duplicate_delivery_is_idempotent(self):
        self.post_delivery()
        response = self.post_delivery()

        self.assertEqual(response.status_code, 202)
        self.assertEqual(response.json()['code'], 'duplicate_delivery')
        self.assertEqual(CIDelivery.objects.count(), 1)

    @mock.patch('devops.api.enqueue_background_job')
    def test_failed_quality_gate_blocks_matching_release_without_queueing(self, enqueue):
        response = self.post_delivery(payload={
            'repository': 'team/service',
            'status': 'failed',
            'delivery_id': 'pipeline-failed',
            'revision': 'a' * 40,
        })

        self.assertEqual(response.status_code, 202)
        self.assertEqual(response.json()['code'], 'release_blocked')
        self.release.refresh_from_db()
        self.assertEqual(self.release.status, DeploymentRelease.STATUS_BLOCKED)
        enqueue.assert_not_called()

    @mock.patch('devops.api.enqueue_background_job')
    def test_running_delivery_keeps_release_pending_when_execution_is_requested(self, enqueue):
        response = self.post_delivery(payload={
            'repository': 'team/service',
            'status': 'running',
            'delivery_id': 'pipeline-running',
            'revision': 'a' * 40,
        })

        self.assertEqual(response.status_code, 202)
        self.assertEqual(response.json()['code'], 'delivery_recorded')
        execute_deployment_release(self.release)
        self.release.refresh_from_db()
        self.assertEqual(self.release.status, DeploymentRelease.STATUS_PENDING)
        enqueue.assert_not_called()

    def test_invalid_signature_cannot_persist_or_queue(self):
        response = self.post_delivery(signature='sha256=' + ('0' * 64))

        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json()['code'], 'invalid_signature')
        self.assertFalse(CIDelivery.objects.exists())

    def test_unsafe_payload_is_not_persisted(self):
        response = self.post_delivery(payload={
            'repository': 'team/service',
            'status': 'success',
            'delivery_id': 'pipeline-unsafe',
            'token': 'must-not-store',
        })

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()['code'], 'unsafe_payload')
        self.assertFalse(CIDelivery.objects.exists())

    def test_ci_delivery_summary_requires_session_authentication(self):
        response = self.client.get('/devops/api/ci-deliveries/')

        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json()['code'], 'unauthorized')
