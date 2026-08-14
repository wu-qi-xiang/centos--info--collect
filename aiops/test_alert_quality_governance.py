from django.core.exceptions import ValidationError
from django.test import TestCase

from RemoteLinux.models import User
from RemoteLinux.models import NewLinux
from devops.models import (
    AlertEvent,
    AlertQualityFeedback,
    AlertQualityGovernanceReview,
    K8sCluster,
    PrometheusRuleRevision,
)

from .alert_quality import (
    alert_quality_suggestion_key,
    build_alert_quality_governance,
    serialize_alert_quality_governance_review,
    synchronize_alert_quality_governance_reviews,
    transition_alert_quality_governance_review,
)


class AlertQualityGovernanceReviewTests(TestCase):
    def setUp(self):
        self.actor = User.objects.create(
            user='quality-reviewer', email='quality-reviewer@example.com',
            password='pwd', confirm_pwd='pwd',
        )
        self.suggestion = {
            'metric': 'latency',
            'classification': AlertQualityFeedback.CLASSIFICATION_NOISE,
            'action': 'review_threshold',
        }

    def test_sync_is_idempotent_and_uses_stable_key(self):
        first = synchronize_alert_quality_governance_reviews([self.suggestion])
        second = synchronize_alert_quality_governance_reviews([self.suggestion])
        self.assertEqual(len(first), 1)
        self.assertTrue(first[0][1])
        self.assertFalse(second[0][1])
        self.assertEqual(AlertQualityGovernanceReview.objects.count(), 1)
        self.assertEqual(first[0][0].suggestion_key, alert_quality_suggestion_key(
            'latency', AlertQualityFeedback.CLASSIFICATION_NOISE, 'review_threshold',
        ))

    def test_suggestions_include_the_same_stable_key(self):
        host = NewLinux.objects.create(
            linux_name='governance-key-host', linux_ip='127.0.0.252', linux_hostname='governance-key-host',
        )
        for index in range(2):
            alert = AlertEvent.objects.create(host=host, metric='latency', message='private %s' % index)
            AlertQualityFeedback.objects.create(alert=alert, classification=AlertQualityFeedback.CLASSIFICATION_NOISE)
        suggestion = build_alert_quality_governance([host])['suggestions'][0]
        self.assertEqual(suggestion['suggestion_key'], alert_quality_suggestion_key(
            'latency', AlertQualityFeedback.CLASSIFICATION_NOISE, 'review_threshold',
        ))

    def test_transition_requires_valid_order_and_is_idempotent(self):
        review = synchronize_alert_quality_governance_reviews([self.suggestion])[0][0]
        invalid = transition_alert_quality_governance_review(
            review, AlertQualityGovernanceReview.STATUS_IMPLEMENTED, self.actor,
        )
        self.assertFalse(invalid['ok'])
        accepted = transition_alert_quality_governance_review(
            review, AlertQualityGovernanceReview.STATUS_ACCEPTED, self.actor,
            note='计划创建规则修订',
        )
        self.assertTrue(accepted['ok'])
        repeated = transition_alert_quality_governance_review(
            review, AlertQualityGovernanceReview.STATUS_ACCEPTED, self.actor,
        )
        self.assertTrue(repeated['ok'])
        self.assertEqual(repeated['code'], 'idempotent')
        implemented = transition_alert_quality_governance_review(
            review, AlertQualityGovernanceReview.STATUS_IMPLEMENTED, self.actor,
        )
        self.assertTrue(implemented['ok'])
        review.refresh_from_db()
        self.assertEqual(review.status, AlertQualityGovernanceReview.STATUS_IMPLEMENTED)
        self.assertIsNotNone(review.implemented_at)

    def test_rule_revision_reference_and_safe_serialization(self):
        review = synchronize_alert_quality_governance_reviews([self.suggestion])[0][0]
        cluster = K8sCluster.objects.create(
            name='quality-review-cluster', kubeconfig='apiVersion: v1', created_by='test',
        )
        revision = PrometheusRuleRevision.objects.create(
            cluster=cluster, namespace='default', name='latency-rule',
            action=PrometheusRuleRevision.ACTION_UPDATE, desired_yaml='private: rule',
            desired_digest='a' * 64, baseline_resource_version='1', created_by=self.actor,
        )
        transition_alert_quality_governance_review(
            review, AlertQualityGovernanceReview.STATUS_ACCEPTED, self.actor,
            note='private reviewer rationale', rule_revision=revision,
        )
        review.refresh_from_db()
        payload = serialize_alert_quality_governance_review(review)
        self.assertEqual(payload['rule_revision_id'], revision.id)
        self.assertTrue(payload['review_note_present'])
        self.assertNotIn('private reviewer rationale', repr(payload))
        self.assertNotIn('private: rule', repr(payload))

    def test_model_identity_is_immutable(self):
        review = synchronize_alert_quality_governance_reviews([self.suggestion])[0][0]
        review.metric = 'cpu'
        with self.assertRaises(ValidationError):
            review.full_clean()
