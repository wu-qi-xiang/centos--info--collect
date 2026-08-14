"""Deterministic, safe alert-quality suggestions for AIOps."""

from collections import defaultdict
import hashlib
import re

from django.db import transaction
from django.db.models import Count
from django.utils import timezone

from devops.models import AlertQualityFeedback, AlertQualityGovernanceReview


MIN_FEEDBACK_COUNT = 2
SAFE_METRIC_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9_.:-]{0,49}$')
REVIEW_TRANSITIONS = {
    AlertQualityGovernanceReview.STATUS_OPEN: frozenset((
        AlertQualityGovernanceReview.STATUS_ACCEPTED,
        AlertQualityGovernanceReview.STATUS_REJECTED,
    )),
    AlertQualityGovernanceReview.STATUS_ACCEPTED: frozenset((
        AlertQualityGovernanceReview.STATUS_IMPLEMENTED,
        AlertQualityGovernanceReview.STATUS_REJECTED,
    )),
    AlertQualityGovernanceReview.STATUS_REJECTED: frozenset((
        AlertQualityGovernanceReview.STATUS_OPEN,
    )),
    AlertQualityGovernanceReview.STATUS_IMPLEMENTED: frozenset((
        AlertQualityGovernanceReview.STATUS_OPEN,
    )),
}


def _safe_metric(metric):
    metric = (metric or '').strip()
    return metric if SAFE_METRIC_RE.match(metric) else 'other'


def alert_quality_suggestion_key(metric, classification, action):
    """Return a stable key without placing user-controlled text in storage."""
    identity = '%s|%s|%s' % (_safe_metric(metric), classification or '', action or '')
    return 'aqg-' + hashlib.sha256(identity.encode('utf-8')).hexdigest()[:56]


def _safe_review_note(note):
    if not isinstance(note, str):
        return None
    note = ' '.join(note.split())
    return note if len(note) <= 500 else None


def serialize_alert_quality_governance_review(review):
    """Return audit-friendly metadata without exposing reviewer notes."""
    return {
        'id': review.id,
        'suggestion_key': review.suggestion_key,
        'metric': review.metric,
        'classification': review.classification,
        'action': review.action,
        'status': review.status,
        'review_note_present': bool(review.review_note),
        'reviewed_by': review.reviewed_by.user if review.reviewed_by else None,
        'rule_revision_id': review.rule_revision_id,
        'first_seen_at': review.first_seen_at.strftime('%Y-%m-%d %H:%M:%S'),
        'last_seen_at': review.last_seen_at.strftime('%Y-%m-%d %H:%M:%S'),
        'reviewed_at': review.reviewed_at.strftime('%Y-%m-%d %H:%M:%S') if review.reviewed_at else None,
        'implemented_at': review.implemented_at.strftime('%Y-%m-%d %H:%M:%S') if review.implemented_at else None,
    }


def synchronize_alert_quality_governance_reviews(suggestions):
    """Upsert review records by stable suggestion key without changing status."""
    reviews = []
    with transaction.atomic():
        for suggestion in suggestions or []:
            if not isinstance(suggestion, dict):
                continue
            metric = _safe_metric(suggestion.get('metric'))
            classification = suggestion.get('classification') or ''
            action = suggestion.get('action') or ''
            if classification not in dict(AlertQualityFeedback.CLASSIFICATION_CHOICES) or not action:
                continue
            key = alert_quality_suggestion_key(metric, classification, action)
            review, created = AlertQualityGovernanceReview.objects.get_or_create(
                suggestion_key=key,
                defaults={
                    'metric': metric,
                    'classification': classification,
                    'action': action,
                },
            )
            reviews.append((review, created))
    return reviews


def transition_alert_quality_governance_review(review, status, actor, note='', rule_revision=None):
    """Apply an explicit, idempotent governance review transition.

    This does not modify a Prometheus rule.  A referenced revision is metadata
    only and is intentionally optional until an implementation is available.
    """
    if not review or not getattr(review, 'pk', None) or not actor or not getattr(actor, 'pk', None):
        return {'ok': False, 'code': 'validation_error', 'message': '审核记录或审核人无效。'}
    if status not in dict(AlertQualityGovernanceReview.STATUS_CHOICES):
        return {'ok': False, 'code': 'validation_error', 'message': '审核状态无效。'}
    note = _safe_review_note(note)
    if note is None:
        return {'ok': False, 'code': 'validation_error', 'message': '审核备注无效。'}
    if rule_revision is not None and not getattr(rule_revision, 'pk', None):
        return {'ok': False, 'code': 'validation_error', 'message': '规则修订引用无效。'}
    with transaction.atomic():
        locked = AlertQualityGovernanceReview.objects.select_for_update().get(pk=review.pk)
        if locked.status == status:
            metadata_changed = (bool(note) and note != locked.review_note) or (
                rule_revision is not None and rule_revision.pk != locked.rule_revision_id
            )
            if metadata_changed:
                locked.review_note = note
                locked.reviewed_by = actor
                locked.reviewed_at = timezone.now()
                if rule_revision is not None:
                    locked.rule_revision = rule_revision
                locked.save(update_fields=[
                    'review_note', 'reviewed_by', 'reviewed_at', 'rule_revision',
                    'last_seen_at', 'updated_at',
                ])
                return {'ok': True, 'code': 'updated', 'message': '审核备注或规则引用已更新。',
                        'review': serialize_alert_quality_governance_review(locked)}
            return {'ok': True, 'code': 'idempotent', 'message': '审核状态未变化。',
                    'review': serialize_alert_quality_governance_review(locked)}
        if status not in REVIEW_TRANSITIONS.get(locked.status, frozenset()):
            return {'ok': False, 'code': 'invalid_transition', 'message': '审核状态转换无效。'}
        now = timezone.now()
        locked.status = status
        locked.review_note = note
        locked.reviewed_by = actor
        locked.reviewed_at = now
        if rule_revision is not None:
            locked.rule_revision = rule_revision
        if status == AlertQualityGovernanceReview.STATUS_IMPLEMENTED:
            locked.implemented_at = now
        elif status == AlertQualityGovernanceReview.STATUS_OPEN:
            locked.implemented_at = None
        locked.save(update_fields=[
            'status', 'review_note', 'reviewed_by', 'reviewed_at', 'rule_revision',
            'implemented_at', 'last_seen_at', 'updated_at',
        ])
    return {'ok': True, 'code': 'ok', 'message': '审核状态已更新。',
            'review': serialize_alert_quality_governance_review(locked)}


def build_alert_quality_governance(hosts):
    """Build safe, review-only alert-quality governance data for scoped hosts.

    The result intentionally contains metric-level aggregates only.  Alert
    messages and feedback notes are never exposed, and no rule is changed.
    """
    host_ids = [host.id for host in hosts]
    if not host_ids:
        return {
            'summary': {
                'feedback_count': 0,
                'noise_count': 0,
                'duplicate_count': 0,
                'threshold_count': 0,
                'suggestion_count': 0,
            },
            'suggestions': [],
        }
    rows = list(AlertQualityFeedback.objects.filter(
        alert__host_id__in=host_ids,
    ).values('alert__metric', 'classification').annotate(
        feedback_count=Count('id'),
        alert_count=Count('alert_id', distinct=True),
        host_count=Count('alert__host_id', distinct=True),
    ))
    totals = defaultdict(int)
    for row in rows:
        totals[row['classification']] += row['feedback_count']
    suggestions = []
    action_map = {
        AlertQualityFeedback.CLASSIFICATION_NOISE: (
            'review_threshold', '审核阈值与持续时间',
        ),
        AlertQualityFeedback.CLASSIFICATION_DUPLICATE: (
            'review_deduplication', '审核聚合与去重规则',
        ),
        AlertQualityFeedback.CLASSIFICATION_THRESHOLD: (
            'review_threshold', '审核触发条件',
        ),
    }
    for row in rows:
        classification = row['classification']
        count = row['feedback_count']
        if classification not in action_map:
            continue
        if classification != AlertQualityFeedback.CLASSIFICATION_THRESHOLD and count < MIN_FEEDBACK_COUNT:
            continue
        priority = 'critical' if count >= 5 else ('high' if count >= 3 else 'medium')
        action, action_label = action_map[classification]
        suggestions.append({
            'metric': row['alert__metric'] or 'unknown',
            'classification': classification,
            'feedback_count': count,
            'alert_count': row['alert_count'],
            'host_count': row['host_count'],
            'priority': priority,
            'action': action,
            'action_label': action_label,
            'suggestion_key': alert_quality_suggestion_key(
                row['alert__metric'] or 'unknown', classification, action,
            ),
            'review_only': True,
        })
    suggestions.sort(key=lambda item: (
        {'critical': 0, 'high': 1, 'medium': 2}.get(item['priority'], 3),
        -item['feedback_count'], item['metric'], item['action'],
    ))
    return {
        'summary': {
            'feedback_count': sum(totals.values()),
            'noise_count': totals[AlertQualityFeedback.CLASSIFICATION_NOISE],
            'duplicate_count': totals[AlertQualityFeedback.CLASSIFICATION_DUPLICATE],
            'threshold_count': totals[AlertQualityFeedback.CLASSIFICATION_THRESHOLD],
            'suggestion_count': len(suggestions),
        },
        'suggestions': suggestions[:12],
    }


def build_alert_quality_suggestions(hosts):
    host_ids = [host.id for host in hosts]
    if not host_ids:
        return []
    counts = defaultdict(int)
    for row in AlertQualityFeedback.objects.filter(alert__host_id__in=host_ids).values(
            'alert__metric', 'classification'):
        metric = row['alert__metric'] or 'unknown'
        counts[(metric, row['classification'])] += 1
    suggestions = []
    for (metric, classification), count in counts.items():
        if classification == AlertQualityFeedback.CLASSIFICATION_NOISE and count >= MIN_FEEDBACK_COUNT:
            action, summary = 'review_threshold', '噪声反馈达到 %s 次，建议审核阈值或持续时间' % count
        elif classification == AlertQualityFeedback.CLASSIFICATION_DUPLICATE and count >= MIN_FEEDBACK_COUNT:
            action, summary = 'review_deduplication', '重复反馈达到 %s 次，建议审核聚合或去重规则' % count
        elif classification == AlertQualityFeedback.CLASSIFICATION_THRESHOLD:
            action, summary = 'review_threshold', '存在阈值待优化反馈，建议人工复核触发条件'
        else:
            continue
        suggestions.append({
            'metric': metric,
            'classification': classification,
            'feedback_count': count,
            'action': action,
            'suggestion_key': alert_quality_suggestion_key(metric, classification, action),
            'summary': summary,
        })
    return sorted(suggestions, key=lambda item: (-item['feedback_count'], item['metric'], item['action']))[:12]
