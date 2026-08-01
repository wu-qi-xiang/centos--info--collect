"""Deterministic, safe alert-quality suggestions for AIOps."""

from collections import defaultdict

from devops.models import AlertQualityFeedback


MIN_FEEDBACK_COUNT = 2


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
            'summary': summary,
        })
    return sorted(suggestions, key=lambda item: (-item['feedback_count'], item['metric'], item['action']))[:12]
