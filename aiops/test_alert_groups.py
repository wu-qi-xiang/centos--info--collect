from datetime import timedelta

from django.test import TestCase
from django.utils import timezone

from RemoteLinux.models import NewLinux
from devops.models import AlertEvent, AlertQualityFeedback, Incident

from .alert_groups import build_alert_groups


class AlertGroupTests(TestCase):
    def setUp(self):
        self.host = NewLinux.objects.create(linux_name='group-a', linux_ip='127.0.0.251', linux_hostname='group-a')
        self.other = NewLinux.objects.create(linux_name='group-b', linux_ip='127.0.0.252', linux_hostname='group-b')
        self.hidden = NewLinux.objects.create(linux_name='group-hidden', linux_ip='127.0.0.253', linux_hostname='group-hidden')
        self.now = timezone.now()

    def alert(self, host, metric, level, status=AlertEvent.STATUS_OPEN, repeats=1):
        alert = AlertEvent.objects.create(
            host=host, metric=metric, level=level, status=status,
            repeat_count=repeats, fingerprint='%s:%s:%s' % (host.id, metric, level),
            message='private alert message', remark='private remark',
        )
        AlertEvent.objects.filter(pk=alert.pk).update(updated_at=self.now)
        return alert

    def test_groups_visible_active_alerts_without_raw_text(self):
        first = self.alert(self.host, 'cpu', AlertEvent.LEVEL_CRITICAL, repeats=3)
        second = self.alert(self.other, 'cpu', AlertEvent.LEVEL_CRITICAL, AlertEvent.STATUS_SILENCED, repeats=2)
        Incident.objects.create(alert=first, host=self.host, status=Incident.STATUS_PROCESSING, title='private incident')
        self.alert(self.hidden, 'cpu', AlertEvent.LEVEL_CRITICAL, repeats=9)
        resolved = self.alert(self.host, 'cpu', AlertEvent.LEVEL_CRITICAL, AlertEvent.STATUS_RESOLVED, repeats=7)
        AlertEvent.objects.filter(pk=resolved.pk).update(updated_at=self.now)

        groups = build_alert_groups([self.host, self.other], self.now - timedelta(hours=24), self.now)

        self.assertEqual(len(groups), 1)
        group = groups[0]
        self.assertEqual(group['key'], 'cpu:critical')
        self.assertEqual(group['host_count'], 2)
        self.assertEqual(group['active_count'], 1)
        self.assertEqual(group['silenced_count'], 1)
        self.assertEqual(group['repeat_count'], 5)
        self.assertEqual(group['incident_statuses'], ['processing'])
        self.assertNotIn('private', repr(group))

    def test_empty_scope_returns_empty_groups(self):
        self.assertEqual(build_alert_groups([], self.now - timedelta(hours=6), self.now), [])

    def test_groups_replace_non_public_metric_and_level(self):
        self.alert(self.host, 'private-token-identifier', 'escalated')

        groups = build_alert_groups([self.host], self.now - timedelta(hours=6), self.now)

        self.assertEqual(groups, [{
            'key': 'other:unknown',
            'metric': 'other',
            'level': 'unknown',
            'host_count': 1,
            'active_count': 1,
            'silenced_count': 0,
            'repeat_count': 1,
            'incident_statuses': [],
            'quality_feedback_counts': {'valid': 0, 'noise': 0, 'duplicate': 0, 'threshold': 0},
            'quality_state': 'normal',
            'recommendation': '优先建立或更新事件并检查近期变更',
        }])
        self.assertNotIn('private-token-identifier', repr(groups))
        self.assertNotIn('escalated', repr(groups))

    def test_groups_include_safe_quality_feedback_counts(self):
        alert = self.alert(self.host, 'cpu', AlertEvent.LEVEL_CRITICAL, repeats=3)
        AlertQualityFeedback.objects.create(
            alert=alert, classification=AlertQualityFeedback.CLASSIFICATION_NOISE,
            note='private feedback',
        )
        AlertQualityFeedback.objects.create(
            alert=alert, classification=AlertQualityFeedback.CLASSIFICATION_DUPLICATE,
            note='private duplicate feedback',
        )

        group = build_alert_groups([self.host], self.now - timedelta(hours=6), self.now)[0]

        self.assertEqual(group['quality_feedback_counts'], {
            'valid': 0, 'noise': 1, 'duplicate': 1, 'threshold': 0,
        })
        self.assertEqual(group['quality_state'], 'needs_review')
        self.assertIn('质量反馈', group['recommendation'])
        self.assertNotIn('private feedback', repr(group))
