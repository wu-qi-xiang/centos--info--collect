from django.test import TestCase

from RemoteLinux.models import NewLinux
from devops.models import AlertEvent, AlertQualityFeedback

from .alert_quality import build_alert_quality_suggestions


class AlertQualitySuggestionTests(TestCase):
    def test_repeated_noise_feedback_produces_safe_threshold_suggestion(self):
        host = NewLinux.objects.create(linux_name='quality-host', linux_ip='127.0.0.241', linux_hostname='quality-host')
        for index in range(2):
            alert = AlertEvent.objects.create(host=host, metric='cpu', message='private alert %s' % index)
            AlertQualityFeedback.objects.create(alert=alert, classification=AlertQualityFeedback.CLASSIFICATION_NOISE)

        suggestions = build_alert_quality_suggestions([host])

        self.assertEqual(suggestions[0]['metric'], 'cpu')
        self.assertEqual(suggestions[0]['action'], 'review_threshold')
        self.assertEqual(suggestions[0]['feedback_count'], 2)
        self.assertNotIn('private alert', repr(suggestions))
