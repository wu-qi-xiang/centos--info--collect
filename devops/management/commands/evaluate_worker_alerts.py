from django.conf import settings
from django.core.management.base import BaseCommand

from devops.services import record_alert, resolve_alert, summarize_background_jobs


ALERTS = (
    (
        'DEVOPS_WORKER_ALERT_PENDING_THRESHOLD',
        'pending',
        'worker:pending',
        'Worker pending jobs',
    ),
    (
        'DEVOPS_WORKER_ALERT_FAILURE_RATE_PERCENT',
        'recent_failure_rate_percent',
        'worker:failure_rate',
        'Worker recent failure rate',
    ),
    (
        'DEVOPS_WORKER_ALERT_TIMED_OUT_THRESHOLD',
        'timed_out',
        'worker:timed_out',
        'Worker timed-out jobs',
    ),
)


def threshold_value(setting_name):
    try:
        return int(getattr(settings, setting_name, 0))
    except (TypeError, ValueError):
        return 0


class Command(BaseCommand):
    help = 'Evaluate configured DevOps Worker thresholds and maintain system alerts.'

    def handle(self, *args, **options):
        summary = summarize_background_jobs()
        summary['recent_failure_rate_percent'] = round(
            float(summary.get('recent_failure_rate', 0.0)) * 100, 2,
        )
        opened = 0
        resolved = 0
        for setting_name, summary_key, metric, label in ALERTS:
            threshold = threshold_value(setting_name)
            value = summary[summary_key]
            if threshold > 0 and value >= threshold:
                record_alert(
                    None,
                    metric,
                    '%s is %s (threshold %s).' % (label, value, threshold),
                )
                opened += 1
            elif resolve_alert(
                None,
                metric,
                '%s returned below its configured threshold.' % label,
            ):
                resolved += 1
        self.stdout.write(
            'Evaluated Worker alerts: %s threshold breach(es), %s resolved.' % (
                opened, resolved,
            ),
        )
