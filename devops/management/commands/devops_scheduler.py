import time

from django.conf import settings
from django.core.management.base import BaseCommand

from devops.scheduler import run_due_scheduled_tasks


class Command(BaseCommand):
    help = 'Run durable built-in monitoring and operations scheduler tasks.'

    def add_arguments(self, parser):
        parser.add_argument('--once', action='store_true', help='Run one due-task scan and exit.')
        parser.add_argument('--poll-seconds', type=float, default=None, help='Override the idle polling interval.')

    def handle(self, *args, **options):
        poll_seconds = options['poll_seconds']
        if poll_seconds is None:
            poll_seconds = settings.DEVOPS_SCHEDULER_POLL_SECONDS
        try:
            poll_seconds = max(0.1, float(poll_seconds))
        except (TypeError, ValueError):
            poll_seconds = settings.DEVOPS_SCHEDULER_POLL_SECONDS

        while True:
            result = run_due_scheduled_tasks()
            self.stdout.write('Started %s scheduled task(s).' % len(result['started']))
            if result['failed']:
                self.stderr.write('Failed %s scheduled task(s).' % len(result['failed']))
            if options['once']:
                return
            time.sleep(poll_seconds)
