import time

from django.conf import settings
from django.core.management.base import BaseCommand

from devops.services import fail_timed_out_background_jobs, process_next_background_job


class Command(BaseCommand):
    help = 'Process durable DevOps background jobs.'

    def add_arguments(self, parser):
        parser.add_argument('--once', action='store_true', help='Process at most one queued job and exit.')
        parser.add_argument('--poll-seconds', type=float, default=None, help='Override the idle polling interval.')

    def handle(self, *args, **options):
        poll_seconds = options['poll_seconds']
        if poll_seconds is None:
            poll_seconds = getattr(settings, 'DEVOPS_WORKER_POLL_SECONDS', 2)
        try:
            poll_seconds = max(0.1, float(poll_seconds))
        except (TypeError, ValueError):
            poll_seconds = 2
        max_attempts = getattr(settings, 'DEVOPS_WORKER_MAX_ATTEMPTS', 1)
        job_timeout = getattr(settings, 'DEVOPS_WORKER_JOB_TIMEOUT_SECONDS', 0)

        while True:
            expired = fail_timed_out_background_jobs(job_timeout)
            if expired:
                self.stderr.write('Marked %s timed-out DevOps job(s) failed.' % expired)
            job = process_next_background_job(max_attempts=max_attempts)
            if options['once']:
                if job is None:
                    self.stdout.write('No pending DevOps jobs.')
                else:
                    self.stdout.write('Processed DevOps job %s.' % job.id)
                return
            if job is None:
                time.sleep(poll_seconds)
