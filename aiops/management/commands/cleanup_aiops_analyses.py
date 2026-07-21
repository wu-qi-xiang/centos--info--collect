from django.conf import settings
from django.core.management.base import BaseCommand
from django.utils import timezone

from aiops.models import AiopsAlertAnalysis


class Command(BaseCommand):
	help = '清理超过 AIOps 分析记录保留期的记录'

	def handle(self, *args, **options):
		days = int(getattr(settings, 'AIOPS_ANALYSIS_RETENTION_DAYS', 0) or 0)
		if days <= 0:
			self.stdout.write('0')
			return
		cutoff = timezone.now() - timezone.timedelta(days=days)
		deleted, details = AiopsAlertAnalysis.objects.filter(created_at__lt=cutoff).delete()
		self.stdout.write(str(deleted))
