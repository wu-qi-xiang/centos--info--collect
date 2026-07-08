from django.core.management.base import BaseCommand
from django.utils import timezone

from devops.models import AuditLog
from devops.services import cleanup_audit_logs


class Command(BaseCommand):
	help = '清理超过保留天数的 DevOps 审计日志'

	def add_arguments(self, parser):
		parser.add_argument('--days', type=int, default=None, help='保留天数；默认读取 AUDIT_LOG_RETENTION_DAYS')
		parser.add_argument('--dry-run', action='store_true', help='只显示将被清理的数量，不删除数据')

	def handle(self, *args, **options):
		days = options.get('days')
		if days is None:
			from django.conf import settings
			days = int(getattr(settings, 'AUDIT_LOG_RETENTION_DAYS', 0) or 0)
		if days <= 0:
			self.stdout.write('审计日志保留策略未启用')
			return
		cutoff = timezone.now() - timezone.timedelta(days=days)
		count = AuditLog.objects.filter(created_at__lt=cutoff).count()
		if options.get('dry_run'):
			self.stdout.write('将清理 %s 条审计日志' % count)
			return
		deleted = cleanup_audit_logs(days)
		self.stdout.write('已清理 %s 条审计日志' % deleted)
