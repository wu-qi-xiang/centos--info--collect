from django.core.validators import MaxValueValidator, MinValueValidator
from django.db import models

from PyLinux.crypto import decrypt_text, encrypt_text
from devops.models import AlertEvent, ApprovalRequest, RunbookTemplate
import re


class AiopsIntegration(models.Model):
	alertmanager_url = models.URLField(blank=True)
	llm_url = models.URLField(blank=True)
	llm_api_key = models.TextField(blank=True)
	llm_model = models.CharField(max_length=100, default='gpt-4o-mini', blank=True)
	enabled = models.BooleanField(default=True)
	updated_by = models.CharField(max_length=100, blank=True)
	updated_at = models.DateTimeField(auto_now=True)

	class Meta:
		db_table = 'aiops_integration'

	@classmethod
	def current(cls):
		config = cls.objects.first()
		if config:
			return config
		return cls.objects.create()

	@property
	def decrypted_llm_api_key(self):
		return decrypt_text(self.llm_api_key)

	def save(self, *args, **kwargs):
		self.llm_api_key = encrypt_text(self.llm_api_key)
		super(AiopsIntegration, self).save(*args, **kwargs)


class AiopsAlertAnalysis(models.Model):
	STATUS_RECEIVED = 'received'
	STATUS_ANALYZED = 'analyzed'
	STATUS_FAILED = 'failed'

	STATUS_CHOICES = (
		(STATUS_RECEIVED, '已接收'),
		(STATUS_ANALYZED, '已分析'),
		(STATUS_FAILED, '分析失败'),
	)

	alert_name = models.CharField(max_length=200, blank=True)
	severity = models.CharField(max_length=50, blank=True)
	instance = models.CharField(max_length=200, blank=True)
	source = models.CharField(max_length=100, default='alertmanager')
	raw_payload = models.TextField(blank=True, default='')
	summary = models.TextField(blank=True)
	suggestion = models.TextField(blank=True)
	llm_response = models.TextField(blank=True, default='')
	status = models.CharField(max_length=20, choices=STATUS_CHOICES, default=STATUS_RECEIVED)
	error = models.TextField(blank=True)
	created_at = models.DateTimeField(auto_now_add=True)
	updated_at = models.DateTimeField(auto_now=True)

	class Meta:
		db_table = 'aiops_alert_analysis'
		ordering = ['-created_at']


class AiopsRunbookRecommendation(models.Model):
	"""A host-scoped AIOps suggestion that can only enter the approval flow."""
	STATUS_RECOMMENDED = 'recommended'
	STATUS_INITIATED = 'initiated'
	STATUS_CHOICES = (
		(STATUS_RECOMMENDED, '已建议'),
		(STATUS_INITIATED, '已提交审批'),
	)

	alert = models.ForeignKey(AlertEvent, on_delete=models.CASCADE, related_name='aiops_runbook_recommendations')
	host = models.ForeignKey('RemoteLinux.NewLinux', on_delete=models.CASCADE, related_name='aiops_runbook_recommendations')
	runbook = models.ForeignKey(RunbookTemplate, on_delete=models.PROTECT, related_name='aiops_runbook_recommendations')
	summary = models.CharField(max_length=300, blank=True)
	status = models.CharField(max_length=20, choices=STATUS_CHOICES, default=STATUS_RECOMMENDED)
	initiated_approval = models.ForeignKey(ApprovalRequest, null=True, blank=True, on_delete=models.SET_NULL)
	created_by = models.CharField(max_length=100, blank=True)
	created_at = models.DateTimeField(auto_now_add=True)
	updated_at = models.DateTimeField(auto_now=True)

	class Meta:
		db_table = 'aiops_runbook_recommendation'
		ordering = ['-created_at', '-id']
		unique_together = ('alert', 'runbook')


class AiopsInvestigation(models.Model):
	"""Persisted, host-scoped metadata for a read-only AIOps investigation."""

	STATUS_OPEN = 'open'
	STATUS_ANALYZING = 'analyzing'
	STATUS_COMPLETED = 'completed'
	STATUS_PARTIAL = 'partial'
	STATUS_FAILED = 'failed'
	STATUS_CHOICES = (
		(STATUS_OPEN, '待分析'),
		(STATUS_ANALYZING, '分析中'),
		(STATUS_COMPLETED, '已完成'),
		(STATUS_PARTIAL, '部分完成'),
		(STATUS_FAILED, '失败'),
	)

	RISK_UNKNOWN = 'unknown'
	RISK_LOW = 'low'
	RISK_MEDIUM = 'medium'
	RISK_HIGH = 'high'
	RISK_CRITICAL = 'critical'
	RISK_CHOICES = (
		(RISK_UNKNOWN, '未知'),
		(RISK_LOW, '低'),
		(RISK_MEDIUM, '中'),
		(RISK_HIGH, '高'),
		(RISK_CRITICAL, '严重'),
	)

	WINDOW_CHOICES = (
		('1h', '最近 1 小时'),
		('6h', '最近 6 小时'),
		('24h', '最近 24 小时'),
		('7d', '最近 7 天'),
	)

	created_by = models.CharField(max_length=100, blank=True)
	status = models.CharField(max_length=20, choices=STATUS_CHOICES, default=STATUS_OPEN, db_index=True)
	title = models.CharField(max_length=200)
	window_key = models.CharField(max_length=20, choices=WINDOW_CHOICES, default='24h')
	window_start = models.DateTimeField()
	window_end = models.DateTimeField()
	hosts = models.ManyToManyField(
		'RemoteLinux.NewLinux', blank=True, related_name='aiops_investigations',
	)
	services = models.ManyToManyField(
		'devops.ServiceCatalog', blank=True, related_name='aiops_investigations',
	)
	risk = models.CharField(max_length=20, choices=RISK_CHOICES, default=RISK_UNKNOWN, db_index=True)
	confidence = models.PositiveSmallIntegerField(
		default=0, validators=[MinValueValidator(0), MaxValueValidator(100)],
	)
	summary = models.CharField(max_length=1000, blank=True)
	root_cause_summary = models.CharField(max_length=2000, blank=True)
	created_at = models.DateTimeField(auto_now_add=True)
	updated_at = models.DateTimeField(auto_now=True)

	class Meta:
		db_table = 'aiops_investigation'
		ordering = ['-created_at', '-id']


class AiopsInvestigationFeedback(models.Model):
	CLASSIFICATION_EFFECTIVE = 'effective'
	CLASSIFICATION_PARTIAL = 'partial'
	CLASSIFICATION_INEFFECTIVE = 'ineffective'
	CLASSIFICATION_CHOICES = ((CLASSIFICATION_EFFECTIVE, '有效'), (CLASSIFICATION_PARTIAL, '部分有效'), (CLASSIFICATION_INEFFECTIVE, '无效'))
	investigation = models.ForeignKey(AiopsInvestigation, on_delete=models.CASCADE, related_name='feedback')
	classification = models.CharField(max_length=20, choices=CLASSIFICATION_CHOICES)
	note = models.CharField(max_length=300, blank=True)
	created_by = models.CharField(max_length=100, blank=True)
	created_at = models.DateTimeField(auto_now_add=True)
	class Meta:
		db_table = 'aiops_investigation_feedback'
		ordering = ['-created_at', '-id']
	def save(self, *args, **kwargs):
		self.note = re.sub(r'https?://\S+|\b(?:token|password|secret|key)\s*[:=]\s*\S+', '[redacted]', self.note or '', flags=re.I)[:300]
		super(AiopsInvestigationFeedback, self).save(*args, **kwargs)
