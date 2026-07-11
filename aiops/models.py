from django.db import models


class AiopsIntegration(models.Model):
	alertmanager_url = models.URLField(blank=True)
	llm_url = models.URLField(blank=True)
	llm_api_key = models.CharField(max_length=300, blank=True)
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
	raw_payload = models.TextField()
	summary = models.TextField(blank=True)
	suggestion = models.TextField(blank=True)
	llm_response = models.TextField(blank=True)
	status = models.CharField(max_length=20, choices=STATUS_CHOICES, default=STATUS_RECEIVED)
	error = models.TextField(blank=True)
	created_at = models.DateTimeField(auto_now_add=True)
	updated_at = models.DateTimeField(auto_now=True)

	class Meta:
		db_table = 'aiops_alert_analysis'
		ordering = ['-created_at']
