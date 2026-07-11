from django.db import models
from PyLinux.crypto import decrypt_text, encrypt_text
# Create your models here.


class Monitor(models.Model):
    monitor_email = models.EmailField(blank=True)
    monitor_cpu = models.CharField(max_length=100, blank=True)
    monitor_men = models.CharField(max_length=100, blank=True)
    monitor_disk = models.CharField(max_length=100, blank=True)

    class Meta:
        db_table = "monitor-info"


class PrometheusConfig(models.Model):
    prometheus_url = models.URLField(max_length=500, blank=True)
    enabled = models.BooleanField(default=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "monitor-prometheus-config"


class AlertNotificationConfig(models.Model):
    PROVIDER_FEISHU = 'feishu'
    PROVIDER_WECOM = 'wecom'
    PROVIDER_CHOICES = (
        (PROVIDER_FEISHU, '飞书'),
        (PROVIDER_WECOM, '企业微信'),
    )

    provider = models.CharField(max_length=20, choices=PROVIDER_CHOICES, unique=True)
    name = models.CharField(max_length=100, blank=True)
    webhook_url = models.TextField(blank=True)
    enabled = models.BooleanField(default=False)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "monitor-alert-notification"

    @property
    def decrypted_webhook_url(self):
        return decrypt_text(self.webhook_url)

    def save(self, *args, **kwargs):
        self.webhook_url = encrypt_text(self.webhook_url)
        super(AlertNotificationConfig, self).save(*args, **kwargs)
