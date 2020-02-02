from django.db import models
# Create your models here.


class Monitor(models.Model):
    monitor_email = models.EmailField(blank=True)
    monitor_cpu = models.CharField(max_length=100, blank=True)
    monitor_men = models.CharField(max_length=100, blank=True)
    monitor_disk = models.CharField(max_length=100, blank=True)

    class Meta:
        db_table = "monitor-info"
