from django.db import models

# Create your models here.


class NewLinux(models.Model):
	linux_name = models.CharField(max_length=100)
	linux_ip = models.CharField(max_length=100)
	linux_port = models.CharField(max_length=100)
	linux_user = models.CharField(max_length=100)
	linux_passwd = models.CharField(max_length=100)

	class Meta:
		db_table = "linux-info"
