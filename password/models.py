from django.db import models

# Create your models here.


class Password(models.Model):
	system_name = models.CharField(max_length=100)
	account = models.CharField(max_length=100)
	password = models.CharField(max_length=100)
	remark = models.CharField(max_length=100, blank=True)
	auther = models.CharField(max_length=100, blank=True)

	class Meta:
		db_table = "password_manage"