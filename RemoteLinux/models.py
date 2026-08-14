from django.db import models
from django.utils import timezone

# Create your models here.


class NewLinux(models.Model):
	AUTH_PASSWORD = 'password'
	AUTH_KEY = 'key'
	AUTH_CHOICES = (
		(AUTH_PASSWORD, '密码'),
		(AUTH_KEY, 'SSH Key'),
	)

	linux_name = models.CharField(max_length=100,  blank=True)
	linux_ip = models.CharField(max_length=100)
	linux_hostname = models.CharField(max_length=100,  blank=True)
	linux_port = models.CharField(max_length=100)
	linux_user = models.CharField(max_length=100)
	linux_passwd = models.TextField(blank=True)
	linux_auth_type = models.CharField(max_length=20, choices=AUTH_CHOICES, default=AUTH_PASSWORD)
	linux_private_key = models.TextField(blank=True)
	linux_private_key_passphrase = models.TextField(blank=True)
	linux_app = models.CharField(max_length=500, blank=True)

	class Meta:
		db_table = "linux-info"

	def __str__(self):
		return self.linux_name or self.linux_ip


class HostAgent(models.Model):
	"""Outbound-only heartbeat registration for a managed host."""

	host = models.OneToOneField(NewLinux, on_delete=models.CASCADE, related_name='agent')
	registration_id = models.CharField(max_length=64, unique=True)
	credential_hash = models.CharField(max_length=128)
	is_revoked = models.BooleanField(default=False)
	agent_version = models.CharField(max_length=64, blank=True)
	collection_delay_seconds = models.PositiveIntegerField(default=0)
	system_summary = models.JSONField(default=dict, blank=True)
	created_at = models.DateTimeField(auto_now_add=True)
	updated_at = models.DateTimeField(auto_now=True)
	last_heartbeat_at = models.DateTimeField(null=True, blank=True, db_index=True)
	revoked_at = models.DateTimeField(null=True, blank=True)

	class Meta:
		db_table = 'host_agent'

	def revoke(self):
		self.is_revoked = True
		self.revoked_at = timezone.now()
		self.save(update_fields=['is_revoked', 'revoked_at', 'updated_at'])


class User(models.Model):
	user = models.CharField(max_length=100)
	email = models.EmailField(max_length=100)
	password = models.CharField(max_length=128)
	confirm_pwd = models.CharField(max_length=128, default=None)

	class Meta:
		db_table = "user"

	def __str__(self):
		return self.user
