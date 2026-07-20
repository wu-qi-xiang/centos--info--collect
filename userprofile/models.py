from django.db import models

from RemoteLinux.models import User


class ExternalIdentity(models.Model):
	"""A stable external provider identity bound to one local platform user."""

	PROVIDER_OIDC = 'oidc'
	PROVIDER_LDAP = 'ldap'
	PROVIDER_CHOICES = (
		(PROVIDER_OIDC, 'OIDC'),
		(PROVIDER_LDAP, 'LDAP'),
	)

	provider = models.CharField(max_length=20, choices=PROVIDER_CHOICES)
	subject = models.CharField(max_length=255)
	user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='external_identity')
	created_at = models.DateTimeField(auto_now_add=True)
	updated_at = models.DateTimeField(auto_now=True)

	class Meta:
		db_table = 'userprofile_external_identity'
		unique_together = ('provider', 'subject')

	def __str__(self):
		return '%s:%s' % (self.provider, self.user.user)
