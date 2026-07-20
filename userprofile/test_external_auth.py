import ssl
from urllib.parse import urlparse

from django.test import TestCase, override_settings

from devops.models import AuditLog, DevOpsRole
from userprofile.external_auth import (
	ExternalAuthenticationError,
	build_oidc_authorization_url,
	ldap_authenticate,
	_secure_ldap_server,
	provision_external_identity,
)
from userprofile.models import ExternalIdentity


class _JsonResponse(object):
	status_code = 200

	def __init__(self, data):
		self.data = data

	def json(self):
		return self.data


class _Attribute(object):
	def __init__(self, value=None, values=None):
		self.value = value
		self.values = values or []


class _LdapEntry(object):
	entry_dn = 'uid=ops-user,ou=people,dc=example,dc=test'
	mail = _Attribute(value='ops@example.test')
	memberOf = _Attribute(values=['ops-admins'])


class _LdapConnection(object):
	def __init__(self):
		self.entries = [_LdapEntry()]
		self.search_filter = ''
		self.rebind_password = ''
		self.unbound = False

	def search(self, base_dn, search_filter, attributes):
		self.search_filter = search_filter
		return base_dn == 'ou=people,dc=example,dc=test' and attributes == ['mail', 'memberOf']

	def rebind(self, user, password):
		self.rebind_password = password
		return user == self.entries[0].entry_dn and password == 'directory-password'

	def unbind(self):
		self.unbound = True


class _FakeLdap3(object):
	NONE = object()

	def __init__(self):
		self.tls_kwargs = None
		self.server_kwargs = None

	def Tls(self, **kwargs):
		self.tls_kwargs = kwargs
		return 'secure-tls'

	def Server(self, host, **kwargs):
		self.server_kwargs = {'host': host, **kwargs}
		return 'server'


@override_settings(EXTERNAL_AUTH_ROLE_MAP={'ops-admins': 'admin'})
class ExternalIdentityProvisioningTests(TestCase):
	def test_new_identity_is_namespaced_and_mapped_to_existing_role(self):
		outcome = provision_external_identity('oidc', 'subject-123', 'staff@example.com', True, ['ops-admins'])

		self.assertTrue(outcome.created)
		self.assertTrue(outcome.user.user.startswith('ext-oidc-'))
		self.assertEqual(outcome.user.email, 'staff@example.com')
		self.assertEqual(DevOpsRole.objects.get(user=outcome.user).role, DevOpsRole.ROLE_ADMIN)
		identity = ExternalIdentity.objects.get(user=outcome.user)
		self.assertEqual(identity.provider, 'oidc')
		self.assertEqual(identity.subject, 'subject-123')
		log = AuditLog.objects.get(target_id=str(identity.id))
		self.assertNotIn('subject-123', log.detail)
		self.assertNotIn('ops-admins', log.detail)

	def test_each_successful_login_recomputes_to_viewer_without_mapping(self):
		first = provision_external_identity('oidc', 'subject-456', groups=['ops-admins'])
		second = provision_external_identity('oidc', 'subject-456', groups=[])

		self.assertFalse(second.created)
		self.assertEqual(first.user.id, second.user.id)
		self.assertEqual(DevOpsRole.objects.get(user=second.user).role, DevOpsRole.ROLE_VIEWER)

	def test_rejects_oversized_subject(self):
		with self.assertRaises(ExternalAuthenticationError):
			provision_external_identity('oidc', 'x' * 256)


@override_settings(OIDC_CONFIG={
	'enabled': True,
	'discovery_url': 'https://issuer.example/.well-known/openid-configuration',
	'client_id': 'ops-client',
	'client_secret': 'not-used-here',
	'redirect_uri': 'https://ops.example/external/oidc/callback/',
})
class OidcStartTests(TestCase):
	def test_authorization_url_uses_state_nonce_and_discovery_endpoint(self):
		url = build_oidc_authorization_url('state-value', 'nonce-value', http_get=lambda *args, **kwargs: _JsonResponse({
			'issuer': 'https://issuer.example',
			'authorization_endpoint': 'https://issuer.example/authorize',
			'token_endpoint': 'https://issuer.example/token',
			'jwks_uri': 'https://issuer.example/keys',
		}))

		self.assertIn('https://issuer.example/authorize?', url)
		self.assertIn('state=state-value', url)
		self.assertIn('nonce=nonce-value', url)

	def test_authorization_rejects_disabled_or_incomplete_configuration(self):
		with self.settings(OIDC_CONFIG={'enabled': False}):
			with self.assertRaises(ExternalAuthenticationError):
				build_oidc_authorization_url('state', 'nonce')


@override_settings(
	EXTERNAL_AUTH_ROLE_MAP={'ops-admins': 'admin'},
	LDAP_CONFIG={
		'enabled': True,
		'server_uri': 'ldaps://directory.example.test',
		'bind_dn': 'cn=service,dc=example,dc=test',
		'bind_password': 'service-password',
		'base_dn': 'ou=people,dc=example,dc=test',
		'user_filter': '(uid={username})',
		'group_attribute': 'memberOf',
	},
)
class LdapAuthenticationTests(TestCase):
	def test_server_requires_certificate_validation_and_optional_ca_file(self):
		ldap3 = _FakeLdap3()
		server = _secure_ldap_server(
			ldap3,
			'ldaps://directory.example.test:636',
			urlparse('ldaps://directory.example.test:636'),
			{'ca_certs_file': '/etc/ssl/certs/internal-ca.pem'},
		)

		self.assertEqual(server, 'server')
		self.assertEqual(ldap3.tls_kwargs, {
			'validate': ssl.CERT_REQUIRED,
			'ca_certs_file': '/etc/ssl/certs/internal-ca.pem',
		})
		self.assertEqual(ldap3.server_kwargs['host'], 'directory.example.test')
		self.assertTrue(ldap3.server_kwargs['use_ssl'])
		self.assertEqual(ldap3.server_kwargs['tls'], 'secure-tls')

	def test_ldap_escapes_lookup_and_never_stores_directory_dn_or_groups(self):
		connection = _LdapConnection()
		outcome = ldap_authenticate(
			'ops*)(uid=*)', 'directory-password',
			connection_factory=lambda *args: (connection, lambda value: value.replace('*', r'\\2a').replace(')', r'\\29')),
		)

		self.assertIn(r'\\2a', connection.search_filter)
		self.assertIn(r'\\29', connection.search_filter)
		self.assertTrue(connection.unbound)
		identity = ExternalIdentity.objects.get(user=outcome.user)
		self.assertEqual(identity.subject, 'ops*)(uid=*)')
		self.assertNotIn('uid=ops-user', identity.subject)
		self.assertEqual(DevOpsRole.objects.get(user=outcome.user).role, DevOpsRole.ROLE_ADMIN)
