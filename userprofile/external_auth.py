"""Secure, transport-agnostic external identity authentication helpers.

Views own redirects and sessions.  This module never persists tokens, LDAP
credentials, group claims, or directory distinguished names.
"""
import base64
import hashlib
import json
import os
import ssl
import time
from dataclasses import dataclass
from urllib.parse import urlencode, urlparse

import requests
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from django.conf import settings
from django.contrib.auth.hashers import make_password
from django.core.exceptions import ImproperlyConfigured
from django.db import IntegrityError, transaction

from RemoteLinux.models import User
from devops.models import AuditLog, DevOpsRole
from .models import ExternalIdentity


class ExternalAuthenticationError(Exception):
	"""Deliberately generic error suitable for presenting to an end user."""


@dataclass(frozen=True)
class AuthenticationOutcome:
	user: User
	provider: str
	role: str
	created: bool


ROLE_RANK = {
	DevOpsRole.ROLE_VIEWER: 0,
	DevOpsRole.ROLE_OPERATOR: 1,
	DevOpsRole.ROLE_ADMIN: 2,
}
def _config(name):
	value = getattr(settings, name, {}) or {}
	if not isinstance(value, dict):
		raise ExternalAuthenticationError('External authentication is unavailable.')
	return value


def _required(config, name):
	value = config.get(name, '')
	if not value:
		raise ExternalAuthenticationError('External authentication is unavailable.')
	return value


def _https_url(value, label):
	parsed = urlparse(value)
	if parsed.scheme != 'https' or not parsed.netloc or parsed.username or parsed.password:
		raise ExternalAuthenticationError('External authentication is unavailable.')
	return value


def _json_response(response):
	if getattr(response, 'status_code', 0) != 200:
		raise ExternalAuthenticationError('External authentication is unavailable.')
	try:
		return response.json()
	except (AttributeError, TypeError, ValueError):
		raise ExternalAuthenticationError('External authentication is unavailable.')


def _b64decode(value):
	if not isinstance(value, str):
		raise ExternalAuthenticationError('External authentication is unavailable.')
	try:
		return base64.urlsafe_b64decode(value + '=' * (-len(value) % 4))
	except (TypeError, ValueError):
		raise ExternalAuthenticationError('External authentication is unavailable.')


def _oidc_discovery(config, http_get=requests.get):
	discovery_url = _https_url(_required(config, 'discovery_url'), 'discovery URL')
	data = _json_response(http_get(discovery_url, timeout=5))
	if not isinstance(data.get('issuer'), str):
		raise ExternalAuthenticationError('External authentication is unavailable.')
	_https_url(data['issuer'], 'issuer')
	for name in ('authorization_endpoint', 'token_endpoint', 'jwks_uri'):
		_https_url(data.get(name, ''), name)
	return data


def oidc_is_available():
	try:
		config = _config('OIDC_CONFIG')
		if not config.get('enabled'):
			return False
		_https_url(_required(config, 'discovery_url'), 'discovery URL')
		_https_url(_required(config, 'redirect_uri'), 'redirect URI')
		_required(config, 'client_id')
		_required(config, 'client_secret')
		return True
	except ExternalAuthenticationError:
		return False


def build_oidc_authorization_url(state, nonce, http_get=requests.get):
	"""Build the OIDC authorization URL; the caller persists state and nonce once."""
	if not oidc_is_available() or not state or not nonce:
		raise ExternalAuthenticationError('External authentication is unavailable.')
	config = _config('OIDC_CONFIG')
	discovery = _oidc_discovery(config, http_get)
	params = {
		'client_id': _required(config, 'client_id'),
		'redirect_uri': _https_url(_required(config, 'redirect_uri'), 'redirect URI'),
		'response_type': 'code', 'scope': config.get('scopes', 'openid profile email groups'),
		'state': state, 'nonce': nonce,
	}
	return discovery['authorization_endpoint'] + '?' + urlencode(params)


def _validate_oidc_token(token, discovery, nonce, http_get=requests.get, now=None):
	parts = token.split('.') if isinstance(token, str) else []
	if len(parts) != 3:
		raise ExternalAuthenticationError('External authentication is unavailable.')
	try:
		header, claims = [json.loads(_b64decode(part).decode('utf-8')) for part in parts[:2]]
	except (UnicodeDecodeError, ValueError):
		raise ExternalAuthenticationError('External authentication is unavailable.')
	if header.get('alg') not in ('RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'ES512') or not header.get('kid'):
		raise ExternalAuthenticationError('External authentication is unavailable.')
	jwks = _json_response(http_get(discovery['jwks_uri'], timeout=5))
	key = next((item for item in jwks.get('keys', []) if item.get('kid') == header['kid']), None)
	if not key:
		raise ExternalAuthenticationError('External authentication is unavailable.')
	_sign_jwt(parts, header['alg'], key)
	now = int(time.time()) if now is None else int(now)
	config = _config('OIDC_CONFIG')
	issuer = discovery.get('issuer')
	client_id = _required(config, 'client_id')
	audience = claims.get('aud')
	if isinstance(audience, str):
		audience = [audience]
	if claims.get('iss') != issuer or client_id not in (audience or []) or not claims.get('sub'):
		raise ExternalAuthenticationError('External authentication is unavailable.')
	if len(audience) > 1 and claims.get('azp') != client_id:
		raise ExternalAuthenticationError('External authentication is unavailable.')
	if claims.get('nonce') != nonce or not isinstance(claims.get('exp'), (int, float)):
		raise ExternalAuthenticationError('External authentication is unavailable.')
	if int(claims['exp']) <= now or ('nbf' in claims and int(claims['nbf']) > now):
		raise ExternalAuthenticationError('External authentication is unavailable.')
	return claims


def _sign_jwt(parts, algorithm, jwk):
	try:
		if jwk.get('kty') == 'RSA':
			public = rsa.RSAPublicNumbers(
				int.from_bytes(_b64decode(jwk['e']), 'big'), int.from_bytes(_b64decode(jwk['n']), 'big')
			).public_key()
			digest = getattr(hashes, algorithm[2:])()
			public.verify(_b64decode(parts[2]), (parts[0] + '.' + parts[1]).encode('ascii'), padding.PKCS1v15(), digest)
		elif jwk.get('kty') == 'EC':
			curve = {'ES256': ec.SECP256R1, 'ES384': ec.SECP384R1, 'ES512': ec.SECP521R1}.get(algorithm)
			if not curve:
				raise ValueError()
			public = ec.EllipticCurvePublicNumbers(int.from_bytes(_b64decode(jwk['x']), 'big'), int.from_bytes(_b64decode(jwk['y']), 'big'), curve()).public_key()
			digest = getattr(hashes, algorithm[2:])()
			raw = _b64decode(parts[2]); size = (public.curve.key_size + 7) // 8
			if len(raw) != size * 2:
				raise ValueError()
			from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
			public.verify(encode_dss_signature(int.from_bytes(raw[:size], 'big'), int.from_bytes(raw[size:], 'big')), (parts[0] + '.' + parts[1]).encode('ascii'), ec.ECDSA(digest))
		else:
			raise ValueError()
	except Exception:
		raise ExternalAuthenticationError('External authentication is unavailable.')


def authenticate_oidc_callback(request, code, nonce, http_get=requests.get, http_post=requests.post):
	"""Validate the callback token after the web layer has consumed callback state."""
	if not oidc_is_available() or not code or not nonce:
		raise ExternalAuthenticationError('External authentication is unavailable.')
	config = _config('OIDC_CONFIG')
	discovery = _oidc_discovery(config, http_get)
	response = http_post(discovery['token_endpoint'], data={
		'grant_type': 'authorization_code', 'code': code,
		'redirect_uri': _https_url(_required(config, 'redirect_uri'), 'redirect URI'),
		'client_id': _required(config, 'client_id'),
		'client_secret': _required(config, 'client_secret'),
	}, timeout=5)
	payload = _json_response(response)
	claims = _validate_oidc_token(payload.get('id_token'), discovery, nonce, http_get)
	outcome = provision_external_identity(ExternalIdentity.PROVIDER_OIDC, claims['sub'], claims.get('email'), claims.get('email_verified') is True, claims.get('groups') or [])
	return outcome.user


def _configured_role(groups):
	mapping = getattr(settings, 'EXTERNAL_AUTH_ROLE_MAP', {}) or {}
	if not isinstance(mapping, dict):
		raise ExternalAuthenticationError('External authentication is unavailable.')
	role = DevOpsRole.ROLE_VIEWER
	for group in groups:
		candidate = mapping.get(str(group))
		if candidate not in ROLE_RANK:
			continue
		if ROLE_RANK[candidate] > ROLE_RANK[role]:
			role = candidate
	return role


def _external_username(provider, subject):
	digest = hashlib.sha256((provider + ':' + subject).encode('utf-8')).hexdigest()[:20]
	return 'ext-%s-%s' % (provider, digest)


def provision_external_identity(provider, subject, email='', email_verified=False, groups=()):
	"""Bind a verified identity, create a namespaced user by default, and set mapped role."""
	if (
		provider not in dict(ExternalIdentity.PROVIDER_CHOICES) or not isinstance(subject, str) or
		not subject.strip() or len(subject) > 255
	):
		raise ExternalAuthenticationError('External authentication is unavailable.')
	role = _configured_role(groups)
	with transaction.atomic():
		identity = ExternalIdentity.objects.select_for_update().filter(provider=provider, subject=subject).select_related('user').first()
		created = False
		if identity:
			user = identity.user
		else:
			user = _matching_local_user(provider, email, email_verified)
			if not user:
				username = _external_username(provider, subject)
				user, created = User.objects.get_or_create(user=username, defaults={
					'email': email if email_verified and email else '%s@external.invalid' % username,
					'password': make_password(None), 'confirm_pwd': make_password(None),
				})
				if not created:
					raise ExternalAuthenticationError('External authentication is unavailable.')
			try:
				identity = ExternalIdentity.objects.create(provider=provider, subject=subject, user=user)
			except IntegrityError:
				raise ExternalAuthenticationError('External authentication is unavailable.')
		DevOpsRole.objects.update_or_create(user=user, defaults={'role': role})
		AuditLog.objects.create(user=user.user, action='外部身份登录', target_type='ExternalIdentity', target_id=str(identity.id), detail='provider=%s role=%s' % (provider, role))
	return AuthenticationOutcome(user=user, provider=provider, role=role, created=created)


def _matching_local_user(provider, email, email_verified):
	# No config currently opts into local-account linking.  Keeping this explicit
	# prevents a verified email from silently taking over a pre-existing account.
	return None


def ldap_is_available():
	try:
		config = _config('LDAP_CONFIG')
		if not config.get('enabled'):
			return False
		url = _required(config, 'server_uri')
		parsed = urlparse(url)
		return parsed.scheme == 'ldaps' or (parsed.scheme == 'ldap' and bool(config.get('starttls')))
	except ExternalAuthenticationError:
		return False


def _secure_ldap_server(ldap3, url, parsed, config):
	"""Create an LDAP server that always validates the directory certificate."""
	ca_certs_file = config.get('ca_certs_file', '')
	if ca_certs_file:
		if not isinstance(ca_certs_file, str) or not os.path.isabs(ca_certs_file) or '\x00' in ca_certs_file:
			raise ExternalAuthenticationError('External authentication is unavailable.')
		tls = ldap3.Tls(validate=ssl.CERT_REQUIRED, ca_certs_file=ca_certs_file)
	else:
		tls = ldap3.Tls(validate=ssl.CERT_REQUIRED)
	return ldap3.Server(
		parsed.hostname,
		port=parsed.port,
		use_ssl=parsed.scheme == 'ldaps',
		tls=tls,
		get_info=ldap3.NONE,
	)


def ldap_authenticate(username, password, connection_factory=None):
	"""Authenticate LDAP over LDAPS or StartTLS, without anonymous directory access."""
	if not ldap_is_available() or not username or not password:
		raise ExternalAuthenticationError('External authentication is unavailable.')
	config = _config('LDAP_CONFIG')
	url = _required(config, 'server_uri')
	parsed = urlparse(url)
	starttls = bool(config.get('starttls', False))
	if parsed.scheme not in ('ldap', 'ldaps') or not parsed.hostname or (parsed.scheme == 'ldap' and not starttls):
		raise ExternalAuthenticationError('External authentication is unavailable.')
	bind_dn = _required(config, 'bind_dn')
	bind_password = _required(config, 'bind_password')
	base_dn = _required(config, 'base_dn')
	try:
		if connection_factory is None:
			import ldap3
			server = _secure_ldap_server(ldap3, url, parsed, config)
			connection = ldap3.Connection(server, user=bind_dn, password=bind_password, auto_bind=False)
			if not connection.open() or (starttls and not connection.start_tls()) or not connection.bind():
				raise ValueError()
			escape = ldap3.utils.conv.escape_filter_chars
		else:
			connection, escape = connection_factory(url, bind_dn, bind_password, starttls)
		filter_template = config.get('user_filter', '(uid={username})')
		if '{username}' not in filter_template or filter_template.count('{username}') != 1:
			raise ValueError()
		search_filter = filter_template.format(username=escape(username))
		email_attr = config.get('email_attribute', 'mail')
		group_attr = config.get('group_attribute', 'memberOf')
		attributes = [email_attr, group_attr]
		if not connection.search(base_dn, search_filter, attributes=attributes) or len(connection.entries) != 1:
			raise ValueError()
		entry = connection.entries[0]
		user_dn = str(entry.entry_dn)
		if not connection.rebind(user=user_dn, password=password):
			raise ValueError()
		email = str(getattr(entry, email_attr).value or '') if hasattr(entry, email_attr) else ''
		groups = list(getattr(entry, group_attr).values or []) if hasattr(entry, group_attr) else []
		# The verified directory lookup binds this account.  Do not persist its DN.
		return provision_external_identity(ExternalIdentity.PROVIDER_LDAP, username, email, bool(email), groups)
	except (ExternalAuthenticationError, ImproperlyConfigured):
		raise
	except Exception:
		raise ExternalAuthenticationError('External authentication is unavailable.')
	finally:
		try:
			connection.unbind()
		except Exception:
			pass


def authenticate_ldap(request, username, password, connection_factory=None):
	"""Authenticate LDAP and return the local user; request is reserved for audit context."""
	return ldap_authenticate(username, password, connection_factory=connection_factory).user
