import json
from unittest.mock import ANY, patch

from django.contrib.auth.hashers import check_password, identify_hasher
from django.test import TestCase
from django.urls import reverse

from RemoteLinux.models import User


class UserPasswordHashTests(TestCase):
	def test_register_rejects_blank_required_fields(self):
		response = self.client.post(reverse('userprofile:register'), {
			'user': ' ',
			'email': 'blank@example.com',
			'password': '',
			'confirm_pwd': '',
		})

		self.assertEqual(response.status_code, 200)
		self.assertContains(response, '用户名、邮箱和密码不能为空')
		self.assertEqual(User.objects.exclude(user='admin').count(), 0)

	def test_register_rejects_invalid_email(self):
		response = self.client.post(reverse('userprofile:register'), {
			'user': 'bad-email-user',
			'email': 'not-an-email',
			'password': 'plain-password',
			'confirm_pwd': 'plain-password',
		})

		self.assertEqual(response.status_code, 200)
		self.assertContains(response, '邮箱格式不正确')
		self.assertEqual(User.objects.exclude(user='admin').count(), 0)

	def test_register_rejects_weak_password(self):
		response = self.client.post(reverse('userprofile:register'), {
			'user': 'weak-user',
			'email': 'weak@example.com',
			'password': '123',
			'confirm_pwd': '123',
		})

		self.assertEqual(response.status_code, 200)
		self.assertContains(response, '密码强度不足')
		self.assertEqual(User.objects.exclude(user='admin').count(), 0)

	def test_register_rejects_duplicate_email(self):
		User.objects.create(
			user='existing-email-user',
			email='same@example.com',
			password='plain-password',
			confirm_pwd='plain-password',
		)

		response = self.client.post(reverse('userprofile:register'), {
			'user': 'new-email-user',
			'email': 'same@example.com',
			'password': 'plain-password',
			'confirm_pwd': 'plain-password',
		})

		self.assertEqual(response.status_code, 200)
		self.assertContains(response, '邮箱已经存在')
		self.assertEqual(User.objects.filter(email='same@example.com').count(), 1)

	def test_register_stores_hashed_password(self):
		response = self.client.post(reverse('userprofile:register'), {
			'user': 'new-user',
			'email': 'new-user@example.com',
			'password': 'plain-password',
			'confirm_pwd': 'plain-password',
		})

		self.assertEqual(response.status_code, 200)
		user = User.objects.get(user='new-user')
		self.assertNotEqual(user.password, 'plain-password')
		self.assertTrue(check_password('plain-password', user.password))
		self.assertEqual(user.confirm_pwd, user.password)

	def test_login_rejects_blank_required_fields(self):
		User.objects.create(
			user='existing',
			email='existing@example.com',
			password='plain-password',
			confirm_pwd='plain-password',
		)

		response = self.client.post(reverse('userprofile:login'), {
			'user': ' ',
			'pwd': '',
		})

		self.assertEqual(response.status_code, 200)
		self.assertContains(response, '用户名和密码不能为空')

	def test_login_upgrades_legacy_plaintext_password(self):
		user = User.objects.create(
			user='legacy',
			email='legacy@example.com',
			password='plain-password',
			confirm_pwd='plain-password',
		)

		response = self.client.post(reverse('userprofile:login'), {
			'user': 'legacy',
			'pwd': 'plain-password',
		})

		self.assertEqual(response.status_code, 302)
		user.refresh_from_db()
		identify_hasher(user.password)
		self.assertTrue(check_password('plain-password', user.password))
		self.assertEqual(user.confirm_pwd, user.password)

	def test_login_rotates_session_key(self):
		User.objects.create(
			user='session-user',
			email='session@example.com',
			password='plain-password',
			confirm_pwd='plain-password',
		)
		session = self.client.session
		session['pre_login_marker'] = 'keep'
		session.save()
		old_key = session.session_key

		response = self.client.post(reverse('userprofile:login'), {
			'user': 'session-user',
			'pwd': 'plain-password',
		})

		self.assertEqual(response.status_code, 302)
		self.assertNotEqual(self.client.session.session_key, old_key)
		self.assertEqual(self.client.session['pre_login_marker'], 'keep')

	def test_login_locks_after_repeated_failures(self):
		User.objects.create(
			user='locked-user',
			email='locked@example.com',
			password='plain-password',
			confirm_pwd='plain-password',
		)

		for index in range(5):
			response = self.client.post(reverse('userprofile:login'), {
				'user': 'locked-user',
				'pwd': 'wrong-password',
			})

		self.assertEqual(response.status_code, 200)
		self.assertContains(response, '密码错误')
		response = self.client.post(reverse('userprofile:login'), {
			'user': 'locked-user',
			'pwd': 'plain-password',
		})

		self.assertEqual(response.status_code, 200)
		self.assertContains(response, '登录失败次数过多')

	def test_successful_login_clears_failure_counter(self):
		User.objects.create(
			user='clear-counter',
			email='clear@example.com',
			password='plain-password',
			confirm_pwd='plain-password',
		)
		session = self.client.session
		session['login_failed_count'] = 3
		session.save()

		response = self.client.post(reverse('userprofile:login'), {
			'user': 'clear-counter',
			'pwd': 'plain-password',
		})

		self.assertEqual(response.status_code, 302)
		self.assertNotIn('login_failed_count', self.client.session)


class InitialAdminTests(TestCase):
	def test_initial_admin_uses_hashed_password_and_can_log_in(self):
		admin = User.objects.get(user='admin')

		identify_hasher(admin.password)
		self.assertNotEqual(admin.password, 'Wx@123456')
		self.assertTrue(check_password('Wx@123456', admin.password))
		self.assertEqual(admin.confirm_pwd, admin.password)

		response = self.client.post(reverse('userprofile:login'), {
			'user': 'admin',
			'pwd': 'Wx@123456',
		})

		self.assertRedirects(response, reverse('index'))
		self.assertTrue(self.client.session['is_login'])
		self.assertEqual(self.client.session['user_name'], 'admin')


class ExternalAuthenticationViewTests(TestCase):
	def _login_payload(self, response):
		return json.loads(response.context['vue_page_payload'])['data']

	@patch('userprofile.external_auth.ldap_is_available', return_value=False)
	@patch('userprofile.external_auth.oidc_is_available', return_value=False)
	def test_login_payload_keeps_local_login_when_external_providers_are_unavailable(self, oidc_available, ldap_available):
		response = self.client.get(reverse('userprofile:login'))

		self.assertEqual(response.status_code, 200)
		payload = self._login_payload(response)
		self.assertEqual(payload['external_auth'], {
			'oidc_available': False,
			'ldap_available': False,
		})
		self.assertContains(response, '登录')

	@patch('userprofile.external_auth.oidc_is_available', return_value=False)
	def test_oidc_start_rejects_unavailable_provider(self, oidc_available):
		response = self.client.get(reverse('userprofile:oidc_login_start'))

		self.assertEqual(response.status_code, 200)
		self.assertContains(response, '外部认证暂不可用')
		self.assertNotIn('external_oidc_state', self.client.session)

	@patch('userprofile.external_auth.build_oidc_authorization_url', return_value='https://identity.example.test/authorize')
	@patch('userprofile.external_auth.oidc_is_available', return_value=True)
	def test_oidc_start_stores_state_and_nonce_before_redirect(self, oidc_available, build_url):
		response = self.client.get(reverse('userprofile:oidc_login_start'))

		self.assertRedirects(response, 'https://identity.example.test/authorize', fetch_redirect_response=False)
		session = self.client.session
		self.assertTrue(session['external_oidc_state'])
		self.assertTrue(session['external_oidc_nonce'])
		build_url.assert_called_once_with(session['external_oidc_state'], session['external_oidc_nonce'])

	def test_oidc_callback_rejects_mismatched_state_and_consumes_pending_values(self):
		session = self.client.session
		session['external_oidc_state'] = 'expected-state'
		session['external_oidc_nonce'] = 'expected-nonce'
		session.save()

		response = self.client.get(reverse('userprofile:oidc_login_callback'), {
			'state': 'different-state',
			'code': 'authorization-code',
		})

		self.assertEqual(response.status_code, 200)
		self.assertContains(response, '外部认证失败，请重试')
		self.assertNotIn('external_oidc_state', self.client.session)
		self.assertNotIn('external_oidc_nonce', self.client.session)

	@patch('userprofile.external_auth.authenticate_oidc_callback')
	def test_oidc_callback_logs_in_verified_user_and_consumes_pending_values(self, authenticate_callback):
		user = User.objects.create(
			user='oidc-user',
			email='oidc-user@example.com',
			password='external-placeholder',
			confirm_pwd='external-placeholder',
		)
		authenticate_callback.return_value = user
		session = self.client.session
		session['external_oidc_state'] = 'expected-state'
		session['external_oidc_nonce'] = 'expected-nonce'
		session.save()

		response = self.client.get(reverse('userprofile:oidc_login_callback'), {
			'state': 'expected-state',
			'code': 'authorization-code',
		})

		self.assertRedirects(response, reverse('index'))
		authenticate_callback.assert_called_once_with(ANY, 'authorization-code', 'expected-nonce')
		self.assertTrue(self.client.session['is_login'])
		self.assertEqual(self.client.session['user_id'], user.id)
		self.assertNotIn('external_oidc_state', self.client.session)
		self.assertNotIn('external_oidc_nonce', self.client.session)

	@patch('userprofile.external_auth.ldap_is_available', return_value=False)
	def test_ldap_login_rejects_unavailable_provider(self, ldap_available):
		response = self.client.post(reverse('userprofile:ldap_login'), {
			'username': 'directory-user',
			'password': 'directory-password',
		})

		self.assertEqual(response.status_code, 200)
		self.assertContains(response, '外部认证暂不可用')

	@patch('userprofile.external_auth.authenticate_ldap', return_value=None)
	@patch('userprofile.external_auth.ldap_is_available', return_value=True)
	def test_ldap_login_reports_generic_failure(self, ldap_available, authenticate_ldap):
		response = self.client.post(reverse('userprofile:ldap_login'), {
			'username': 'directory-user',
			'password': 'directory-password',
		})

		self.assertEqual(response.status_code, 200)
		self.assertContains(response, '外部认证失败，请重试')
		authenticate_ldap.assert_called_once()

	@patch('userprofile.external_auth.authenticate_ldap')
	@patch('userprofile.external_auth.ldap_is_available', return_value=True)
	def test_ldap_login_logs_in_verified_user(self, ldap_available, authenticate_ldap):
		user = User.objects.create(
			user='ldap-user',
			email='ldap-user@example.com',
			password='external-placeholder',
			confirm_pwd='external-placeholder',
		)
		authenticate_ldap.return_value = user

		response = self.client.post(reverse('userprofile:ldap_login'), {
			'username': 'directory-user',
			'password': 'directory-password',
		})

		self.assertRedirects(response, reverse('index'))
		authenticate_ldap.assert_called_once()
		self.assertTrue(self.client.session['is_login'])
		self.assertEqual(self.client.session['user_id'], user.id)

	@patch('userprofile.external_auth.ldap_is_available', return_value=True)
	@patch('userprofile.external_auth.oidc_is_available', return_value=True)
	def test_login_payload_exposes_only_external_provider_availability(self, oidc_available, ldap_available):
		response = self.client.get(reverse('userprofile:login'))

		payload = self._login_payload(response)
		self.assertEqual(payload['external_auth'], {
			'oidc_available': True,
			'ldap_available': True,
		})
		self.assertNotIn('token', json.dumps(payload).lower())
		self.assertNotIn('password', json.dumps(payload).lower())
