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
		self.assertEqual(User.objects.count(), 0)

	def test_register_rejects_invalid_email(self):
		response = self.client.post(reverse('userprofile:register'), {
			'user': 'bad-email-user',
			'email': 'not-an-email',
			'password': 'plain-password',
			'confirm_pwd': 'plain-password',
		})

		self.assertEqual(response.status_code, 200)
		self.assertContains(response, '邮箱格式不正确')
		self.assertEqual(User.objects.count(), 0)

	def test_register_rejects_weak_password(self):
		response = self.client.post(reverse('userprofile:register'), {
			'user': 'weak-user',
			'email': 'weak@example.com',
			'password': '123',
			'confirm_pwd': '123',
		})

		self.assertEqual(response.status_code, 200)
		self.assertContains(response, '密码强度不足')
		self.assertEqual(User.objects.count(), 0)

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
		self.assertEqual(User.objects.count(), 1)

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
