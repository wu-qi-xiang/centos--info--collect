from django.test import TestCase
from django.urls import reverse

from PyLinux.crypto import encrypt_text
from devops.models import AuditLog
from RemoteLinux.models import User
from .models import Password


class PasswordRevealTests(TestCase):
	def setUp(self):
		self.user = User.objects.create(
			user='pwd_user',
			email='pwd@example.com',
			password='plain-password',
			confirm_pwd='plain-password',
		)
		session = self.client.session
		session['is_login'] = True
		session['user_id'] = self.user.id
		session['user_name'] = self.user.user
		session.save()
		self.password = Password.objects.create(
			system_name='prod-db',
			account='admin',
			password=encrypt_text('secret-password'),
			auther=self.user.user,
		)

	def test_password_list_does_not_render_plaintext_password(self):
		response = self.client.get(reverse('password:password_manage'))

		self.assertEqual(response.status_code, 200)
		self.assertNotContains(response, 'secret-password')
		self.assertContains(response, '••••••••')

	def test_password_list_does_not_render_unimplemented_placeholder_actions(self):
		response = self.client.get(reverse('password:password_manage'))

		self.assertEqual(response.status_code, 200)
		self.assertNotContains(response, '导出功能开发中')
		self.assertNotContains(response, '批量导出')
		self.assertNotContains(response, '示例系统')
		self.assertContains(response, 'data-system-name="prod-db"')

	def test_password_search_sets_pagination_context(self):
		response = self.client.get(reverse('password:password_search'), {'search': 'prod'})

		self.assertEqual(response.status_code, 200)
		self.assertEqual(response.context['pagenum'], 0)
		self.assertEqual(response.context['sum'], 1)
		self.assertContains(response, 'prod-db')

	def test_password_search_trims_keyword(self):
		response = self.client.get(reverse('password:password_search'), {'search': '  prod  '})

		self.assertEqual(response.status_code, 200)
		self.assertEqual(response.context['pwd'], 'prod')
		self.assertEqual(response.context['sum'], 1)
		self.assertContains(response, 'prod-db')

	def test_password_search_empty_result_renders_empty_page(self):
		response = self.client.get(reverse('password:password_search'), {'search': 'missing'})

		self.assertEqual(response.status_code, 200)
		self.assertEqual(response.context['sum'], 0)
		self.assertEqual(list(response.context['pages']), [])

	def test_password_search_rejects_non_get_requests(self):
		response = self.client.post(reverse('password:password_search'), {'search': 'prod'})

		self.assertEqual(response.status_code, 405)

	def test_password_manage_rejects_non_get_requests(self):
		response = self.client.post(reverse('password:password_manage'))

		self.assertEqual(response.status_code, 405)

	def test_password_reveal_returns_password_and_records_audit(self):
		response = self.client.post(reverse('password:password_reveal', args=[self.password.id]))

		self.assertEqual(response.status_code, 200)
		self.assertEqual(response.json()['password'], 'secret-password')
		self.assertTrue(AuditLog.objects.filter(action='查看密码', target_id=str(self.password.id)).exists())

	def test_password_create_records_audit(self):
		response = self.client.post(reverse('password:password_create'), {
			'system_name': 'new-system',
			'account': 'admin',
			'password': 'new-secret',
			'remark': 'created',
		})

		self.assertEqual(response.status_code, 302)
		password = Password.objects.get(system_name='new-system')
		self.assertTrue(AuditLog.objects.filter(action='创建密码记录', target_id=str(password.id)).exists())

	def test_password_create_invalid_submission_rerenders_form_errors(self):
		response = self.client.post(reverse('password:password_create'), {
			'system_name': '',
			'account': 'admin',
			'password': '',
			'remark': 'keep this note',
		})

		self.assertEqual(response.status_code, 400)
		self.assertContains(response, '提交失败，请检查以下内容', status_code=400)
		self.assertContains(response, 'keep this note', status_code=400)

	def test_password_update_records_audit(self):
		response = self.client.post(reverse('password:password_update', args=[self.password.id]), {
			'system_name': 'prod-db-updated',
			'account': 'admin',
			'password': 'rotated-secret',
			'remark': 'updated',
		})

		self.assertEqual(response.status_code, 302)
		self.assertTrue(AuditLog.objects.filter(action='更新密码记录', target_id=str(self.password.id)).exists())

	def test_password_update_page_does_not_render_plaintext_password(self):
		response = self.client.get(reverse('password:password_update', args=[self.password.id]))

		self.assertEqual(response.status_code, 200)
		self.assertNotContains(response, 'secret-password')
		self.assertContains(response, '留空则保持原密码不变')

	def test_password_update_blank_password_keeps_existing_password(self):
		original_password = self.password.password

		response = self.client.post(reverse('password:password_update', args=[self.password.id]), {
			'system_name': 'prod-db-renamed',
			'account': 'admin',
			'password': '',
			'remark': 'password unchanged',
		})

		self.assertEqual(response.status_code, 302)
		self.password.refresh_from_db()
		self.assertEqual(self.password.password, original_password)
		self.assertEqual(self.password.system_name, 'prod-db-renamed')

	def test_password_update_invalid_submission_rerenders_form_errors(self):
		response = self.client.post(reverse('password:password_update', args=[self.password.id]), {
			'system_name': '',
			'account': 'admin',
			'password': '',
			'remark': 'bad update',
		})

		self.assertEqual(response.status_code, 400)
		self.assertContains(response, '提交失败，请检查以下内容', status_code=400)
		self.assertContains(response, 'prod-db', status_code=400)

	def test_password_delete_records_audit(self):
		response = self.client.post(reverse('password:password_delete', args=[self.password.id]))

		self.assertEqual(response.status_code, 302)
		self.assertTrue(AuditLog.objects.filter(action='删除密码记录', target_id=str(self.password.id)).exists())
