from django.test import TestCase
from django.urls import reverse
from unittest import mock

from .collectors import collect_local_detail, fetch_public_ip
from password.models import Password
from RemoteLinux.models import NewLinux, User


class LocalCollectorTests(TestCase):
	def test_collect_local_detail_uses_portable_ip_and_root_disk(self):
		outputs = {
			'/etc/os-release': 'Debian GNU/Linux 12',
			'nproc': '8',
			"free -h | awk '/^Mem:/ {print $2}'": '16Gi',
			"free -h | awk '/^Mem:/ {print $3}'": '4Gi',
			"free -h | awk '/^Mem:/ {print $4}'": '2Gi',
			"free -h | awk '/^Mem:/ {print $7}'": '10Gi',
			'uname -r': '6.1.0',
			'hostname -I': '10.0.0.8 172.17.0.1',
			"df -hP / | awk 'NR==2 {print $2}'": '80G',
			"df -hP / | awk 'NR==2 {print $3}'": '20G',
			"df -hP / | awk 'NR==2 {print $4}'": '60G',
		}

		def fake_getoutput(command):
			for pattern, value in outputs.items():
				if pattern in command:
					return value
			return ''

		with mock.patch('linux.collectors.subprocess.getoutput', side_effect=fake_getoutput):
			detail = collect_local_detail(public_ip_lookup=lambda: ['203.0.113.10'])

		self.assertEqual(detail['release'], 'Debian GNU/Linux 12')
		self.assertEqual(detail['cpu'], '8')
		self.assertEqual(detail['intranet_ip'], '10.0.0.8')
		self.assertEqual(detail['outside_ip'], ['203.0.113.10'])
		self.assertEqual(detail['total_disk'], '80G')

	@mock.patch.dict('linux.collectors.os.environ', {}, clear=True)
	@mock.patch('linux.collectors.urllib.request.urlopen')
	def test_public_ip_lookup_is_disabled_by_default(self, urlopen):
		self.assertEqual(fetch_public_ip(), [])
		urlopen.assert_not_called()


class HostSearchTests(TestCase):
	def setUp(self):
		self.user = User.objects.create(
			user='tester',
			email='tester@example.com',
			password='plain-password',
			confirm_pwd='plain-password',
		)
		session = self.client.session
		session['is_login'] = True
		session['user_id'] = self.user.id
		session['user_name'] = 'tester'
		session.save()
		for index in range(9):
			NewLinux.objects.create(
				linux_name='web-%02d' % index,
				linux_ip='10.0.0.%s' % index,
				linux_hostname='web-host-%02d' % index,
				linux_port='22',
				linux_user='root',
				linux_passwd='',
				linux_app='web',
			)
		NewLinux.objects.create(
			linux_name='db-01',
			linux_ip='10.0.1.1',
			linux_hostname='db-host-01',
			linux_port='22',
			linux_user='root',
			linux_passwd='',
			linux_app='mysql',
		)

	def test_search_filters_hosts_and_preserves_keyword_for_pagination(self):
		response = self.client.get(reverse('search'), {'search': 'web'})

		self.assertEqual(response.status_code, 200)
		self.assertEqual(response.context['keyword'], 'web')
		self.assertEqual(response.context['sum'], 9)
		self.assertContains(response, 'search=web')
		self.assertNotContains(response, 'db-01')

	def test_host_detail_page_filters_with_search_query(self):
		response = self.client.get(reverse('linux_detail'), {'search': 'web'})

		self.assertEqual(response.status_code, 200)
		self.assertEqual(response.context['keyword'], 'web')
		self.assertEqual(response.context['sum'], 9)
		self.assertContains(response, 'search=web')
		self.assertNotContains(response, 'db-01')

	def test_blank_search_returns_all_hosts_without_reusing_previous_keyword(self):
		self.client.get(reverse('search'), {'search': 'web'})
		response = self.client.get(reverse('search'), {'page': '1'})

		self.assertEqual(response.status_code, 200)
		self.assertEqual(response.context['keyword'], '')
		self.assertEqual(response.context['sum'], 10)

	def test_search_empty_result_renders_empty_page(self):
		response = self.client.get(reverse('search'), {'search': 'missing'})

		self.assertEqual(response.status_code, 200)
		self.assertEqual(response.context['sum'], 0)
		self.assertEqual(list(response.context['pages']), [])

	def test_search_rejects_non_get_requests(self):
		response = self.client.post(reverse('search'), {'search': 'web'})

		self.assertEqual(response.status_code, 405)


class IndexDashboardTests(TestCase):
	def setUp(self):
		self.user = User.objects.create(
			user='dashboard-user',
			email='dashboard@example.com',
			password='plain-password',
			confirm_pwd='plain-password',
		)
		session = self.client.session
		session['is_login'] = True
		session['user_id'] = self.user.id
		session['user_name'] = self.user.user
		session.save()

	def test_index_uses_database_counts_without_generating_static_chart(self):
		NewLinux.objects.create(
			linux_name='dashboard-host',
			linux_ip='10.0.0.1',
			linux_hostname='dashboard-host',
			linux_port='22',
			linux_user='root',
			linux_passwd='',
		)
		Password.objects.create(
			system_name='dashboard-system',
			account='admin',
			password='encrypted',
			auther=self.user.user,
		)

		response = self.client.get(reverse('index'))

		self.assertEqual(response.status_code, 200)
		self.assertEqual(response.context['nwl'], 1)
		self.assertEqual(response.context['pwd'], 1)

	def test_local_linux_page_includes_security_context(self):
		with mock.patch('linux.views.collect_local_detail', return_value={}):
			response = self.client.get(reverse('linux'))

		self.assertEqual(response.status_code, 200)
		self.assertIn('can_manage_hosts', response.context)
		self.assertIn('can_use_webssh', response.context)
