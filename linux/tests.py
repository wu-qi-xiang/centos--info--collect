import json

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

		with mock.patch('linux.collectors.subprocess.getoutput', side_effect=fake_getoutput), \
				mock.patch('linux.collectors.local_disk_path', return_value='/'):
			detail = collect_local_detail(public_ip_lookup=lambda: ['203.0.113.10'])

		self.assertEqual(detail['release'], 'Debian GNU/Linux 12')
		self.assertEqual(detail['cpu'], '8')
		self.assertEqual(detail['intranet_ip'], '10.0.0.8')
		self.assertEqual(detail['outside_ip'], ['203.0.113.10'])
		self.assertEqual(detail['total_disk'], '80G')

	def test_collect_local_detail_falls_back_to_proc_meminfo(self):
		meminfo = '\n'.join([
			'MemTotal:       16384 kB',
			'MemFree:         2048 kB',
			'MemAvailable:   12288 kB',
			'Buffers:         1024 kB',
			'Cached:          4096 kB',
		])

		def fake_getoutput(command):
			if 'free -h' in command:
				return ''
			if command.startswith('cat /proc/meminfo'):
				return meminfo
			return ''

		with mock.patch('linux.collectors.subprocess.getoutput', side_effect=fake_getoutput):
			detail = collect_local_detail(public_ip_lookup=lambda: [])

		self.assertEqual(detail['total_mem'], str(16384 * 1024))
		self.assertEqual(detail['used_mem'], str(4096 * 1024))
		self.assertEqual(detail['free_mem'], str(2048 * 1024))
		self.assertEqual(detail['available_mem'], str(12288 * 1024))

	def test_collect_local_detail_falls_back_to_sysctl_memory(self):
		vm_stat = '\n'.join([
			'Pages free:                               1000.',
			'Pages inactive:                           2000.',
			'Pages speculative:                         500.',
		])

		def fake_getoutput(command):
			if 'free -h' in command or command.startswith('cat /proc/meminfo'):
				return ''
			if command.startswith('sysctl -n hw.memsize'):
				return str(16 * 1024 * 1024)
			if command.startswith('sysctl -n hw.pagesize'):
				return '4096'
			if command.startswith('vm_stat'):
				return vm_stat
			return ''

		with mock.patch('linux.collectors.subprocess.getoutput', side_effect=fake_getoutput):
			detail = collect_local_detail(public_ip_lookup=lambda: [])

		self.assertEqual(detail['total_mem'], str(16 * 1024 * 1024))
		self.assertEqual(detail['free_mem'], str(1000 * 4096))
		self.assertEqual(detail['available_mem'], str(3500 * 4096))
		self.assertEqual(detail['used_mem'], str((16 * 1024 * 1024) - (3500 * 4096)))

	def test_collect_local_detail_falls_back_to_vm_stat_without_sysctl_memory(self):
		vm_stat = '\n'.join([
			'Mach Virtual Memory Statistics: (page size of 4096 bytes)',
			'Pages free:                               1000.',
			'Pages active:                             3000.',
			'Pages inactive:                           2000.',
			'Pages speculative:                         500.',
			'Pages wired down:                          500.',
		])

		def fake_getoutput(command):
			if 'free -h' in command or command.startswith('cat /proc/meminfo'):
				return ''
			if command.startswith('sysctl -n hw.memsize') or command.startswith('sysctl -n hw.pagesize'):
				return ''
			if command.startswith('vm_stat'):
				return vm_stat
			return ''

		with mock.patch('linux.collectors.subprocess.getoutput', side_effect=fake_getoutput):
			detail = collect_local_detail(public_ip_lookup=lambda: [])

		self.assertEqual(detail['total_mem'], str(7000 * 4096))
		self.assertEqual(detail['free_mem'], str(1000 * 4096))
		self.assertEqual(detail['available_mem'], str(3500 * 4096))
		self.assertEqual(detail['used_mem'], str(3500 * 4096))

	def test_collect_local_detail_falls_back_to_df_k_disk(self):
		df_k = '\n'.join([
			'Filesystem 1024-blocks Used Available Capacity Mounted on',
			'/dev/root 81920 20480 61440 25% /',
		])

		def fake_getoutput(command):
			if 'df -hP /' in command:
				return ''
			if command.startswith('df -kP /'):
				return df_k
			return ''

		with mock.patch('linux.collectors.subprocess.getoutput', side_effect=fake_getoutput), \
				mock.patch('linux.collectors.local_disk_path', return_value='/'):
			detail = collect_local_detail(public_ip_lookup=lambda: [])

		self.assertEqual(detail['total_disk'], str(81920 * 1024))
		self.assertEqual(detail['used_disk'], str(20480 * 1024))
		self.assertEqual(detail['available_disk'], str(61440 * 1024))

	def test_collect_local_detail_falls_back_to_shutil_disk(self):
		usage = mock.Mock(total=1000, used=400, free=600)

		def fake_getoutput(command):
			if 'df -hP /' in command or command.startswith('df -kP /'):
				return ''
			return ''

		with mock.patch('linux.collectors.subprocess.getoutput', side_effect=fake_getoutput), \
				mock.patch('linux.collectors.local_disk_path', return_value='/'), \
				mock.patch('linux.collectors.shutil.disk_usage', return_value=usage):
			detail = collect_local_detail(public_ip_lookup=lambda: [])

		self.assertEqual(detail['total_disk'], '1000')
		self.assertEqual(detail['used_disk'], '400')
		self.assertEqual(detail['available_disk'], '600')

	def test_collect_local_detail_falls_back_to_getconf_and_sysctl_cpu(self):
		def fake_getoutput(command):
			if command.startswith('getconf _NPROCESSORS_ONLN'):
				return '6'
			if command.startswith('sysctl -n hw.ncpu'):
				return '4'
			return ''

		with mock.patch('linux.collectors.subprocess.getoutput', side_effect=fake_getoutput):
			detail = collect_local_detail(public_ip_lookup=lambda: [])

		self.assertEqual(detail['cpu'], '6')

		def fake_sysctl_getoutput(command):
			if command.startswith('sysctl -n hw.ncpu'):
				return '4'
			return ''

		with mock.patch('linux.collectors.subprocess.getoutput', side_effect=fake_sysctl_getoutput):
			detail = collect_local_detail(public_ip_lookup=lambda: [])

		self.assertEqual(detail['cpu'], '4')

	def test_collect_local_detail_falls_back_to_ifconfig_route_ip(self):
		def fake_getoutput(command):
			if command.startswith('ifconfig 2>/dev/null'):
				return 'inet 10.10.0.5 netmask 0xffffff00 broadcast 10.10.0.255'
			return ''

		with mock.patch('linux.collectors.subprocess.getoutput', side_effect=fake_getoutput):
			detail = collect_local_detail(public_ip_lookup=lambda: [])

		self.assertEqual(detail['intranet_ip'], '10.10.0.5')

	def test_collect_local_detail_prefers_macos_data_volume_for_disk(self):
		commands = []

		def fake_getoutput(command):
			commands.append(command)
			if command.startswith('df -kP /System/Volumes/Data'):
				return '\n'.join([
					'Filesystem 1024-blocks Used Available Capacity Mounted on',
					'/dev/disk1s2 488245288 275175932 191175060 60% /System/Volumes/Data',
				])
			return ''

		with mock.patch('linux.collectors.subprocess.getoutput', side_effect=fake_getoutput), \
				mock.patch('linux.collectors.local_disk_path', return_value='/System/Volumes/Data'):
			detail = collect_local_detail(public_ip_lookup=lambda: [])

		self.assertTrue(any('/System/Volumes/Data' in command for command in commands))
		self.assertEqual(detail['used_disk'], str(275175932 * 1024))

	@mock.patch.dict('linux.collectors.os.environ', {'DISABLE_PUBLIC_IP_LOOKUP': '1'}, clear=True)
	@mock.patch('linux.collectors.urllib.request.urlopen')
	def test_public_ip_lookup_can_be_disabled(self, urlopen):
		self.assertEqual(fetch_public_ip(), [])
		urlopen.assert_not_called()

	@mock.patch.dict('linux.collectors.os.environ', {}, clear=True)
	@mock.patch('linux.collectors.urllib.request.urlopen')
	def test_public_ip_lookup_tries_multiple_services(self, urlopen):
		first_response = Exception('network down')
		second_response = mock.Mock()
		second_response.read.return_value = b'198.51.100.9\n'
		urlopen.side_effect = [first_response, second_response]

		self.assertEqual(fetch_public_ip(timeout=1), ['198.51.100.9'])
		self.assertEqual(urlopen.call_count, 2)

	@mock.patch.dict('linux.collectors.os.environ', {}, clear=True)
	@mock.patch('linux.collectors.urllib.request.urlopen', side_effect=Exception('dns failed'))
	def test_public_ip_lookup_falls_back_to_curl(self, urlopen):
		def fake_getoutput(command):
			if command.startswith('curl -4'):
				return '203.0.113.88'
			return ''

		with mock.patch('linux.collectors.subprocess.getoutput', side_effect=fake_getoutput):
			self.assertEqual(fetch_public_ip(timeout=1), ['203.0.113.88'])


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
		payload = json.loads(response.context['vue_page_payload'])
		self.assertEqual(payload['title'], '资产列表')
		self.assertEqual(response.context['keyword'], 'web')
		self.assertEqual(response.context['sum'], 9)
		self.assertContains(response, 'search=web')
		self.assertNotContains(response, 'db-01')

	def test_host_detail_page_filters_with_search_query(self):
		response = self.client.get(reverse('linux_detail'), {'search': 'web'})

		self.assertEqual(response.status_code, 200)
		payload = json.loads(response.context['vue_page_payload'])
		self.assertEqual(payload['title'], '资产列表')
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

	def test_asset_management_page_links_to_existing_asset_pages(self):
		response = self.client.get(reverse('asset_management'))

		self.assertEqual(response.status_code, 200)
		self.assertContains(response, '资产管理')
		self.assertContains(response, '本地资产')
		self.assertContains(response, '资产列表')
		self.assertContains(response, 'href="%s"' % reverse('linux'))
		self.assertContains(response, 'href="%s"' % reverse('linux_detail'))

	def test_asset_management_page_requires_login(self):
		self.client.get(reverse('userprofile:logout'))
		response = self.client.get(reverse('asset_management'))

		self.assertEqual(response.status_code, 302)
		self.assertEqual(response.url, reverse('userprofile:login'))

	def test_asset_management_rejects_non_get_requests(self):
		response = self.client.post(reverse('asset_management'))

		self.assertEqual(response.status_code, 405)

	def test_shared_navigation_uses_management_parent_and_child_links(self):
		response = self.client.get(reverse('index'))

		self.assertContains(response, 'href="%s"' % reverse('asset_management'))
		self.assertContains(response, 'href="%s"' % reverse('linux'))
		self.assertContains(response, 'href="%s"' % reverse('linux_detail'))
		self.assertContains(response, 'href="%s"' % reverse('password:credential_management'))
		self.assertContains(response, 'href="%s"' % reverse('password:password_manage'))
		self.assertContains(response, '资产管理')
		self.assertContains(response, '本地资产')
		self.assertContains(response, '资产列表')
		self.assertContains(response, '凭据管理')
		self.assertContains(response, '凭据列表')

	def test_local_linux_page_uses_local_asset_title(self):
		with mock.patch('linux.views.collect_local_detail', return_value={}):
			response = self.client.get(reverse('linux'))

		payload = json.loads(response.context['vue_page_payload'])
		self.assertEqual(payload['title'], '本地资产')

	def _local_linux_items(self, detail):
		with mock.patch('linux.views.collect_local_detail', return_value=detail):
			response = self.client.get(reverse('linux'))

		self.assertEqual(response.status_code, 200)
		payload = json.loads(response.context['vue_page_payload'])
		return {item['label']: item['value'] for item in payload['data']['items']}

	def test_local_linux_page_formats_values_with_units_and_types(self):
		items = self._local_linux_items({
			'cpu': '8',
			'total_mem': '16Gi',
			'used_mem': '4096',
			'available_mem': '0',
			'release': 'Debian GNU/Linux 12',
			'kernel': '6.1.0',
			'intranet_ip': '10.0.0.8',
			'outside_ip': ['203.0.113.10'],
			'total_disk': '80G',
			'used_disk': '20',
			'available_disk': '0',
		})

		self.assertEqual(items['CPU 核数'], '8 核')
		self.assertEqual(items['总内存'], '16 GiB')
		self.assertEqual(items['已用内存'], '4 KiB')
		self.assertEqual(items['可用内存'], '0 B')
		self.assertEqual(items['系统版本'], 'Debian GNU/Linux 12（发行版）')
		self.assertEqual(items['内核'], '6.1.0（内核版本）')
		self.assertEqual(items['内网 IP'], '10.0.0.8（IPv4）')
		self.assertEqual(items['公网 IP'], '203.0.113.10（IPv4）')
		self.assertEqual(items['总磁盘'], '80 GB')
		self.assertEqual(items['已用磁盘'], '20 B')
		self.assertEqual(items['可用磁盘'], '0 B')

	def test_local_linux_page_keeps_unknown_values_and_formats_multiple_public_ips(self):
		items = self._local_linux_items({
			'cpu': '未获取',
			'total_mem': '未获取',
			'used_mem': '',
			'available_mem': None,
			'release': '未获取',
			'kernel': '',
			'intranet_ip': None,
			'outside_ip': ['203.0.113.10', '198.51.100.7'],
			'total_disk': '未获取',
			'used_disk': '80G',
			'available_disk': '0',
		})

		self.assertEqual(items['CPU 核数'], '未获取')
		self.assertEqual(items['总内存'], '未获取')
		self.assertEqual(items['已用内存'], '未获取')
		self.assertEqual(items['可用内存'], '未获取')
		self.assertEqual(items['系统版本'], '未获取')
		self.assertEqual(items['内核'], '未获取')
		self.assertEqual(items['内网 IP'], '未获取')
		self.assertEqual(items['公网 IP'], '203.0.113.10（IPv4）, 198.51.100.7（IPv4）')
		self.assertEqual(items['总磁盘'], '未获取')
		self.assertEqual(items['已用磁盘'], '80 GB')
		self.assertEqual(items['可用磁盘'], '0 B')
