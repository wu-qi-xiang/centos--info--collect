from django.test import TestCase
from django.urls import reverse
from unittest import mock
import socket
from django.core.files.uploadedfile import SimpleUploadedFile

from PyLinux.crypto import decrypt_text, encrypt_text
from devops.models import AuditLog, DevOpsHostScope, DevOpsRole, HostGroup
from .collectors import collect_remote_detail, collect_remote_usage
from .models import NewLinux, User
from .ssh_utils import create_host_ssh_client, describe_ssh_error
from .views import _encrypt_host_credentials, _update_host_credentials


class FakeSSHResponse(object):
    def __init__(self, value):
        self.value = value

    def read(self):
        return self.value.encode('utf-8')


class FakeSSHClient(object):
    def __init__(self, outputs):
        self.outputs = outputs
        self.commands = []

    def exec_command(self, command):
        self.commands.append(command)
        output = ''
        for pattern, value in self.outputs.items():
            if pattern in command:
                output = value
                break
        return None, FakeSSHResponse(output), FakeSSHResponse('')


class RemoteCollectorTests(TestCase):
    def test_collect_remote_detail_uses_portable_fallbacks(self):
        ssh = FakeSSHClient({
            '/etc/os-release': 'Ubuntu 22.04 LTS',
            'uname -r': '5.15.0',
            'nproc': '4',
            "free -h | awk '/^Mem:/ {print $2}'": '8Gi',
            "free -h | awk '/^Mem:/ {print $3}'": '2Gi',
            "free -h | awk '/^Mem:/ {print $4}'": '1Gi',
            "free -h | awk '/^Mem:/ {print $7}'": '5Gi',
            'hostname -I': '10.0.0.5 172.17.0.1',
            "df -hP / | awk 'NR==2 {print $2}'": '40G',
            "df -hP / | awk 'NR==2 {print $3}'": '12G',
            "df -hP / | awk 'NR==2 {print $4}'": '28G',
        })

        detail = collect_remote_detail(ssh)

        self.assertEqual(detail['release'], 'Ubuntu 22.04 LTS')
        self.assertEqual(detail['kernel'], '5.15.0')
        self.assertEqual(detail['cpu'], '4')
        self.assertEqual(detail['intranet_ip'], '10.0.0.5')
        self.assertEqual(detail['total_disk'], '40G')

    def test_collect_remote_usage_parses_cpu_memory_and_root_disk(self):
        ssh = FakeSSHClient({
            'vmstat 1 2': '75',
            "free -m | awk '/^Mem:/ {print $2}'": '1000',
            "free -m | awk '/^Mem:/ {print $7}'": '250',
            "df -P / | awk 'NR==2 {print $5}'": '81%',
        })

        usage = collect_remote_usage(ssh)

        self.assertEqual(usage['cpu'], 0.25)
        self.assertEqual(usage['memory'], 0.75)
        self.assertEqual(usage['disk'], 0.81)


class HostCredentialTests(TestCase):
    def test_encrypt_host_credentials_stores_key_fields_encrypted(self):
        host = NewLinux(
            linux_ip='127.0.0.1',
            linux_port='22',
            linux_user='root',
        )

        _encrypt_host_credentials(host, {
            'linux_auth_type': NewLinux.AUTH_KEY,
            'linux_passwd': 'sudo-password',
            'linux_private_key': 'PRIVATE KEY',
            'linux_private_key_passphrase': 'key-passphrase',
        })

        self.assertEqual(host.linux_auth_type, NewLinux.AUTH_KEY)
        self.assertNotEqual(host.linux_private_key, 'PRIVATE KEY')
        self.assertEqual(decrypt_text(host.linux_private_key), 'PRIVATE KEY')
        self.assertEqual(decrypt_text(host.linux_private_key_passphrase), 'key-passphrase')

    def test_update_host_credentials_keeps_saved_key_when_blank(self):
        old_key = 'enc:saved-key'
        old_passphrase = 'enc:saved-passphrase'
        host = NewLinux(linux_auth_type=NewLinux.AUTH_KEY)

        _update_host_credentials(host, {
            'linux_auth_type': NewLinux.AUTH_KEY,
            'linux_passwd': '',
            'linux_private_key': '',
            'linux_private_key_passphrase': '',
        }, '', old_key, old_passphrase)

        self.assertEqual(host.linux_private_key, old_key)
        self.assertEqual(host.linux_private_key_passphrase, old_passphrase)

    def test_password_auth_clears_saved_key(self):
        host = NewLinux(linux_auth_type=NewLinux.AUTH_KEY)

        _update_host_credentials(host, {
            'linux_auth_type': NewLinux.AUTH_PASSWORD,
            'linux_passwd': 'new-password',
            'linux_private_key': '',
            'linux_private_key_passphrase': '',
        }, 'enc:saved-password', 'enc:saved-key', 'enc:saved-passphrase')

        self.assertEqual(host.linux_auth_type, NewLinux.AUTH_PASSWORD)
        self.assertEqual(host.linux_private_key, '')
        self.assertEqual(host.linux_private_key_passphrase, '')

    @mock.patch('RemoteLinux.ssh_utils.create_ssh_client')
    def test_create_host_ssh_client_uses_saved_private_key(self, create_ssh_client):
        host = NewLinux(
            linux_ip='127.0.0.1',
            linux_port='22',
            linux_user='root',
            linux_auth_type=NewLinux.AUTH_KEY,
            linux_passwd=encrypt_text('sudo-password'),
            linux_private_key=encrypt_text('PRIVATE KEY'),
            linux_private_key_passphrase=encrypt_text('key-passphrase'),
        )

        create_host_ssh_client(host, timeout=3)

        create_ssh_client.assert_called_once_with(
            '127.0.0.1',
            '22',
            'root',
            password='sudo-password',
            private_key='PRIVATE KEY',
            passphrase='key-passphrase',
            timeout=3,
        )

    def test_describe_ssh_error_classifies_timeout(self):
        self.assertIn('超时', describe_ssh_error(socket.timeout('timed out')))


class HostSecurityTests(TestCase):
    def setUp(self):
        self.user = User.objects.create(
            user='viewer',
            email='viewer@example.com',
            password='plain-password',
            confirm_pwd='plain-password',
        )
        self.host = NewLinux.objects.create(
            linux_name='allowed-host',
            linux_ip='127.0.0.1',
            linux_hostname='localhost',
            linux_port='22',
            linux_user='root',
            linux_passwd='bad-password',
        )
        self.blocked_host = NewLinux.objects.create(
            linux_name='blocked-host',
            linux_ip='127.0.0.2',
            linux_hostname='blocked',
            linux_port='22',
            linux_user='root',
            linux_passwd='bad-password',
        )
        session = self.client.session
        session['is_login'] = True
        session['user_id'] = self.user.id
        session['user_name'] = self.user.user
        session.save()

    def set_role(self, role):
        DevOpsRole.objects.update_or_create(user=self.user, defaults={'role': role})

    def limit_scope_to_allowed_host(self):
        group = HostGroup.objects.create(name='allowed')
        group.hosts.add(self.host)
        scope = DevOpsHostScope.objects.create(user=self.user)
        scope.groups.add(group)

    def test_viewer_cannot_open_host_create_page_when_roles_are_configured(self):
        self.set_role(DevOpsRole.ROLE_VIEWER)

        response = self.client.get(reverse('linux_create'))

        self.assertEqual(response.status_code, 403)

    def test_operator_can_open_host_create_page(self):
        self.set_role(DevOpsRole.ROLE_OPERATOR)

        response = self.client.get(reverse('linux_create'))

        self.assertEqual(response.status_code, 200)

    def test_user_without_configured_role_can_open_host_create_and_import(self):
        create_response = self.client.get(reverse('linux_create'))
        import_response = self.client.get(reverse('linux_import'))

        self.assertEqual(create_response.status_code, 200)
        self.assertEqual(import_response.status_code, 200)

    def test_host_scope_filters_legacy_host_list(self):
        self.limit_scope_to_allowed_host()

        response = self.client.get(reverse('linux_detail'))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'allowed-host')
        self.assertNotContains(response, 'blocked-host')
        self.assertEqual(response.context['sum'], 1)

    def test_empty_host_scope_legacy_host_list_renders_empty_page(self):
        DevOpsHostScope.objects.create(user=self.user)

        response = self.client.get(reverse('linux_detail'))

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context['sum'], 0)
        self.assertEqual(list(response.context['pages']), [])

    def test_user_without_configured_role_can_see_hosts_by_default(self):
        response = self.client.get(reverse('linux_detail'))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'allowed-host')
        self.assertContains(response, 'blocked-host')

    def test_configured_viewer_without_scope_cannot_see_hosts(self):
        self.set_role(DevOpsRole.ROLE_VIEWER)

        response = self.client.get(reverse('linux_detail'))

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context['sum'], 0)
        self.assertNotContains(response, 'allowed-host')

    def test_host_scope_blocks_legacy_host_detail(self):
        self.limit_scope_to_allowed_host()

        response = self.client.get(reverse('linux_list_detail', args=[self.blocked_host.id]))

        self.assertEqual(response.status_code, 403)

    def test_missing_host_detail_returns_404(self):
        response = self.client.get(reverse('linux_list_detail', args=[99999]))

        self.assertEqual(response.status_code, 404)

    @mock.patch('RemoteLinux.views.create_host_ssh_client')
    def test_host_detail_opens_without_collecting_remote_info(self, create_host_ssh_client):
        self.limit_scope_to_allowed_host()

        response = self.client.get(reverse('linux_list_detail', args=[self.host.id]))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, '服务器详情')
        self.assertContains(response, 'allowed-host')
        create_host_ssh_client.assert_not_called()

    @mock.patch('RemoteLinux.views.create_host_ssh_client', side_effect=socket.timeout('timed out'))
    def test_host_detail_collect_failure_renders_page_message(self, create_host_ssh_client):
        self.limit_scope_to_allowed_host()

        response = self.client.get(reverse('linux_list_detail', args=[self.host.id]), {'collect': '1'})

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, '远程采集失败')
        self.assertContains(response, '超时')

    def test_missing_host_update_returns_404(self):
        self.set_role(DevOpsRole.ROLE_OPERATOR)

        response = self.client.get(reverse('linux_update', args=[99999]))

        self.assertEqual(response.status_code, 404)

    def test_missing_host_delete_returns_404(self):
        self.set_role(DevOpsRole.ROLE_OPERATOR)

        response = self.client.post(reverse('linux_delete', args=[99999]))

        self.assertEqual(response.status_code, 404)

    def test_host_scope_blocks_server_status_api(self):
        self.limit_scope_to_allowed_host()

        response = self.client.get(reverse('server_status', args=[self.blocked_host.id]))

        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.json()['status'], 'forbidden')

    @mock.patch('RemoteLinux.views.create_host_ssh_client', side_effect=socket.timeout('timed out'))
    def test_server_status_returns_ssh_error_message(self, create_host_ssh_client):
        response = self.client.get(reverse('server_status', args=[self.host.id]))

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()['status'], 'offline')
        self.assertIn('超时', response.json()['message'])

    @mock.patch('RemoteLinux.views.create_ssh_client', side_effect=socket.timeout('timed out'))
    def test_connect_test_returns_classified_ssh_error(self, create_ssh_client):
        self.set_role(DevOpsRole.ROLE_OPERATOR)

        response = self.client.post(reverse('connect_test'), {
            'linux_ip': '127.0.0.1',
            'linux_port': '22',
            'linux_user': 'root',
            'linux_auth_type': NewLinux.AUTH_PASSWORD,
            'linux_passwd': 'secret',
        })

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, '超时')

    def test_viewer_cannot_open_webssh_when_roles_are_configured(self):
        self.set_role(DevOpsRole.ROLE_VIEWER)

        response = self.client.get(reverse('linux_connect', args=[self.host.id]))

        self.assertEqual(response.status_code, 403)

    def test_operator_opening_webssh_page_records_audit(self):
        self.set_role(DevOpsRole.ROLE_OPERATOR)
        self.limit_scope_to_allowed_host()

        response = self.client.get(reverse('linux_connect', args=[self.host.id]))

        self.assertEqual(response.status_code, 200)
        self.assertTrue(AuditLog.objects.filter(action='打开WebSSH页面', target_id=str(self.host.id)).exists())

    def test_host_create_records_audit(self):
        self.set_role(DevOpsRole.ROLE_OPERATOR)

        response = self.client.post(reverse('linux_create'), {
            'linux_name': 'audit-created',
            'linux_ip': '127.0.0.10',
            'linux_hostname': 'audit-created',
            'linux_port': '22',
            'linux_user': 'root',
            'linux_auth_type': NewLinux.AUTH_PASSWORD,
            'linux_passwd': 'secret',
            'linux_private_key': '',
            'linux_private_key_passphrase': '',
            'linux_app': '',
        })

        self.assertEqual(response.status_code, 302)
        host = NewLinux.objects.get(linux_name='audit-created')
        self.assertTrue(AuditLog.objects.filter(action='创建主机', target_id=str(host.id)).exists())
        detail_response = self.client.get(reverse('linux_detail'))
        self.assertContains(detail_response, 'audit-created')

    def test_host_import_creates_visible_hosts_for_operator(self):
        self.set_role(DevOpsRole.ROLE_OPERATOR)
        upload = SimpleUploadedFile(
            'hosts.csv',
            b'linux_name,linux_ip,linux_hostname,linux_port,linux_user,linux_passwd,linux_app\nimported-host,127.0.0.30,imported,22,root,secret,api\n',
            content_type='text/csv',
        )

        response = self.client.post(reverse('linux_import'), {'file': upload})

        self.assertEqual(response.status_code, 302)
        host = NewLinux.objects.get(linux_name='imported-host')
        self.assertEqual(decrypt_text(host.linux_passwd), 'secret')
        detail_response = self.client.get(reverse('linux_detail'))
        self.assertContains(detail_response, 'imported-host')
        self.assertTrue(AuditLog.objects.filter(action='导入主机', target_id=str(host.id)).exists())

    def test_host_import_page_uses_multipart_file_form(self):
        self.set_role(DevOpsRole.ROLE_OPERATOR)

        response = self.client.get(reverse('linux_import'))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, '"kind": "host-import"')
        self.assertContains(response, 'ops-vue-pages.js')
        self.assertContains(response, '下载模板')

    def test_host_import_accepts_chinese_headers(self):
        self.set_role(DevOpsRole.ROLE_OPERATOR)
        upload = SimpleUploadedFile(
            'hosts-cn.csv',
            '名称,IP,主机名,端口,用户,密码,应用说明\n中文导入,127.0.0.31,cn-host,22,root,secret,api\n'.encode('utf-8-sig'),
            content_type='text/csv',
        )

        response = self.client.post(reverse('linux_import'), {'file': upload})

        self.assertEqual(response.status_code, 302)
        host = NewLinux.objects.get(linux_name='中文导入')
        self.assertEqual(host.linux_ip, '127.0.0.31')
        self.assertEqual(decrypt_text(host.linux_passwd), 'secret')

    def test_host_import_template_downloads_csv(self):
        self.set_role(DevOpsRole.ROLE_OPERATOR)

        response = self.client.get(reverse('linux_import_template'))

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], 'text/csv; charset=utf-8')
        content = response.content.decode('utf-8-sig')
        self.assertIn('名称,IP,主机名,端口,用户,密码', content)

    def test_host_import_requires_file(self):
        self.set_role(DevOpsRole.ROLE_OPERATOR)

        response = self.client.post(reverse('linux_import'), {})

        self.assertEqual(response.status_code, 400)
        self.assertContains(response, '请选择 CSV 文件', status_code=400)

    def test_host_create_invalid_submission_rerenders_form_errors_without_secret_values(self):
        self.set_role(DevOpsRole.ROLE_OPERATOR)

        response = self.client.post(reverse('linux_create'), {
            'linux_name': 'invalid-host',
            'linux_ip': '',
            'linux_hostname': '',
            'linux_port': '22',
            'linux_user': 'root',
            'linux_auth_type': NewLinux.AUTH_KEY,
            'linux_passwd': 'typed-secret',
            'linux_private_key': '',
            'linux_private_key_passphrase': 'typed-passphrase',
            'linux_app': 'nginx',
        })

        self.assertEqual(response.status_code, 400)
        self.assertContains(response, '提交失败，请检查以下内容', status_code=400)
        self.assertContains(response, 'invalid-host', status_code=400)
        self.assertNotContains(response, 'typed-secret', status_code=400)
        self.assertNotContains(response, 'typed-passphrase', status_code=400)

    def test_host_copy_rejects_non_post_requests(self):
        self.set_role(DevOpsRole.ROLE_OPERATOR)

        response = self.client.get(reverse('copy_form'))

        self.assertEqual(response.status_code, 405)

    def test_host_copy_invalid_submission_returns_json_errors(self):
        self.set_role(DevOpsRole.ROLE_OPERATOR)

        response = self.client.post(reverse('copy_form'), {
            'linux_name': 'copy-invalid',
            'linux_ip': '',
            'linux_hostname': '',
            'linux_port': '22',
            'linux_user': 'root',
            'linux_auth_type': NewLinux.AUTH_PASSWORD,
            'linux_passwd': '',
            'linux_private_key': '',
            'linux_private_key_passphrase': '',
            'linux_app': '',
        })

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()['status'], 'error')

    def test_host_update_records_audit(self):
        self.set_role(DevOpsRole.ROLE_OPERATOR)
        self.limit_scope_to_allowed_host()

        response = self.client.post(reverse('linux_update', args=[self.host.id]), {
            'linux_name': 'audit-updated',
            'linux_ip': self.host.linux_ip,
            'linux_hostname': self.host.linux_hostname,
            'linux_port': self.host.linux_port,
            'linux_user': self.host.linux_user,
            'linux_auth_type': NewLinux.AUTH_PASSWORD,
            'linux_passwd': 'new-secret',
            'linux_private_key': '',
            'linux_private_key_passphrase': '',
            'linux_app': '',
        })

        self.assertEqual(response.status_code, 302)
        self.assertTrue(AuditLog.objects.filter(action='更新主机', target_id=str(self.host.id)).exists())

    def test_host_update_page_does_not_render_plaintext_password(self):
        self.set_role(DevOpsRole.ROLE_OPERATOR)
        self.limit_scope_to_allowed_host()
        self.host.linux_passwd = encrypt_text('saved-secret')
        self.host.save()

        response = self.client.get(reverse('linux_update', args=[self.host.id]))

        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, 'saved-secret')
        self.assertContains(response, '留空则保持原密码不变')

    def test_host_update_blank_password_keeps_existing_password(self):
        self.set_role(DevOpsRole.ROLE_OPERATOR)
        self.limit_scope_to_allowed_host()
        self.host.linux_passwd = encrypt_text('saved-secret')
        self.host.save()
        original_password = self.host.linux_passwd

        response = self.client.post(reverse('linux_update', args=[self.host.id]), {
            'linux_name': 'audit-updated-blank-password',
            'linux_ip': self.host.linux_ip,
            'linux_hostname': self.host.linux_hostname,
            'linux_port': self.host.linux_port,
            'linux_user': self.host.linux_user,
            'linux_auth_type': NewLinux.AUTH_PASSWORD,
            'linux_passwd': '',
            'linux_private_key': '',
            'linux_private_key_passphrase': '',
            'linux_app': '',
        })

        self.assertEqual(response.status_code, 302)
        self.host.refresh_from_db()
        self.assertEqual(self.host.linux_passwd, original_password)

    def test_host_update_invalid_submission_rerenders_form_errors(self):
        self.set_role(DevOpsRole.ROLE_OPERATOR)
        self.limit_scope_to_allowed_host()

        response = self.client.post(reverse('linux_update', args=[self.host.id]), {
            'linux_name': 'invalid-update',
            'linux_ip': '',
            'linux_hostname': self.host.linux_hostname,
            'linux_port': self.host.linux_port,
            'linux_user': self.host.linux_user,
            'linux_auth_type': NewLinux.AUTH_PASSWORD,
            'linux_passwd': '',
            'linux_private_key': '',
            'linux_private_key_passphrase': '',
            'linux_app': '',
        })

        self.assertEqual(response.status_code, 400)
        self.assertContains(response, '提交失败，请检查以下内容', status_code=400)
        self.assertContains(response, 'invalid-update', status_code=400)

    def test_host_delete_records_audit(self):
        self.set_role(DevOpsRole.ROLE_OPERATOR)
        group = HostGroup.objects.create(name='delete-allowed')
        group.hosts.add(self.blocked_host)
        scope = DevOpsHostScope.objects.create(user=self.user)
        scope.groups.add(group)

        response = self.client.post(reverse('linux_delete', args=[self.blocked_host.id]))

        self.assertEqual(response.status_code, 302)
        self.assertTrue(AuditLog.objects.filter(action='删除主机', target_id=str(self.blocked_host.id)).exists())
