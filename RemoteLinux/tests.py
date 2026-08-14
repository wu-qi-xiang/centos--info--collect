import json
from datetime import timedelta

from django.test import Client, RequestFactory, TestCase
from django.urls import resolve, reverse
from django.utils import timezone
from unittest import mock
import socket
from django.core.files.uploadedfile import SimpleUploadedFile

from PyLinux.crypto import decrypt_text, encrypt_text
from devops.models import AuditLog, DevOpsHostScope, DevOpsRole, HostGroup
from .collectors import collect_remote_detail, collect_remote_usage
from .models import HostAgent, NewLinux, User
from .agent import create_host_agent, ingest_heartbeat, revoke_host_agent
from .ssh_utils import create_host_ssh_client, describe_ssh_error
from .views import (
    _encrypt_host_credentials, _update_host_credentials, agent_heartbeat,
    agent_fleet, agent_fleet_bulk_revoke, agent_register, agent_revoke,
    agent_rotate_credential, agent_management,
)


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


class HostAgentTests(TestCase):
    def setUp(self):
        self.host = NewLinux.objects.create(
            linux_name='agent-host',
            linux_ip='127.0.0.9',
            linux_port='22',
            linux_user='root',
        )

    def test_registration_returns_opaque_credential_once_and_stores_only_hash(self):
        agent, credential = create_host_agent(self.host)

        self.assertTrue(credential)
        self.assertNotEqual(agent.credential_hash, credential)
        self.assertNotIn(credential, agent.credential_hash)
        self.assertEqual(HostAgent.objects.get(host=self.host).registration_id, agent.registration_id)

    def test_heartbeat_accepts_only_bounded_safe_summary(self):
        agent, credential = create_host_agent(self.host)

        accepted = ingest_heartbeat(
            'Bearer %s.%s' % (agent.registration_id, credential),
            {
                'agent_version': '1.2.3',
                'collection_delay_seconds': 12,
                'system_summary': {
                    'os_family': 'linux',
                    'cpu_count': 4,
                    'memory_total_mb': 8192,
                    'disk_total_gb': 80,
                },
            },
        )

        self.assertTrue(accepted.ok)
        agent.refresh_from_db()
        self.assertEqual(agent.agent_version, '1.2.3')
        self.assertEqual(agent.system_summary['cpu_count'], 4)
        self.assertIsNotNone(agent.last_heartbeat_at)

    def test_heartbeat_rejects_unsafe_or_unknown_payload_and_revoked_credential(self):
        agent, credential = create_host_agent(self.host)
        header = 'Bearer %s.%s' % (agent.registration_id, credential)

        unsafe = ingest_heartbeat(header, {
            'agent_version': '1.2.3',
            'collection_delay_seconds': 0,
            'system_summary': {'os_family': {'command_output': 'not-allowed'}},
        })
        unknown = ingest_heartbeat(header, {
            'agent_version': '1.2.3',
            'collection_delay_seconds': 0,
            'system_summary': {'os_family': 'linux'},
            'command_output': 'not-allowed',
        })
        revoke_host_agent(agent)
        revoked = ingest_heartbeat(header, {
            'agent_version': '1.2.3',
            'collection_delay_seconds': 0,
            'system_summary': {'os_family': 'linux'},
        })

        self.assertFalse(unsafe.ok)
        self.assertFalse(unknown.ok)
        self.assertFalse(revoked.ok)
        self.assertEqual(revoked.code, 'unauthorized')


class HostAgentViewTests(TestCase):
    def setUp(self):
        self.factory = RequestFactory()
        self.user = User.objects.create(
            user='agent-operator', email='agent-operator@example.com',
            password='plain-password', confirm_pwd='plain-password',
        )
        self.host = NewLinux.objects.create(
            linux_name='agent-allowed', linux_ip='127.0.0.21',
            linux_port='22', linux_user='root',
        )
        self.blocked_host = NewLinux.objects.create(
            linux_name='agent-blocked', linux_ip='127.0.0.22',
            linux_port='22', linux_user='root',
        )
        DevOpsRole.objects.create(user=self.user, role=DevOpsRole.ROLE_OPERATOR)
        group = HostGroup.objects.create(name='agent-allowed-group')
        group.hosts.add(self.host)
        scope = DevOpsHostScope.objects.create(user=self.user)
        scope.groups.add(group)
        self.session = self.client.session
        self.session['is_login'] = True
        self.session['user_id'] = self.user.id
        self.session['user_name'] = self.user.user
        self.session.save()

    def _authenticated_request(self, path='/agent/'):
        request = self.factory.post(path)
        request.session = self.session
        return request

    def test_registration_view_enforces_host_scope_and_returns_credential_once(self):
        denied = agent_register(self._authenticated_request(), self.blocked_host.id)
        accepted = agent_register(self._authenticated_request(), self.host.id)
        revoked = agent_revoke(self._authenticated_request(), self.host.id)

        self.assertEqual(denied.status_code, 403)
        self.assertEqual(accepted.status_code, 201)
        self.assertEqual(revoked.status_code, 200)
        self.assertEqual(set(json.loads(accepted.content)), {
            'registration_id', 'credential', 'authorization_format',
        })
        self.assertTrue(AuditLog.objects.filter(action='注册主机Agent').exists())
        self.assertTrue(AuditLog.objects.filter(action='吊销主机Agent').exists())

    def test_heartbeat_view_rejects_unknown_json_fields(self):
        agent, credential = create_host_agent(self.host)
        request = self.factory.post(
            '/agent/heartbeat/',
            data=b'{"agent_version":"1.0","collection_delay_seconds":0,"system_summary":{},"private_key":"x"}',
            content_type='application/json',
            HTTP_AUTHORIZATION='Bearer %s.%s' % (agent.registration_id, credential),
        )

        response = agent_heartbeat(request)

        self.assertEqual(response.status_code, 400)
        self.assertEqual(json.loads(response.content)['status'], 'invalid_payload')

    def test_agent_urls_resolve_to_the_expected_views(self):
        self.assertEqual(resolve('/agents/%s/' % self.host.id).func, agent_management)
        self.assertEqual(resolve('/api/agents/%s/register/' % self.host.id).func, agent_register)
        self.assertEqual(resolve('/api/agents/%s/revoke/' % self.host.id).func, agent_revoke)
        self.assertEqual(resolve('/api/agent/heartbeat/').func, agent_heartbeat)


class HostAgentFleetViewTests(TestCase):
    def setUp(self):
        self.user = User.objects.create(
            user='fleet-operator', email='fleet-operator@example.com',
            password='plain-password', confirm_pwd='plain-password',
        )
        self.allowed_host = NewLinux.objects.create(
            linux_name='fleet-allowed', linux_ip='127.0.0.31',
            linux_port='22', linux_user='root',
        )
        self.offline_host = NewLinux.objects.create(
            linux_name='fleet-offline', linux_ip='127.0.0.32',
            linux_port='22', linux_user='root',
        )
        self.blocked_host = NewLinux.objects.create(
            linux_name='fleet-blocked', linux_ip='127.0.0.33',
            linux_port='22', linux_user='root',
        )
        self.allowed_agent, _ = create_host_agent(self.allowed_host)
        self.offline_agent, _ = create_host_agent(self.offline_host)
        self.blocked_agent, _ = create_host_agent(self.blocked_host)
        self.allowed_agent.last_heartbeat_at = timezone.now()
        self.allowed_agent.save(update_fields=['last_heartbeat_at'])
        self.offline_agent.last_heartbeat_at = timezone.now() - timedelta(hours=1)
        self.offline_agent.save(update_fields=['last_heartbeat_at'])
        DevOpsRole.objects.create(user=self.user, role=DevOpsRole.ROLE_OPERATOR)
        group = HostGroup.objects.create(name='fleet-visible')
        group.hosts.add(self.allowed_host, self.offline_host)
        scope = DevOpsHostScope.objects.create(user=self.user)
        scope.groups.add(group)
        session = self.client.session
        session['is_login'] = True
        session['user_id'] = self.user.id
        session['user_name'] = self.user.user
        session.save()

    def test_fleet_requires_login_and_security_operator_role(self):
        self.assertEqual(Client().get(reverse('agent_fleet')).status_code, 302)
        DevOpsRole.objects.filter(user=self.user).update(role=DevOpsRole.ROLE_VIEWER)
        self.assertEqual(self.client.get(reverse('agent_fleet')).status_code, 403)

    def test_fleet_lists_only_visible_hosts_and_filters_state(self):
        response = self.client.get(reverse('agent_fleet'))
        filtered = self.client.get(reverse('agent_fleet'), {'state': 'healthy'})

        self.assertContains(response, 'fleet-allowed')
        self.assertContains(response, 'fleet-offline')
        self.assertNotContains(response, 'fleet-blocked')
        self.assertContains(filtered, 'fleet-allowed')
        self.assertEqual([row['host_name'] for row in filtered.context['fleet_rows']], ['fleet-allowed'])
        self.assertNotContains(response, self.allowed_agent.credential_hash)

    def test_fleet_marks_registered_agent_without_heartbeat_offline(self):
        self.offline_agent.last_heartbeat_at = None
        self.offline_agent.save(update_fields=['last_heartbeat_at'])

        response = self.client.get(reverse('agent_fleet'), {'state': 'offline'})

        self.assertEqual([row['host_name'] for row in response.context['fleet_rows']], ['fleet-offline'])

    def test_bulk_revoke_requires_every_host_to_be_visible_before_changes(self):
        response = self.client.post(reverse('agent_fleet_bulk_revoke'), {
            'host_ids': [str(self.allowed_host.id), str(self.blocked_host.id)],
        })

        self.assertEqual(response.status_code, 403)
        self.allowed_agent.refresh_from_db()
        self.blocked_agent.refresh_from_db()
        self.assertFalse(self.allowed_agent.is_revoked)
        self.assertFalse(self.blocked_agent.is_revoked)

    def test_bulk_revoke_and_single_host_rotation_are_post_only_and_audited(self):
        self.assertEqual(self.client.get(reverse('agent_fleet_bulk_revoke')).status_code, 405)
        self.assertEqual(self.client.get(reverse('agent_rotate_credential', args=[self.allowed_host.id])).status_code, 405)
        original_hash = self.allowed_agent.credential_hash
        rotated = self.client.post(reverse('agent_rotate_credential', args=[self.allowed_host.id]))
        revoked = self.client.post(reverse('agent_fleet_bulk_revoke'), {
            'host_ids': [str(self.offline_host.id)],
        })

        self.assertEqual(rotated.status_code, 201)
        self.assertEqual(set(rotated.json()), {'registration_id', 'credential', 'authorization_format'})
        self.allowed_agent.refresh_from_db()
        self.offline_agent.refresh_from_db()
        self.assertNotEqual(self.allowed_agent.credential_hash, original_hash)
        self.assertTrue(self.offline_agent.is_revoked)
        self.assertEqual(revoked.status_code, 200)
        self.assertTrue(AuditLog.objects.filter(action='轮换主机Agent凭据').exists())
        self.assertTrue(AuditLog.objects.filter(action='批量吊销主机Agent').exists())

    def test_fleet_urls_resolve_to_expected_views(self):
        self.assertEqual(resolve('/agents/').func, agent_fleet)
        self.assertEqual(resolve('/api/agents/bulk-revoke/').func, agent_fleet_bulk_revoke)
        self.assertEqual(resolve('/api/agents/%s/rotate/' % self.allowed_host.id).func, agent_rotate_credential)


class HostAgentHealthTests(TestCase):
    def setUp(self):
        self.host = NewLinux.objects.create(
            linux_name='agent-health-host', linux_ip='127.0.0.31',
            linux_port='22', linux_user='root',
        )
        self.agent, self.credential = create_host_agent(self.host)

    def test_evaluator_opens_and_resolves_agent_heartbeat_alerts(self):
        from devops.models import AlertEvent
        from .agent_health import evaluate_host_agent_health

        now = timezone.now()
        self.agent.last_heartbeat_at = now - timedelta(seconds=601)
        self.agent.save(update_fields=['last_heartbeat_at'])

        unhealthy = evaluate_host_agent_health(now=now, timeout_seconds=600)
        alert = AlertEvent.objects.get(host=self.host, metric='agent_heartbeat')
        self.assertEqual(unhealthy['offline'], 1)
        self.assertEqual(alert.status, AlertEvent.STATUS_OPEN)

        self.agent.last_heartbeat_at = now
        self.agent.collection_delay_seconds = 0
        self.agent.save(update_fields=['last_heartbeat_at', 'collection_delay_seconds'])
        healthy = evaluate_host_agent_health(now=now, timeout_seconds=600)
        alert.refresh_from_db()
        self.assertEqual(healthy['recovered'], 1)
        self.assertEqual(alert.status, AlertEvent.STATUS_RESOLVED)

    def test_evaluator_marks_excessive_collection_delay_stale_and_skips_revoked_agents(self):
        from devops.models import AlertEvent
        from .agent_health import evaluate_host_agent_health

        now = timezone.now()
        self.agent.last_heartbeat_at = now
        self.agent.collection_delay_seconds = 601
        self.agent.save(update_fields=['last_heartbeat_at', 'collection_delay_seconds'])

        stale = evaluate_host_agent_health(now=now, timeout_seconds=600)
        self.assertEqual(stale['stale'], 1)
        self.assertTrue(AlertEvent.objects.filter(host=self.host, metric='agent_heartbeat').exists())

        revoke_host_agent(self.agent)
        excluded = evaluate_host_agent_health(now=now, timeout_seconds=600)
        self.assertEqual(excluded['revoked'], 1)
        self.assertEqual(excluded['offline'], 0)
        self.assertEqual(excluded['stale'], 0)


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
