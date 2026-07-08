from django.core.files.uploadedfile import SimpleUploadedFile
from django.core.files.base import ContentFile
from django.core.management import call_command
from django.test import TestCase
from django.urls import reverse
from io import StringIO
import json
import socket
try:
    from unittest import mock
except ImportError:
    import mock

from RemoteLinux.models import NewLinux, User
from django.utils import timezone

from .models import (
    AlertEvent,
    AlertHistory,
    AlertSilence,
    ApprovalRequest,
    AuditLog,
    BatchTask,
    BatchTaskResult,
    CommandExecution,
    DeploymentApp,
    DeploymentRelease,
    DeploymentResult,
    DevOpsHostScope,
    DevOpsModulePermission,
    DevOpsSetting,
    DevOpsRole,
    FileDistribution,
    FileDistributionResult,
    HostGroup,
    HostTag,
    MetricSample,
    NotificationChannel,
    NotificationLog,
    ServiceOperation,
)
from .services import cleanup_audit_logs, cleanup_metric_samples, enqueue_background_job, latest_metric_map, record_alert, record_metric_sample, run_background_job, send_notification_channel, validate_remote_path
from .services import execute_batch_task, execute_command_record, execute_deployment_release, execute_deployment_rollback, execute_file_distribution
from .services import COMMAND_ALLOWED, COMMAND_BLOCKED, evaluate_command_policy


class DevOpsViewTests(TestCase):
    def setUp(self):
        self.user = User.objects.create(
            user='tester',
            email='tester@example.com',
            password='plain-password',
            confirm_pwd='plain-password',
        )
        self.host = NewLinux.objects.create(
            linux_name='test-host',
            linux_ip='127.0.0.1',
            linux_hostname='localhost',
            linux_port='22',
            linux_user='root',
            linux_passwd='bad-password',
            linux_app='',
        )
        session = self.client.session
        session['is_login'] = True
        session['user_id'] = self.user.id
        session['user_name'] = self.user.user
        session.save()

    def set_role(self, role):
        DevOpsRole.objects.update_or_create(user=self.user, defaults={'role': role})

    def test_dashboard_requires_login(self):
        self.client.session.flush()

        response = self.client.get(reverse('devops:dashboard'))

        self.assertEqual(response.status_code, 302)
        self.assertIn('/login/', response['Location'])

    def test_api_requires_login(self):
        self.client.session.flush()

        response = self.client.get(reverse('devops:api_bootstrap'))

        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json()['code'], 'unauthorized')

    def test_vue_app_requires_login(self):
        self.client.session.flush()

        response = self.client.get(reverse('devops:vue_app'))

        self.assertEqual(response.status_code, 302)
        self.assertIn('/login/', response['Location'])

    def test_vue_app_renders_shell(self):
        response = self.client.get(reverse('devops:vue_app'))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'devops-vue-root')
        self.assertContains(response, 'devops-vue.js')
        self.assertContains(response, 'DevOps控制台')
        self.assertContains(response, '加载 DevOps 控制台')

    def test_dashboard_uses_vue_shell(self):
        response = self.client.get(reverse('devops:dashboard'))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'devops-vue-root')
        self.assertContains(response, 'DevOps 控制台')
        self.assertContains(response, 'devops-vue.js')

    def test_legacy_dashboard_still_available(self):
        response = self.client.get(reverse('devops:legacy_dashboard'))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'DevOps平台')
        self.assertContains(response, '最近命令')

    def test_api_bootstrap_returns_user_counts_and_module_permissions(self):
        response = self.client.get(reverse('devops:api_bootstrap'))

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertTrue(payload['ok'])
        self.assertEqual(payload['user']['name'], self.user.user)
        self.assertEqual(payload['counts']['hosts'], 1)
        for key in ('command', 'task', 'approval', 'metric', 'deployment', 'file', 'notification'):
            self.assertIn(key, payload['permissions'])

    def test_api_bootstrap_module_permission_flags_respect_overrides(self):
        self.set_role(DevOpsRole.ROLE_ADMIN)
        DevOpsModulePermission.objects.create(
            user=self.user,
            module=DevOpsModulePermission.MODULE_DEPLOYMENT,
            role=DevOpsRole.ROLE_VIEWER,
        )
        DevOpsModulePermission.objects.create(
            user=self.user,
            module=DevOpsModulePermission.MODULE_FILE,
            role=DevOpsRole.ROLE_VIEWER,
        )

        response = self.client.get(reverse('devops:api_bootstrap'))

        self.assertEqual(response.status_code, 200)
        permissions = response.json()['permissions']
        self.assertTrue(permissions['deployment'])
        self.assertTrue(permissions['file'])
        self.assertTrue(permissions['command'])

    def test_api_hosts_returns_visible_hosts(self):
        response = self.client.get(reverse('devops:api_hosts'))

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload['results'][0]['name'], 'test-host')
        self.assertNotIn('linux_passwd', payload['results'][0])

    def test_api_dashboard_returns_recent_data(self):
        CommandExecution.objects.create(host=self.host, command='uptime', status=CommandExecution.STATUS_SUCCESS)
        record_metric_sample(self.host, MetricSample.METRIC_CPU, 0.72)

        response = self.client.get(reverse('devops:api_dashboard'))

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload['counts']['hosts'], 1)
        self.assertEqual(payload['recent_commands'][0]['command'], 'uptime')
        self.assertEqual(payload['host_metrics'][0]['cpu'], 72.0)

    def test_api_bootstrap_counts_respect_host_scope(self):
        allowed_group = HostGroup.objects.create(name='api-bootstrap-allowed')
        allowed_group.hosts.add(self.host)
        other = NewLinux.objects.create(
            linux_name='api-bootstrap-blocked',
            linux_ip='127.0.1.10',
            linux_hostname='api-bootstrap-blocked',
            linux_port='22',
            linux_user='root',
            linux_passwd='bad-password',
            linux_app='',
        )
        AlertEvent.objects.create(host=self.host, message='visible alert', status=AlertEvent.STATUS_OPEN)
        AlertEvent.objects.create(host=other, message='hidden alert', status=AlertEvent.STATUS_OPEN)
        ApprovalRequest.objects.create(
            request_type=ApprovalRequest.TYPE_COMMAND,
            status=ApprovalRequest.STATUS_PENDING,
            title='visible approval',
            host=self.host,
        )
        ApprovalRequest.objects.create(
            request_type=ApprovalRequest.TYPE_COMMAND,
            status=ApprovalRequest.STATUS_PENDING,
            title='hidden approval',
            host=other,
        )
        scope = DevOpsHostScope.objects.create(user=self.user)
        scope.groups.add(allowed_group)

        response = self.client.get(reverse('devops:api_bootstrap'))

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload['counts']['hosts'], 1)
        self.assertEqual(payload['counts']['groups'], 1)
        self.assertEqual(payload['counts']['open_alerts'], 1)
        self.assertEqual(payload['counts']['pending_approvals'], 1)

    def test_api_dashboard_filters_host_scoped_counts_and_alerts(self):
        allowed_group = HostGroup.objects.create(name='api-dashboard-allowed')
        allowed_group.hosts.add(self.host)
        other = NewLinux.objects.create(
            linux_name='api-dashboard-blocked',
            linux_ip='127.0.1.11',
            linux_hostname='api-dashboard-blocked',
            linux_port='22',
            linux_user='root',
            linux_passwd='bad-password',
            linux_app='',
        )
        CommandExecution.objects.create(host=self.host, command='visible-command')
        CommandExecution.objects.create(host=other, command='hidden-command')
        visible_task = BatchTask.objects.create(name='visible-task', command='uptime')
        visible_task.hosts.add(self.host)
        hidden_task = BatchTask.objects.create(name='hidden-task', command='uptime')
        hidden_task.hosts.add(other)
        AlertEvent.objects.create(host=self.host, message='visible alert', status=AlertEvent.STATUS_OPEN)
        AlertEvent.objects.create(host=other, message='hidden alert', status=AlertEvent.STATUS_OPEN)
        scope = DevOpsHostScope.objects.create(user=self.user)
        scope.groups.add(allowed_group)

        response = self.client.get(reverse('devops:api_dashboard'))

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload['counts']['hosts'], 1)
        self.assertEqual(payload['counts']['open_alerts'], 1)
        self.assertEqual(payload['counts']['tasks'], 1)
        self.assertEqual([item['command'] for item in payload['recent_commands']], ['visible-command'])
        self.assertEqual([item['message'] for item in payload['recent_alerts']], ['visible alert'])

    def test_api_alerts_respects_host_scope(self):
        allowed_group = HostGroup.objects.create(name='api-alerts-allowed')
        allowed_group.hosts.add(self.host)
        other = NewLinux.objects.create(
            linux_name='api-alerts-blocked',
            linux_ip='127.0.1.12',
            linux_hostname='api-alerts-blocked',
            linux_port='22',
            linux_user='root',
            linux_passwd='bad-password',
            linux_app='',
        )
        AlertEvent.objects.create(host=self.host, message='visible alert')
        AlertEvent.objects.create(host=other, message='hidden alert')
        scope = DevOpsHostScope.objects.create(user=self.user)
        scope.groups.add(allowed_group)

        response = self.client.get(reverse('devops:api_alerts'))

        self.assertEqual(response.status_code, 200)
        messages = [item['message'] for item in response.json()['results']]
        self.assertEqual(messages, ['visible alert'])

    def test_api_collection_host_counts_use_visible_hosts(self):
        allowed_group = HostGroup.objects.create(name='api-count-allowed')
        allowed_group.hosts.add(self.host)
        other = NewLinux.objects.create(
            linux_name='api-count-blocked',
            linux_ip='127.0.1.13',
            linux_hostname='api-count-blocked',
            linux_port='22',
            linux_user='root',
            linux_passwd='bad-password',
            linux_app='',
        )
        task = BatchTask.objects.create(name='mixed task', command='uptime')
        task.hosts.add(self.host, other)
        app = DeploymentApp.objects.create(name='mixed app')
        release = DeploymentRelease.objects.create(
            app=app,
            version='v1',
            deploy_script='echo deploy',
        )
        release.hosts.add(self.host, other)
        distribution = FileDistribution.objects.create(
            name='mixed file',
            source_file=SimpleUploadedFile('artifact.txt', b'hello'),
            remote_path='/tmp/artifact.txt',
        )
        distribution.hosts.add(self.host, other)
        scope = DevOpsHostScope.objects.create(user=self.user)
        scope.groups.add(allowed_group)

        task_response = self.client.get(reverse('devops:api_tasks'))
        deployment_response = self.client.get(reverse('devops:api_deployments'))
        file_response = self.client.get(reverse('devops:api_files'))

        self.assertEqual(task_response.status_code, 200)
        self.assertEqual(deployment_response.status_code, 200)
        self.assertEqual(file_response.status_code, 200)
        self.assertEqual(task_response.json()['results'][0]['host_count'], 1)
        self.assertEqual(deployment_response.json()['results'][0]['host_count'], 1)
        self.assertEqual(file_response.json()['results'][0]['host_count'], 1)

    def test_audit_logs_can_be_filtered(self):
        AuditLog.objects.create(user='alice', action='创建主机', target_type='NewLinux', target_id='1', detail='prod-web')
        AuditLog.objects.create(user='bob', action='删除密码记录', target_type='Password', target_id='2', detail='legacy')

        response = self.client.get(reverse('devops:audit_logs'), {'q': 'prod', 'user': 'alice'})

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, '创建主机')
        self.assertNotContains(response, '删除密码记录')

    def test_audit_logs_export_csv_uses_current_filter(self):
        AuditLog.objects.create(user='alice', action='创建主机', target_type='NewLinux', target_id='1', detail='prod-web')
        AuditLog.objects.create(user='bob', action='删除密码记录', target_type='Password', target_id='2', detail='legacy')

        response = self.client.get(reverse('devops:audit_logs'), {'target_type': 'NewLinux', 'export': 'csv'})

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], 'text/csv; charset=utf-8')
        content = response.content.decode('utf-8-sig')
        self.assertIn('时间,用户,动作,对象类型,对象ID,详情,IP', content)
        self.assertIn('创建主机', content)
        self.assertNotIn('删除密码记录', content)

    def test_audit_logs_export_csv_escapes_formula_cells(self):
        AuditLog.objects.create(
            user='=cmd',
            action='+action',
            target_type='-type',
            target_id='@id',
            detail='=HYPERLINK("http://example.com")',
            ip_address='127.0.0.1',
        )

        response = self.client.get(reverse('devops:audit_logs'), {'export': 'csv'})

        self.assertEqual(response.status_code, 200)
        content = response.content.decode('utf-8-sig')
        self.assertIn("'=cmd", content)
        self.assertIn("'+action", content)
        self.assertIn("'-type", content)
        self.assertIn("'@id", content)
        self.assertIn("'=HYPERLINK", content)

    def test_cleanup_audit_logs_respects_retention_days(self):
        old_log = AuditLog.objects.create(user='alice', action='old')
        new_log = AuditLog.objects.create(user='bob', action='new')
        AuditLog.objects.filter(id=old_log.id).update(created_at=timezone.now() - timezone.timedelta(days=40))
        AuditLog.objects.filter(id=new_log.id).update(created_at=timezone.now() - timezone.timedelta(days=2))

        deleted = cleanup_audit_logs(30)

        self.assertEqual(deleted, 1)
        self.assertFalse(AuditLog.objects.filter(id=old_log.id).exists())
        self.assertTrue(AuditLog.objects.filter(id=new_log.id).exists())

    def test_cleanup_audit_logs_disabled_by_zero_days(self):
        AuditLog.objects.create(user='alice', action='old')

        deleted = cleanup_audit_logs(0)

        self.assertEqual(deleted, 0)
        self.assertEqual(AuditLog.objects.count(), 1)

    def test_cleanup_audit_logs_command_dry_run_does_not_delete(self):
        old_log = AuditLog.objects.create(user='alice', action='old')
        AuditLog.objects.filter(id=old_log.id).update(created_at=timezone.now() - timezone.timedelta(days=40))
        output = StringIO()

        call_command('cleanup_audit_logs', '--days=30', '--dry-run', stdout=output)

        self.assertIn('将清理 1 条审计日志', output.getvalue())
        self.assertTrue(AuditLog.objects.filter(id=old_log.id).exists())

    def test_api_command_post_creates_record(self):
        response = self.client.post(
            reverse('devops:api_commands'),
            data=json.dumps({'host_id': self.host.id, 'command': 'uptime'}),
            content_type='application/json',
        )

        self.assertEqual(response.status_code, 201)
        payload = response.json()
        self.assertTrue(payload['ok'])
        self.assertEqual(payload['record']['command'], 'uptime')
        self.assertTrue(CommandExecution.objects.filter(command='uptime').exists())

    def test_api_dangerous_command_creates_approval(self):
        response = self.client.post(
            reverse('devops:api_commands'),
            data=json.dumps({'host_id': self.host.id, 'command': 'rm -rf /'}),
            content_type='application/json',
        )

        self.assertEqual(response.status_code, 202)
        payload = response.json()
        self.assertTrue(payload['requires_approval'])
        self.assertEqual(payload['approval']['request_type'], ApprovalRequest.TYPE_COMMAND)

    def test_api_command_detail_respects_host_scope(self):
        allowed_group = HostGroup.objects.create(name='api-allowed')
        allowed_group.hosts.add(self.host)
        other = NewLinux.objects.create(
            linux_name='api-blocked',
            linux_ip='127.0.0.4',
            linux_hostname='blocked',
            linux_port='22',
            linux_user='root',
            linux_passwd='bad-password',
            linux_app='',
        )
        record = CommandExecution.objects.create(host=other, command='uptime')
        scope = DevOpsHostScope.objects.create(user=self.user)
        scope.groups.add(allowed_group)

        response = self.client.get(reverse('devops:api_command_detail', args=[record.id]))

        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.json()['code'], 'host_forbidden')

    def test_api_task_post_creates_task(self):
        response = self.client.post(
            reverse('devops:api_tasks'),
            data=json.dumps({'name': 'api task', 'host_ids': [self.host.id], 'command': 'hostname'}),
            content_type='application/json',
        )

        self.assertEqual(response.status_code, 201)
        task = BatchTask.objects.get(name='api task')
        self.assertEqual(task.hosts.get(), self.host)

    def test_api_metrics_returns_series(self):
        record_metric_sample(self.host, MetricSample.METRIC_CPU, 0.5)
        record_metric_sample(self.host, MetricSample.METRIC_MEMORY, 0.7)

        response = self.client.get(reverse('devops:api_metrics'), {'host': self.host.id, 'range': '24h'})

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload['host']['id'], self.host.id)
        self.assertIn('cpu', payload['series'])

    def test_dangerous_command_auto_creates_approval(self):
        response = self.client.post(reverse('devops:command_center'), {
            'host': self.host.id,
            'command': 'rm -rf /',
        })

        self.assertEqual(response.status_code, 302)
        self.assertFalse(CommandExecution.objects.exists())
        approval = ApprovalRequest.objects.get()
        self.assertEqual(approval.request_type, ApprovalRequest.TYPE_COMMAND)
        self.assertEqual(approval.status, ApprovalRequest.STATUS_PENDING)
        self.assertIn('拦截', approval.reason)
        self.assertTrue(AuditLog.objects.filter(action='高危命令转审批').exists())

    def test_default_command_policy_blocks_common_variants(self):
        blocked_commands = [
            'rm -fr /',
            'RM   -rf   /',
        ]

        for command in blocked_commands:
            decision, policy = evaluate_command_policy(command)
            self.assertEqual(decision, COMMAND_BLOCKED)

    def test_default_command_policy_rejects_power_command_variants(self):
        commands = [
            'sudo reboot',
            '/sbin/poweroff',
        ]

        for command in commands:
            decision, policy = evaluate_command_policy(command)
            self.assertNotEqual(decision, COMMAND_ALLOWED)

    def test_viewer_cannot_execute_command_when_roles_are_configured(self):
        self.set_role(DevOpsRole.ROLE_VIEWER)

        response = self.client.post(reverse('devops:command_center'), {
            'host': self.host.id,
            'command': 'uptime',
        })

        self.assertEqual(response.status_code, 403)
        self.assertFalse(CommandExecution.objects.exists())

    def test_admin_required_command_auto_creates_approval_for_operator(self):
        self.set_role(DevOpsRole.ROLE_OPERATOR)
        allowed_group = HostGroup.objects.create(name='operator-allowed')
        allowed_group.hosts.add(self.host)
        scope = DevOpsHostScope.objects.create(user=self.user)
        scope.groups.add(allowed_group)

        response = self.client.post(reverse('devops:command_center'), {
            'host': self.host.id,
            'command': 'reboot',
        })

        self.assertEqual(response.status_code, 302)
        self.assertFalse(CommandExecution.objects.exists())
        approval = ApprovalRequest.objects.get()
        self.assertEqual(approval.request_type, ApprovalRequest.TYPE_COMMAND)
        self.assertIn('管理员权限', approval.reason)

    def test_blocked_batch_task_records_host_results(self):
        response = self.client.post(reverse('devops:batch_tasks'), {
            'name': 'dangerous batch',
            'hosts': [self.host.id],
            'command': 'rm -rf /',
        })

        self.assertEqual(response.status_code, 302)
        task = BatchTask.objects.get()
        result = BatchTaskResult.objects.get(task=task)
        self.assertEqual(task.status, BatchTask.STATUS_BLOCKED)
        self.assertEqual(result.host, self.host)
        self.assertEqual(result.status, CommandExecution.STATUS_BLOCKED)

    def test_group_and_tag_can_be_created(self):
        group_response = self.client.post(reverse('devops:group_create'), {
            'name': 'prod',
            'description': 'production hosts',
            'hosts': [self.host.id],
        })
        tag_response = self.client.post(reverse('devops:tag_create'), {
            'name': 'web',
            'color': 'primary',
            'description': 'web servers',
            'hosts': [self.host.id],
        })

        self.assertEqual(group_response.status_code, 302)
        self.assertEqual(tag_response.status_code, 302)
        self.assertEqual(HostGroup.objects.get(name='prod').hosts.get(), self.host)
        self.assertEqual(HostTag.objects.get(name='web').hosts.get(), self.host)

    def test_module_permission_overrides_global_role(self):
        self.set_role(DevOpsRole.ROLE_ADMIN)
        DevOpsModulePermission.objects.create(
            user=self.user,
            module=DevOpsModulePermission.MODULE_COMMAND,
            role=DevOpsRole.ROLE_VIEWER,
        )

        response = self.client.post(reverse('devops:command_center'), {
            'host': self.host.id,
            'command': 'uptime',
        })

        self.assertEqual(response.status_code, 403)
        self.assertFalse(CommandExecution.objects.exists())

    def test_host_scope_filters_command_form_and_records(self):
        allowed_group = HostGroup.objects.create(name='allowed')
        allowed_group.hosts.add(self.host)
        other = NewLinux.objects.create(
            linux_name='out-of-scope',
            linux_ip='127.0.0.2',
            linux_hostname='other',
            linux_port='22',
            linux_user='root',
            linux_passwd='bad-password',
            linux_app='',
        )
        CommandExecution.objects.create(host=self.host, command='uptime')
        CommandExecution.objects.create(host=other, command='hostname')
        scope = DevOpsHostScope.objects.create(user=self.user)
        scope.groups.add(allowed_group)

        response = self.client.get(reverse('devops:command_center'))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'test-host')
        self.assertNotContains(response, 'out-of-scope')
        self.assertContains(response, 'uptime')
        self.assertNotContains(response, 'hostname')

    def test_host_scope_allows_hosts_by_tag(self):
        allowed_tag = HostTag.objects.create(name='allowed-tag', color='success')
        allowed_tag.hosts.add(self.host)
        other = NewLinux.objects.create(
            linux_name='tag-out-of-scope',
            linux_ip='127.0.0.12',
            linux_hostname='tag-other',
            linux_port='22',
            linux_user='root',
            linux_passwd='bad-password',
            linux_app='',
        )
        CommandExecution.objects.create(host=self.host, command='uptime')
        CommandExecution.objects.create(host=other, command='hostname')
        scope = DevOpsHostScope.objects.create(user=self.user)
        scope.tags.add(allowed_tag)

        response = self.client.get(reverse('devops:command_center'))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'test-host')
        self.assertNotContains(response, 'tag-out-of-scope')
        self.assertContains(response, 'uptime')
        self.assertNotContains(response, 'hostname')

    def test_empty_host_scope_allows_no_hosts(self):
        DevOpsHostScope.objects.create(user=self.user)
        CommandExecution.objects.create(host=self.host, command='uptime')

        response = self.client.get(reverse('devops:command_center'))

        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, 'test-host')
        self.assertNotContains(response, 'uptime')

    def test_non_admin_without_host_scope_sees_no_hosts_by_default(self):
        self.set_role(DevOpsRole.ROLE_OPERATOR)

        response = self.client.get(reverse('devops:api_hosts'))

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()['results'], [])

    def test_admin_without_host_scope_sees_all_hosts_by_default(self):
        self.set_role(DevOpsRole.ROLE_ADMIN)

        response = self.client.get(reverse('devops:api_hosts'))

        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.json()['results']), 1)

    def test_host_scope_set_saves_tags(self):
        self.set_role(DevOpsRole.ROLE_ADMIN)
        group = HostGroup.objects.create(name='scope-group')
        group.hosts.add(self.host)
        tag = HostTag.objects.create(name='scope-tag', color='primary')
        tag.hosts.add(self.host)

        response = self.client.post(reverse('devops:host_scope_set'), {
            'user': self.user.id,
            'groups': [group.id],
            'tags': [tag.id],
        })

        self.assertEqual(response.status_code, 302)
        scope = DevOpsHostScope.objects.get(user=self.user)
        self.assertEqual(scope.groups.get(), group)
        self.assertEqual(scope.tags.get(), tag)
        log = AuditLog.objects.get(action='设置主机范围')
        self.assertIn('用户=tester', log.detail)
        self.assertIn('主机组=scope-group', log.detail)
        self.assertIn('标签=scope-tag', log.detail)

    def test_host_scope_blocks_command_detail_for_unscoped_host(self):
        allowed_group = HostGroup.objects.create(name='allowed-detail')
        allowed_group.hosts.add(self.host)
        other = NewLinux.objects.create(
            linux_name='blocked-detail',
            linux_ip='127.0.0.3',
            linux_hostname='blocked',
            linux_port='22',
            linux_user='root',
            linux_passwd='bad-password',
            linux_app='',
        )
        record = CommandExecution.objects.create(host=other, command='uptime')
        scope = DevOpsHostScope.objects.create(user=self.user)
        scope.groups.add(allowed_group)

        response = self.client.get(reverse('devops:command_detail', args=[record.id]))

        self.assertEqual(response.status_code, 403)

    def test_command_detail_renders_full_record(self):
        record = CommandExecution.objects.create(
            host=self.host,
            command='uptime',
            status=CommandExecution.STATUS_SUCCESS,
            output='system up',
            created_by=self.user.user,
        )

        response = self.client.get(reverse('devops:command_detail', args=[record.id]))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'uptime')
        self.assertContains(response, 'system up')
        self.assertContains(response, '重试次数')
        self.assertContains(response, 'SSH连接超时')
        self.assertContains(response, '命令超时')

    def test_background_job_runs_inline_during_tests(self):
        state = []

        result = enqueue_background_job(lambda value: state.append(value), 'done')

        self.assertIsNone(result)
        self.assertEqual(state, ['done'])

    @mock.patch('devops.services.print')
    def test_background_job_marks_command_failed_on_unhandled_exception(self, print_mock):
        record = CommandExecution.objects.create(
            host=self.host,
            command='uptime',
            status=CommandExecution.STATUS_RUNNING,
            created_by=self.user.user,
        )

        def boom(target_record):
            raise RuntimeError('worker crashed')

        run_background_job(boom, (record,), {})

        record.refresh_from_db()
        self.assertEqual(record.status, CommandExecution.STATUS_FAILED)
        self.assertIn('worker crashed', record.error)
        self.assertIsNotNone(record.finished_at)
        self.assertTrue(AuditLog.objects.filter(
            action='后台任务异常',
            target_type='CommandExecution',
            target_id=str(record.id),
        ).exists())

    @mock.patch('devops.services.print')
    def test_background_job_marks_batch_task_failed_on_unhandled_exception(self, print_mock):
        task = BatchTask.objects.create(
            name='boom task',
            command='uptime',
            status=BatchTask.STATUS_RUNNING,
            created_by=self.user.user,
        )

        def boom(target_task):
            raise RuntimeError('batch crashed')

        run_background_job(boom, (task,), {})

        task.refresh_from_db()
        self.assertEqual(task.status, BatchTask.STATUS_FAILED)
        self.assertIn('batch crashed', task.summary)
        self.assertIsNotNone(task.finished_at)

    def test_batch_task_detail_renders_runtime_config(self):
        task = BatchTask.objects.create(
            name='detail task',
            command='uptime',
            status=BatchTask.STATUS_SUCCESS,
            created_by=self.user.user,
        )
        task.hosts.add(self.host)
        BatchTaskResult.objects.create(
            task=task,
            host=self.host,
            status=CommandExecution.STATUS_SUCCESS,
            output='ok',
        )

        response = self.client.get(reverse('devops:batch_task_detail', args=[task.id]))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, '重试次数')
        self.assertContains(response, 'SSH连接超时')
        self.assertContains(response, '命令超时')

    @mock.patch('devops.services.create_host_ssh_client', side_effect=socket.timeout('timed out'))
    def test_execute_command_record_classifies_ssh_error(self, create_host_ssh_client):
        record = CommandExecution.objects.create(
            host=self.host,
            command='uptime',
            created_by=self.user.user,
        )

        execute_command_record(record)

        record.refresh_from_db()
        self.assertEqual(record.status, CommandExecution.STATUS_FAILED)
        self.assertIn('超时', record.error)

    @mock.patch('devops.services.settings.DEVOPS_TASK_RETRY_COUNT', 1)
    @mock.patch('devops.services.create_host_ssh_client')
    def test_execute_command_record_retries_transient_ssh_error(self, create_host_ssh_client):
        class FakeStream(object):
            def __init__(self, value):
                self.value = value

            def read(self):
                return self.value

        class FakeClient(object):
            def exec_command(self, command, timeout=60):
                return None, FakeStream(b'ok'), FakeStream(b'')

            def close(self):
                pass

        create_host_ssh_client.side_effect = [socket.timeout('timed out'), FakeClient()]
        record = CommandExecution.objects.create(
            host=self.host,
            command='uptime',
            created_by=self.user.user,
        )

        execute_command_record(record)

        record.refresh_from_db()
        self.assertEqual(record.status, CommandExecution.STATUS_SUCCESS)
        self.assertEqual(record.output, 'ok')
        self.assertEqual(create_host_ssh_client.call_count, 2)

    @mock.patch('devops.services.settings.DEVOPS_COMMAND_OUTPUT_MAX_BYTES', 4)
    @mock.patch('devops.services.create_host_ssh_client')
    def test_execute_command_record_truncates_large_output(self, create_host_ssh_client):
        class FakeStream(object):
            def __init__(self, value):
                self.value = value

            def read(self):
                return self.value

        class FakeClient(object):
            def exec_command(self, command, timeout=60):
                return None, FakeStream(b'abcdef'), FakeStream(b'')

            def close(self):
                pass

        create_host_ssh_client.return_value = FakeClient()
        record = CommandExecution.objects.create(
            host=self.host,
            command='cat big.log',
            created_by=self.user.user,
        )

        execute_command_record(record)

        record.refresh_from_db()
        self.assertTrue(record.output.startswith('abcd'))
        self.assertIn('输出已截断', record.output)

    @mock.patch('devops.services.settings.DEVOPS_COMMAND_TIMEOUT_SECONDS', 7)
    @mock.patch('devops.services.settings.DEVOPS_SSH_CONNECT_TIMEOUT_SECONDS', 3)
    @mock.patch('devops.services.create_host_ssh_client')
    def test_execute_command_record_uses_configured_timeouts(self, create_host_ssh_client):
        class FakeStream(object):
            def __init__(self, value):
                self.value = value

            def read(self):
                return self.value

        class FakeClient(object):
            def __init__(self):
                self.exec_timeout = None

            def exec_command(self, command, timeout=60):
                self.exec_timeout = timeout
                return None, FakeStream(b'ok'), FakeStream(b'')

            def close(self):
                pass

        client = FakeClient()
        create_host_ssh_client.return_value = client
        record = CommandExecution.objects.create(
            host=self.host,
            command='uptime',
            created_by=self.user.user,
        )

        execute_command_record(record)

        self.assertEqual(create_host_ssh_client.call_args[1]['timeout'], 3)
        self.assertEqual(client.exec_timeout, 7)

    @mock.patch('devops.services.create_host_ssh_client')
    def test_execute_command_record_is_idempotent_after_started(self, create_host_ssh_client):
        record = CommandExecution.objects.create(
            host=self.host,
            command='uptime',
            status=CommandExecution.STATUS_RUNNING,
            created_by=self.user.user,
        )

        execute_command_record(record)

        record.refresh_from_db()
        self.assertEqual(record.status, CommandExecution.STATUS_RUNNING)
        create_host_ssh_client.assert_not_called()

    def test_execute_batch_task_is_idempotent_after_started(self):
        task = BatchTask.objects.create(
            name='already running',
            command='uptime',
            status=BatchTask.STATUS_RUNNING,
            created_by=self.user.user,
        )
        task.hosts.add(self.host)

        execute_batch_task(task)

        task.refresh_from_db()
        self.assertEqual(task.status, BatchTask.STATUS_RUNNING)
        self.assertFalse(CommandExecution.objects.exists())
        self.assertFalse(BatchTaskResult.objects.exists())

    def test_service_operation_rejects_unsafe_service_name(self):
        self.set_role(DevOpsRole.ROLE_OPERATOR)
        group = HostGroup.objects.create(name='service-allowed')
        group.hosts.add(self.host)
        scope = DevOpsHostScope.objects.create(user=self.user)
        scope.groups.add(group)

        response = self.client.post(reverse('devops:service_manage'), {
            'host': self.host.id,
            'service_name': 'nginx; reboot',
            'action': 'restart',
        })

        self.assertEqual(response.status_code, 200)
        self.assertFalse(CommandExecution.objects.filter(command__contains='nginx; reboot').exists())
        self.assertFalse(ServiceOperation.objects.exists())

    def test_alerts_are_deduplicated_by_host_and_metric(self):
        with mock.patch('devops.services.notify_alert') as notify:
            first, created_first = record_alert(self.host, 'cpu', 'cpu high')
            second, created_second = record_alert(self.host, 'cpu', 'cpu still high')

        self.assertTrue(created_first)
        self.assertFalse(created_second)
        self.assertEqual(first.id, second.id)
        second.refresh_from_db()
        self.assertEqual(second.repeat_count, 2)
        self.assertEqual(AlertEvent.objects.count(), 1)
        notify.assert_called_once_with(first)

    def test_alert_silence_marks_matching_alert(self):
        now = timezone.now()
        AlertSilence.objects.create(
            host=self.host,
            metric='memory',
            reason='maintenance',
            starts_at=now - timezone.timedelta(minutes=5),
            ends_at=now + timezone.timedelta(minutes=30),
            created_by=self.user.user,
        )

        with mock.patch('devops.services.notify_alert') as notify:
            alert, created = record_alert(self.host, 'memory', 'memory high')

        self.assertTrue(created)
        self.assertEqual(alert.status, AlertEvent.STATUS_SILENCED)
        notify.assert_not_called()

    def test_alert_silence_rejects_end_before_start(self):
        self.set_role(DevOpsRole.ROLE_OPERATOR)
        now = timezone.now()

        response = self.client.post(reverse('devops:silence_create'), {
            'host': self.host.id,
            'metric': 'cpu',
            'reason': 'invalid window',
            'starts_at': (now + timezone.timedelta(hours=1)).strftime('%Y-%m-%d %H:%M'),
            'ends_at': now.strftime('%Y-%m-%d %H:%M'),
        })

        self.assertEqual(response.status_code, 302)
        self.assertFalse(AlertSilence.objects.filter(reason='invalid window').exists())

    def test_alert_update_creates_history(self):
        self.set_role(DevOpsRole.ROLE_OPERATOR)
        alert = AlertEvent.objects.create(
            host=self.host,
            metric='disk',
            message='disk high',
            fingerprint='host:disk',
        )

        response = self.client.post(reverse('devops:alert_update', args=[alert.id]), {
            'status': AlertEvent.STATUS_RESOLVED,
            'handler': self.user.user,
            'remark': 'fixed',
        })

        self.assertEqual(response.status_code, 302)
        history = AlertHistory.objects.get(alert=alert)
        self.assertEqual(history.from_status, AlertEvent.STATUS_OPEN)
        self.assertEqual(history.to_status, AlertEvent.STATUS_RESOLVED)

    def test_alert_events_can_filter_collection_failures(self):
        AlertEvent.objects.create(
            host=self.host,
            metric='collector',
            level=AlertEvent.LEVEL_CRITICAL,
            message='collection failed',
            fingerprint='collector',
        )
        AlertEvent.objects.create(
            host=self.host,
            metric='cpu',
            level=AlertEvent.LEVEL_WARNING,
            message='cpu high',
            fingerprint='cpu',
        )

        response = self.client.get(reverse('devops:alert_events'), {'metric': 'collector'})

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'collection failed')
        self.assertNotContains(response, 'cpu high')
        self.assertContains(response, '采集失败 1')

    def test_alert_update_returns_to_filtered_alert_page(self):
        self.set_role(DevOpsRole.ROLE_OPERATOR)
        alert = AlertEvent.objects.create(
            host=self.host,
            metric='collector',
            message='collection failed',
            fingerprint='collector',
        )

        response = self.client.post(reverse('devops:alert_update', args=[alert.id]), {
            'status': AlertEvent.STATUS_PROCESSING,
            'handler': self.user.user,
            'remark': 'checking',
            'next': reverse('devops:alert_events') + '?metric=collector',
        })

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response['Location'], reverse('devops:alert_events') + '?metric=collector')

    def test_alert_update_rejects_external_next_url(self):
        self.set_role(DevOpsRole.ROLE_OPERATOR)
        alert = AlertEvent.objects.create(
            host=self.host,
            metric='collector',
            message='collection failed',
            fingerprint='collector-external-next',
        )

        response = self.client.post(reverse('devops:alert_update', args=[alert.id]), {
            'status': AlertEvent.STATUS_PROCESSING,
            'handler': self.user.user,
            'remark': 'checking',
            'next': 'https://evil.example/phish',
        })

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response['Location'], reverse('devops:alert_events'))

    def test_metric_samples_are_recorded_and_latest_map_returns_newest(self):
        older = timezone.now() - timezone.timedelta(minutes=5)
        newer = timezone.now()
        record_metric_sample(self.host, MetricSample.METRIC_CPU, 0.5, collected_at=older)
        latest = record_metric_sample(self.host, MetricSample.METRIC_CPU, 0.8, collected_at=newer)

        latest_map = latest_metric_map([self.host])

        self.assertEqual(latest_map[(self.host.id, MetricSample.METRIC_CPU)].id, latest.id)

    def test_cleanup_metric_samples_removes_only_expired_rows(self):
        now = timezone.now()
        old_sample = record_metric_sample(
            self.host,
            MetricSample.METRIC_CPU,
            0.5,
            collected_at=now - timezone.timedelta(days=40),
        )
        fresh_sample = record_metric_sample(
            self.host,
            MetricSample.METRIC_CPU,
            0.8,
            collected_at=now - timezone.timedelta(days=2),
        )

        deleted = cleanup_metric_samples(retention_days=30, now=now)

        self.assertEqual(deleted, 1)
        self.assertFalse(MetricSample.objects.filter(id=old_sample.id).exists())
        self.assertTrue(MetricSample.objects.filter(id=fresh_sample.id).exists())

    def test_cleanup_metric_samples_disabled_with_zero_days(self):
        record_metric_sample(
            self.host,
            MetricSample.METRIC_MEMORY,
            0.5,
            collected_at=timezone.now() - timezone.timedelta(days=40),
        )

        deleted = cleanup_metric_samples(retention_days=0)

        self.assertEqual(deleted, 0)
        self.assertEqual(MetricSample.objects.count(), 1)

    def test_metrics_history_page_renders_samples(self):
        record_metric_sample(self.host, MetricSample.METRIC_MEMORY, 0.7)

        response = self.client.get(reverse('devops:metrics_history'))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, '监控历史')
        self.assertContains(response, '内存')
        self.assertContains(response, '70.00%')

    def test_metrics_history_filters_by_host_and_range(self):
        other = NewLinux.objects.create(
            linux_name='other-host',
            linux_ip='127.0.0.2',
            linux_hostname='other',
            linux_port='22',
            linux_user='root',
            linux_passwd='bad-password',
            linux_app='',
        )
        record_metric_sample(other, MetricSample.METRIC_CPU, 0.3)
        record_metric_sample(self.host, MetricSample.METRIC_CPU, 0.8)
        record_metric_sample(self.host, MetricSample.METRIC_MEMORY, 0.6)
        record_metric_sample(self.host, MetricSample.METRIC_DISK, 0.4)

        response = self.client.get(reverse('devops:metrics_history'), {
            'host': self.host.id,
            'range': '6h',
        })

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, '最近 6 小时')
        self.assertContains(response, '"host_name": "test-host"')
        self.assertContains(response, '80.0')

    def test_validate_remote_path_rejects_unsafe_paths(self):
        self.assertEqual(validate_remote_path('relative/path')[0], False)
        self.assertEqual(validate_remote_path('/tmp/../etc/passwd')[0], False)
        self.assertEqual(validate_remote_path('/')[0], False)
        self.assertEqual(validate_remote_path('/tmp/app.conf'), (True, '/tmp/app.conf'))

    def test_file_distribution_rejects_invalid_remote_path_before_creating_record(self):
        upload = SimpleUploadedFile('config.txt', b'hello')

        response = self.client.post(reverse('devops:file_distributions'), {
            'name': 'bad path',
            'source_file': upload,
            'remote_path': 'tmp/config.txt',
            'hosts': [self.host.id],
        })

        self.assertEqual(response.status_code, 200)
        self.assertFalse(FileDistribution.objects.exists())
        self.assertFalse(FileDistributionResult.objects.exists())

    @mock.patch('devops.services.settings.DEVOPS_TASK_RETRY_COUNT', 1)
    @mock.patch('devops.services.create_host_ssh_client')
    def test_file_distribution_retries_transient_ssh_error(self, create_host_ssh_client):
        class FakeSftp(object):
            def put(self, source, target):
                pass

            def close(self):
                pass

        class FakeClient(object):
            def open_sftp(self):
                return FakeSftp()

            def close(self):
                pass

        distribution = FileDistribution.objects.create(
            name='retry distribution',
            remote_path='/tmp/config.txt',
            created_by=self.user.user,
        )
        distribution.hosts.add(self.host)
        distribution.source_file.save('config.txt', ContentFile(b'hello'), save=True)
        create_host_ssh_client.side_effect = [socket.timeout('timed out'), FakeClient()]

        execute_file_distribution(distribution)

        distribution.refresh_from_db()
        result = FileDistributionResult.objects.get(distribution=distribution)
        self.assertEqual(distribution.status, FileDistribution.STATUS_SUCCESS)
        self.assertEqual(result.status, CommandExecution.STATUS_SUCCESS)
        self.assertEqual(create_host_ssh_client.call_count, 2)

    @mock.patch('devops.services.create_host_ssh_client')
    def test_file_distribution_is_idempotent_after_started(self, create_host_ssh_client):
        distribution = FileDistribution.objects.create(
            name='already running distribution',
            remote_path='/tmp/config.txt',
            status=FileDistribution.STATUS_RUNNING,
            created_by=self.user.user,
        )
        distribution.hosts.add(self.host)
        distribution.source_file.save('config.txt', ContentFile(b'hello'), save=True)

        execute_file_distribution(distribution)

        distribution.refresh_from_db()
        self.assertEqual(distribution.status, FileDistribution.STATUS_RUNNING)
        self.assertFalse(FileDistributionResult.objects.exists())
        create_host_ssh_client.assert_not_called()

    def test_file_distribution_page_renders(self):
        response = self.client.get(reverse('devops:file_distributions'))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, '文件分发')

    def test_viewer_cannot_create_file_distribution_when_roles_are_configured(self):
        self.set_role(DevOpsRole.ROLE_VIEWER)
        upload = SimpleUploadedFile('config.txt', b'hello')

        response = self.client.post(reverse('devops:file_distributions'), {
            'name': 'blocked upload',
            'source_file': upload,
            'remote_path': '/tmp/config.txt',
            'hosts': [self.host.id],
        })

        self.assertEqual(response.status_code, 403)
        self.assertFalse(FileDistribution.objects.exists())

    def test_deployment_app_can_be_created(self):
        response = self.client.post(reverse('devops:deployments'), {
            'form_type': 'app',
            'name': 'order-service',
            'description': 'order app',
        })

        self.assertEqual(response.status_code, 302)
        self.assertTrue(DeploymentApp.objects.filter(name='order-service').exists())

    def test_dangerous_deployment_is_blocked_with_host_results(self):
        app = DeploymentApp.objects.create(name='billing-service', created_by=self.user.user)

        response = self.client.post(reverse('devops:deployments'), {
            'form_type': 'release',
            'app': app.id,
            'version': 'v1.0.0',
            'description': 'blocked release',
            'deploy_script': 'rm -rf /',
            'rollback_script': 'echo rollback',
            'hosts': [self.host.id],
        })

        self.assertEqual(response.status_code, 302)
        release = DeploymentRelease.objects.get()
        result = DeploymentResult.objects.get(release=release)
        self.assertEqual(release.status, DeploymentRelease.STATUS_BLOCKED)
        self.assertEqual(result.status, CommandExecution.STATUS_BLOCKED)

    def test_deployment_release_is_idempotent_after_started(self):
        app = DeploymentApp.objects.create(name='running-release', created_by=self.user.user)
        release = DeploymentRelease.objects.create(
            app=app,
            version='v1',
            deploy_script='echo deploy',
            rollback_script='echo rollback',
            status=DeploymentRelease.STATUS_RUNNING,
            created_by=self.user.user,
        )
        release.hosts.add(self.host)
        DeploymentResult.objects.create(
            release=release,
            host=self.host,
            action=DeploymentResult.ACTION_DEPLOY,
            status=CommandExecution.STATUS_SUCCESS,
        )

        execute_deployment_release(release)

        release.refresh_from_db()
        self.assertEqual(release.status, DeploymentRelease.STATUS_RUNNING)
        self.assertFalse(CommandExecution.objects.exists())
        self.assertEqual(DeploymentResult.objects.filter(release=release).count(), 1)

    def test_deployment_rollback_is_idempotent_after_started(self):
        app = DeploymentApp.objects.create(name='running-rollback', created_by=self.user.user)
        release = DeploymentRelease.objects.create(
            app=app,
            version='v1',
            deploy_script='echo deploy',
            rollback_script='echo rollback',
            status=DeploymentRelease.STATUS_RUNNING,
            created_by=self.user.user,
        )
        release.hosts.add(self.host)
        DeploymentResult.objects.create(
            release=release,
            host=self.host,
            action=DeploymentResult.ACTION_ROLLBACK,
            status=CommandExecution.STATUS_SUCCESS,
        )

        execute_deployment_rollback(release)

        release.refresh_from_db()
        self.assertEqual(release.status, DeploymentRelease.STATUS_RUNNING)
        self.assertFalse(CommandExecution.objects.exists())
        self.assertEqual(DeploymentResult.objects.filter(release=release).count(), 1)

    def test_deployment_detail_renders_release(self):
        app = DeploymentApp.objects.create(name='web-service', created_by=self.user.user)
        release = DeploymentRelease.objects.create(
            app=app,
            version='v1.0.1',
            deploy_script='echo deploy',
            rollback_script='echo rollback',
            created_by=self.user.user,
        )

        response = self.client.get(reverse('devops:deployment_detail', args=[release.id]))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'web-service')
        self.assertContains(response, 'v1.0.1')

    def test_deployment_rollback_without_script_updates_summary(self):
        app = DeploymentApp.objects.create(name='empty-rollback', created_by=self.user.user)
        release = DeploymentRelease.objects.create(
            app=app,
            version='v1',
            deploy_script='echo deploy',
            rollback_script='',
            status=DeploymentRelease.STATUS_SUCCESS,
            created_by=self.user.user,
        )

        response = self.client.post(reverse('devops:deployment_rollback', args=[release.id]))

        self.assertEqual(response.status_code, 302)
        release.refresh_from_db()
        self.assertEqual(release.summary, '未配置回滚脚本')

    def test_force_rollback_approval_creates_approval(self):
        DevOpsSetting.objects.create(force_rollback_approval=True)
        app = DeploymentApp.objects.create(name='rollback-approval', created_by=self.user.user)
        release = DeploymentRelease.objects.create(
            app=app,
            version='v1',
            deploy_script='echo deploy',
            rollback_script='echo rollback',
            created_by=self.user.user,
        )

        response = self.client.post(reverse('devops:deployment_rollback', args=[release.id]))

        self.assertEqual(response.status_code, 302)
        approval = ApprovalRequest.objects.get()
        self.assertEqual(approval.request_type, ApprovalRequest.TYPE_ROLLBACK)
        self.assertEqual(approval.deployment_release, release)

    def test_viewer_cannot_create_deployment_when_roles_are_configured(self):
        self.set_role(DevOpsRole.ROLE_VIEWER)
        app = DeploymentApp.objects.create(name='viewer-app', created_by=self.user.user)

        response = self.client.post(reverse('devops:deployments'), {
            'form_type': 'release',
            'app': app.id,
            'version': 'v1',
            'deploy_script': 'echo deploy',
            'rollback_script': '',
            'hosts': [self.host.id],
        })

        self.assertEqual(response.status_code, 403)
        self.assertEqual(DeploymentRelease.objects.count(), 0)

    def test_command_approval_can_be_created(self):
        with mock.patch('devops.services.notify_approval') as notify:
            response = self.client.post(reverse('devops:command_approval_create'), {
                'host': self.host.id,
                'command': 'reboot',
                'reason': 'maintenance',
            })

        self.assertEqual(response.status_code, 302)
        approval = ApprovalRequest.objects.get()
        self.assertEqual(approval.request_type, ApprovalRequest.TYPE_COMMAND)
        self.assertEqual(approval.status, ApprovalRequest.STATUS_PENDING)
        notify.assert_called_once_with(approval, '创建')

    def test_admin_can_reject_approval(self):
        approver = User.objects.create(
            user='reject-approver',
            email='reject-approver@example.com',
            password='plain-password',
            confirm_pwd='plain-password',
        )
        DevOpsRole.objects.update_or_create(user=approver, defaults={'role': DevOpsRole.ROLE_ADMIN})
        session = self.client.session
        session['user_id'] = approver.id
        session['user_name'] = approver.user
        session.save()
        approval = ApprovalRequest.objects.create(
            request_type=ApprovalRequest.TYPE_COMMAND,
            title='reject command',
            host=self.host,
            command='reboot',
            requester=self.user.user,
        )

        with mock.patch('devops.views.notify_approval') as notify:
            response = self.client.post(reverse('devops:approval_decide', args=[approval.id]), {
                'action': 'reject',
                'comment': 'not now',
            })

        self.assertEqual(response.status_code, 302)
        approval.refresh_from_db()
        self.assertEqual(approval.status, ApprovalRequest.STATUS_REJECTED)
        self.assertEqual(approval.comment, 'not now')
        notify.assert_called_once_with(approval, '拒绝')

    def test_requester_cannot_approve_own_request(self):
        self.set_role(DevOpsRole.ROLE_ADMIN)
        approval = ApprovalRequest.objects.create(
            request_type=ApprovalRequest.TYPE_COMMAND,
            title='self approve',
            host=self.host,
            command='reboot',
            requester=self.user.user,
        )

        response = self.client.post(reverse('devops:approval_decide', args=[approval.id]), {
            'action': 'approve',
            'comment': 'approved',
        })

        self.assertEqual(response.status_code, 302)
        approval.refresh_from_db()
        self.assertEqual(approval.status, ApprovalRequest.STATUS_PENDING)
        self.assertEqual(approval.comment, '申请人与审批人不能为同一人')
        self.assertIsNone(approval.command_execution)

    def test_admin_approval_executes_command_request(self):
        approver = User.objects.create(
            user='approver',
            email='approver@example.com',
            password='plain-password',
            confirm_pwd='plain-password',
        )
        DevOpsRole.objects.update_or_create(user=approver, defaults={'role': DevOpsRole.ROLE_ADMIN})
        session = self.client.session
        session['user_id'] = approver.id
        session['user_name'] = approver.user
        session.save()
        approval = ApprovalRequest.objects.create(
            request_type=ApprovalRequest.TYPE_COMMAND,
            title='run command',
            host=self.host,
            command='reboot',
            requester=self.user.user,
        )

        response = self.client.post(reverse('devops:approval_decide', args=[approval.id]), {
            'action': 'approve',
            'comment': 'approved',
        })

        self.assertEqual(response.status_code, 302)
        approval.refresh_from_db()
        self.assertIsNotNone(approval.command_execution)
        self.assertIn(approval.status, [ApprovalRequest.STATUS_EXECUTED, ApprovalRequest.STATUS_FAILED])

    def test_force_deploy_approval_creates_approval(self):
        DevOpsSetting.objects.create(force_deploy_approval=True)
        app = DeploymentApp.objects.create(name='force-approval-app', created_by=self.user.user)

        response = self.client.post(reverse('devops:deployments'), {
            'form_type': 'release',
            'submit_mode': 'execute',
            'app': app.id,
            'version': 'v3',
            'description': 'forced approval',
            'deploy_script': 'echo deploy',
            'rollback_script': 'echo rollback',
            'hosts': [self.host.id],
        })

        self.assertEqual(response.status_code, 302)
        release = DeploymentRelease.objects.get()
        approval = ApprovalRequest.objects.get()
        self.assertEqual(release.status, DeploymentRelease.STATUS_PENDING)
        self.assertEqual(approval.request_type, ApprovalRequest.TYPE_DEPLOYMENT)
        self.assertEqual(approval.deployment_release, release)

    def test_deployment_can_be_submitted_for_approval(self):
        app = DeploymentApp.objects.create(name='approval-app', created_by=self.user.user)

        response = self.client.post(reverse('devops:deployments'), {
            'form_type': 'release',
            'submit_mode': 'approval',
            'app': app.id,
            'version': 'v2',
            'description': 'needs approval',
            'deploy_script': 'echo deploy',
            'rollback_script': 'echo rollback',
            'hosts': [self.host.id],
        })

        self.assertEqual(response.status_code, 302)
        release = DeploymentRelease.objects.get()
        approval = ApprovalRequest.objects.get()
        self.assertEqual(release.status, DeploymentRelease.STATUS_PENDING)
        self.assertEqual(approval.deployment_release, release)

    def test_notification_channel_encrypts_secret_fields(self):
        channel = NotificationChannel.objects.create(
            name='ops webhook',
            channel_type=NotificationChannel.TYPE_WEBHOOK,
            webhook_url='https://example.com/hook',
            secret='plain-secret',
            created_by=self.user.user,
        )

        stored = NotificationChannel.objects.get(id=channel.id)

        self.assertNotEqual(stored.webhook_url, 'https://example.com/hook')
        self.assertTrue(stored.webhook_url.startswith('enc:'))
        self.assertEqual(stored.decrypted_webhook_url, 'https://example.com/hook')
        self.assertEqual(stored.decrypted_secret, 'plain-secret')

    def test_send_notification_channel_records_success(self):
        channel = NotificationChannel.objects.create(
            name='generic',
            channel_type=NotificationChannel.TYPE_WEBHOOK,
            webhook_url='https://example.com/hook',
            notify_alert=True,
        )
        response = mock.Mock(status_code=200, text='ok')

        with mock.patch('devops.services.requests.post', return_value=response) as post:
            log = send_notification_channel(channel, NotificationLog.EVENT_ALERT, 'alert title', 'alert content')

        self.assertEqual(log.status, NotificationLog.STATUS_SUCCESS)
        post.assert_called_once()
        payload = post.call_args[1]['json']
        self.assertEqual(payload['event_type'], NotificationLog.EVENT_ALERT)
        self.assertEqual(payload['title'], 'alert title')

    def test_send_notification_channel_deduplicates_recent_same_message(self):
        channel = NotificationChannel.objects.create(
            name='dedupe',
            channel_type=NotificationChannel.TYPE_WEBHOOK,
            webhook_url='https://example.com/hook',
        )
        response = mock.Mock(status_code=200, text='ok')

        with mock.patch('devops.services.requests.post', return_value=response) as post:
            first = send_notification_channel(channel, NotificationLog.EVENT_ALERT, 'same title', 'same content')
            second = send_notification_channel(channel, NotificationLog.EVENT_ALERT, 'same title', 'same content')

        self.assertEqual(first.status, NotificationLog.STATUS_SUCCESS)
        self.assertEqual(second.status, NotificationLog.STATUS_SUCCESS)
        self.assertIn('deduped', second.response)
        post.assert_called_once()

    def test_send_notification_channel_records_failure(self):
        channel = NotificationChannel.objects.create(
            name='generic fail',
            channel_type=NotificationChannel.TYPE_WEBHOOK,
            webhook_url='https://example.com/hook',
        )

        with mock.patch('devops.services.requests.post', side_effect=Exception('network down')):
            log = send_notification_channel(channel, NotificationLog.EVENT_TEST, 'test', 'content')

        self.assertEqual(log.status, NotificationLog.STATUS_FAILED)
        self.assertIn('network down', log.response)

    @mock.patch('devops.services.settings.NOTIFICATION_RETRY_COUNT', 1)
    @mock.patch('devops.services.settings.NOTIFICATION_TIMEOUT_SECONDS', 3)
    def test_send_notification_channel_retries_failure(self):
        channel = NotificationChannel.objects.create(
            name='retry webhook',
            channel_type=NotificationChannel.TYPE_WEBHOOK,
            webhook_url='https://example.com/hook',
        )
        response = mock.Mock(status_code=200, text='ok')

        with mock.patch('devops.services.requests.post', side_effect=[Exception('network down'), response]) as post:
            log = send_notification_channel(channel, NotificationLog.EVENT_TEST, 'retry title', 'retry content')

        self.assertEqual(log.status, NotificationLog.STATUS_SUCCESS)
        self.assertIn('已尝试 2 次', log.response)
        self.assertEqual(post.call_count, 2)
        self.assertEqual(post.call_args[1]['timeout'], 3)

    def test_api_notifications_filters_logs_and_omits_channel_secrets(self):
        alert_channel = NotificationChannel.objects.create(
            name='alert webhook',
            channel_type=NotificationChannel.TYPE_WEBHOOK,
            webhook_url='https://example.com/alert-hook',
            secret='alert-secret',
        )
        deploy_channel = NotificationChannel.objects.create(
            name='deploy webhook',
            channel_type=NotificationChannel.TYPE_WEBHOOK,
            webhook_url='https://example.com/deploy-hook',
            secret='deploy-secret',
        )
        matched = NotificationLog.objects.create(
            channel=alert_channel,
            event_type=NotificationLog.EVENT_ALERT,
            title='matched alert',
            content='content',
            status=NotificationLog.STATUS_FAILED,
            response='failed',
        )
        NotificationLog.objects.create(
            channel=alert_channel,
            event_type=NotificationLog.EVENT_APPROVAL,
            title='wrong event',
            content='content',
            status=NotificationLog.STATUS_FAILED,
            response='failed',
        )
        NotificationLog.objects.create(
            channel=deploy_channel,
            event_type=NotificationLog.EVENT_ALERT,
            title='wrong channel',
            content='content',
            status=NotificationLog.STATUS_SUCCESS,
            response='ok',
        )

        response = self.client.get(reverse('devops:api_notifications'), {
            'channel': alert_channel.id,
            'event_type': NotificationLog.EVENT_ALERT,
            'status': NotificationLog.STATUS_FAILED,
        })

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual([item['id'] for item in payload['logs']], [matched.id])
        self.assertEqual(payload['logs'][0]['channel_id'], alert_channel.id)
        serialized = json.dumps(payload)
        self.assertNotIn('webhook_url', serialized)
        self.assertNotIn('secret', serialized)
        self.assertNotIn('https://example.com/alert-hook', serialized)
        self.assertNotIn('alert-secret', serialized)

    def test_api_notifications_truncates_failure_response_preview(self):
        channel = NotificationChannel.objects.create(
            name='long response webhook',
            channel_type=NotificationChannel.TYPE_WEBHOOK,
            webhook_url='https://example.com/hook',
        )
        NotificationLog.objects.create(
            channel=channel,
            event_type=NotificationLog.EVENT_TEST,
            title='long failure',
            content='content',
            status=NotificationLog.STATUS_FAILED,
            response='x' * 500,
        )

        response = self.client.get(reverse('devops:api_notifications'))

        self.assertEqual(response.status_code, 200)
        preview = response.json()['logs'][0]['response']
        self.assertEqual(len(preview), 303)
        self.assertTrue(preview.endswith('...'))

    def test_api_notifications_rejects_invalid_filters(self):
        response = self.client.get(reverse('devops:api_notifications'), {'event_type': 'unknown'})

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()['code'], 'validation_error')

    def test_notification_page_renders(self):
        response = self.client.get(reverse('devops:notification_channels'))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, '通知渠道')

    def test_admin_can_create_notification_channel(self):
        self.set_role(DevOpsRole.ROLE_ADMIN)

        response = self.client.post(reverse('devops:notification_create'), {
            'name': 'wecom',
            'channel_type': NotificationChannel.TYPE_WECOM,
            'webhook_url': 'https://example.com/wecom',
            'secret': '',
            'notify_alert': 'on',
            'notify_approval': 'on',
            'notify_deployment': 'on',
            'enabled': 'on',
        })

        self.assertEqual(response.status_code, 302)
        channel = NotificationChannel.objects.get(name='wecom')
        self.assertEqual(channel.decrypted_webhook_url, 'https://example.com/wecom')
        log = AuditLog.objects.get(action='创建通知渠道')
        self.assertIn('名称=wecom', log.detail)
        self.assertIn('类型=wecom', log.detail)
        self.assertNotIn('https://example.com/wecom', log.detail)

    def test_notification_channel_rejects_invalid_webhook_url(self):
        self.set_role(DevOpsRole.ROLE_ADMIN)

        response = self.client.post(reverse('devops:notification_create'), {
            'name': 'bad-webhook',
            'channel_type': NotificationChannel.TYPE_WEBHOOK,
            'webhook_url': 'javascript:alert(1)',
            'secret': '',
            'notify_alert': 'on',
            'notify_approval': 'on',
            'notify_deployment': 'on',
            'enabled': 'on',
        })

        self.assertEqual(response.status_code, 302)
        self.assertFalse(NotificationChannel.objects.filter(name='bad-webhook').exists())

    def test_notification_update_keeps_secret_fields_when_blank(self):
        self.set_role(DevOpsRole.ROLE_ADMIN)
        channel = NotificationChannel.objects.create(
            name='keep-secret',
            channel_type=NotificationChannel.TYPE_WEBHOOK,
            webhook_url='https://example.com/original',
            secret='original-secret',
        )

        response = self.client.post(reverse('devops:notification_update', args=[channel.id]), {
            'name': 'keep-secret-updated',
            'channel_type': NotificationChannel.TYPE_WEBHOOK,
            'webhook_url': '',
            'secret': '',
            'notify_alert': 'on',
            'notify_approval': 'on',
            'notify_deployment': 'on',
            'enabled': 'on',
        })

        self.assertEqual(response.status_code, 302)
        channel.refresh_from_db()
        self.assertEqual(channel.name, 'keep-secret-updated')
        self.assertEqual(channel.decrypted_webhook_url, 'https://example.com/original')
        self.assertEqual(channel.decrypted_secret, 'original-secret')
        log = AuditLog.objects.get(action='更新通知渠道')
        self.assertIn('名称=keep-secret-updated', log.detail)
        self.assertNotIn('https://example.com/original', log.detail)
        self.assertNotIn('original-secret', log.detail)
