from datetime import timedelta
from io import StringIO
from unittest import mock

from django.core.management import call_command
from django.test import TestCase, override_settings
from django.utils import timezone

from devops.models import ScheduledTaskRun
from devops.scheduler import ScheduledTask, run_due_scheduled_tasks


class DurableSchedulerTests(TestCase):

    @override_settings(DEVOPS_SCHEDULER_AGENT_HEALTH_INTERVAL_SECONDS=60)
    def test_registry_includes_fixed_agent_health_task(self):
        from devops.scheduler import scheduled_task_registry

        tasks = {task.name: task for task in scheduled_task_registry()}

        self.assertIn('agent_health', tasks)
        self.assertEqual(tasks['agent_health'].interval_seconds, 60)

    @override_settings(DEVOPS_SCHEDULER_OPERATOR_SCAN_INTERVAL_SECONDS=123)
    def test_registry_includes_operator_scan_task(self):
        from devops.scheduler import scheduled_task_registry
        tasks = {task.name: task for task in scheduled_task_registry()}
        self.assertEqual(tasks['operator_scan'].interval_seconds, 123)
    def test_due_task_is_leased_once_and_records_safe_success_summary(self):
        callback = mock.Mock(return_value={'processed': 3, 'ignored': 'must not persist'})
        task = ScheduledTask('test-task', 60, callback)

        first = run_due_scheduled_tasks(task_specs=(task,))
        second = run_due_scheduled_tasks(task_specs=(task,))

        self.assertEqual(first['started'], ['test-task'])
        self.assertEqual(second['started'], [])
        callback.assert_called_once_with()
        state = ScheduledTaskRun.objects.get(task_name='test-task')
        self.assertEqual(state.status, ScheduledTaskRun.STATUS_SUCCESS)
        self.assertEqual(state.last_summary, 'completed: processed=3')
        self.assertNotIn('must not persist', state.last_summary)
        self.assertIsNotNone(state.next_run_at)

    def test_leased_task_is_not_invoked_by_another_scheduler(self):
        callback = mock.Mock()
        now = timezone.now()
        ScheduledTaskRun.objects.create(
            task_name='leased-task',
            status=ScheduledTaskRun.STATUS_RUNNING,
            next_run_at=now - timedelta(seconds=1),
            lease_expires_at=now + timedelta(seconds=60),
        )

        result = run_due_scheduled_tasks(task_specs=(ScheduledTask('leased-task', 60, callback),))

        self.assertEqual(result['started'], [])
        self.assertEqual(result['leased'], ['leased-task'])
        callback.assert_not_called()

    def test_callback_failure_records_exception_type_without_payload(self):
        def fail():
            raise RuntimeError('token=never-store-this alert body')

        run_due_scheduled_tasks(task_specs=(ScheduledTask('failed-task', 60, fail),))

        state = ScheduledTaskRun.objects.get(task_name='failed-task')
        self.assertEqual(state.status, ScheduledTaskRun.STATUS_FAILED)
        self.assertEqual(state.last_summary, 'failed: RuntimeError')
        self.assertNotIn('never-store-this', state.last_summary)

    @mock.patch('devops.management.commands.devops_scheduler.run_due_scheduled_tasks')
    def test_once_command_runs_one_scheduler_cycle(self, run_due):
        run_due.return_value = {'started': ['monitor'], 'leased': [], 'failed': []}
        output = StringIO()

        call_command('devops_scheduler', '--once', stdout=output)

        run_due.assert_called_once_with()
        self.assertIn('Started 1 scheduled task(s).', output.getvalue())
