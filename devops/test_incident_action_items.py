import json
from datetime import timedelta

from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from RemoteLinux.models import NewLinux, User
from .models import DevOpsModulePermission, DevOpsRole, HostGroup, DevOpsHostScope, Incident


class IncidentActionItemApiTests(TestCase):
    def setUp(self):
        self.user = User.objects.create(user='action-owner', email='action@example.com', password='x', confirm_pwd='x')
        self.assignee = User.objects.create(user='action-assignee', email='assignee@example.com', password='x', confirm_pwd='x')
        self.host = NewLinux.objects.create(
            linux_name='action-host', linux_ip='127.0.8.1', linux_hostname='action-host',
            linux_port='22', linux_user='root', linux_passwd='not-used', linux_app='',
        )
        DevOpsRole.objects.create(user=self.user, role=DevOpsRole.ROLE_OPERATOR)
        DevOpsModulePermission.objects.create(
            user=self.user, module=DevOpsModulePermission.MODULE_ALERT, role=DevOpsRole.ROLE_OPERATOR,
        )
        group = HostGroup.objects.create(name='action-items')
        group.hosts.add(self.host)
        scope = DevOpsHostScope.objects.create(user=self.user)
        scope.groups.add(group)
        session = self.client.session
        session.update({'is_login': True, 'user_id': self.user.id, 'user_name': self.user.user})
        session.save()
        self.incident = Incident.objects.create(title='action incident', host=self.host, status=Incident.STATUS_RESOLVED)

    def test_action_item_crud_status_and_overdue(self):
        response = self.client.post(
            reverse('devops:api_incident_action_items', args=[self.incident.id]),
            data=json.dumps({'title': '建立饱和度告警', 'assignee_id': self.assignee.id,
                             'priority': 'high', 'due_at': (timezone.now() - timedelta(hours=1)).isoformat()}),
            content_type='application/json',
        )
        self.assertEqual(response.status_code, 201)
        item = response.json()['action_item']
        self.assertTrue(item['overdue'])
        action_id = item['id']
        updated = self.client.patch(
            reverse('devops:api_incident_action_item_detail', args=[self.incident.id, action_id]),
            data=json.dumps({'description': '告警规则变更并验证'}), content_type='application/json',
        )
        self.assertEqual(updated.status_code, 200)
        completed = self.client.post(
            reverse('devops:api_incident_action_item_status', args=[self.incident.id, action_id]),
            data=json.dumps({'status': 'completed'}), content_type='application/json',
        )
        self.assertEqual(completed.status_code, 200)
        self.assertFalse(completed.json()['action_item']['overdue'])
        self.assertIsNotNone(completed.json()['action_item']['completed_at'])
        listing = self.client.get(reverse('devops:api_incident_action_items', args=[self.incident.id]))
        self.assertEqual(listing.status_code, 200)
        self.assertEqual(len(listing.json()['results']), 1)

    def test_action_item_rejects_unknown_assignee_and_viewer_cannot_mutate(self):
        response = self.client.post(
            reverse('devops:api_incident_action_items', args=[self.incident.id]),
            data=json.dumps({'title': 'invalid', 'assignee_id': 99999}), content_type='application/json',
        )
        self.assertEqual(response.status_code, 400)
        DevOpsRole.objects.filter(user=self.user).update(role=DevOpsRole.ROLE_VIEWER)
        DevOpsModulePermission.objects.filter(user=self.user).update(role=DevOpsRole.ROLE_VIEWER)
        response = self.client.post(
            reverse('devops:api_incident_action_items', args=[self.incident.id]),
            data=json.dumps({'title': 'forbidden'}), content_type='application/json',
        )
        self.assertEqual(response.status_code, 403)
