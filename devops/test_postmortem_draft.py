from django.test import TestCase

from RemoteLinux.models import NewLinux
from devops.models import Incident, IncidentTimeline


class IncidentPostmortemDraftTests(TestCase):
    def test_builds_safe_draft_for_resolved_incident(self):
        from .postmortem_draft import build_incident_postmortem_draft

        host = NewLinux.objects.create(
            linux_name='postmortem-host', linux_ip='127.0.0.293', linux_hostname='postmortem-host',
        )
        incident = Incident.objects.create(
            host=host, title='private incident', description='private description',
            severity=Incident.SEVERITY_HIGH, status=Incident.STATUS_RESOLVED,
            root_cause='private cause', resolution='private resolution', follow_up='private followup',
        )
        IncidentTimeline.objects.create(incident=incident, note='private timeline')

        draft = build_incident_postmortem_draft(incident)

        self.assertEqual(draft['incident'], {
            'id': incident.id, 'severity': Incident.SEVERITY_HIGH, 'status': Incident.STATUS_RESOLVED,
        })
        self.assertEqual(draft['evidence_counts']['timeline_entries'], 1)
        self.assertEqual(draft['draft']['impact'], '请根据服务影响与事件处置记录确认实际影响范围')
        self.assertNotIn('private', repr(draft))

    def test_rejects_unresolved_incident(self):
        from .postmortem_draft import build_incident_postmortem_draft

        incident = Incident.objects.create(title='open', status=Incident.STATUS_OPEN)
        with self.assertRaises(ValueError):
            build_incident_postmortem_draft(incident)
