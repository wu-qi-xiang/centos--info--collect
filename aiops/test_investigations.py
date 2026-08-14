from datetime import timedelta

from django.core.exceptions import ValidationError
from django.test import TestCase
from django.utils import timezone

from RemoteLinux.models import NewLinux, User
from devops.models import (
	AlertEvent, CIDelivery, DeploymentApp, DeploymentHealthEvaluation, DeploymentRelease,
	Incident, MetricSample, ServiceCatalog, ServiceDependency, ServiceSlo,
	DevOpsRole, DevOpsModulePermission,
)
from unittest.mock import patch
import json

from .models import AiopsInvestigation
from .investigations import build_investigation_result


class AiopsInvestigationModelTests(TestCase):
	def setUp(self):
		self.user = User.objects.create(
			user='investigator', email='investigator@example.com', password='pwd', confirm_pwd='pwd',
		)
		self.host = NewLinux.objects.create(
			linux_name='investigation-host', linux_ip='192.0.2.10', linux_port='22', linux_user='ops',
		)
		self.service = ServiceCatalog.objects.create(name='checkout-api')

	def test_status_risk_and_window_contracts(self):
		investigation = AiopsInvestigation.objects.create(
			created_by=self.user.user,
			title='Checkout incident investigation',
			window_start=timezone.now() - timedelta(hours=24),
			window_end=timezone.now(),
		)

		self.assertEqual(investigation.status, AiopsInvestigation.STATUS_OPEN)
		self.assertEqual(investigation.window_key, '24h')
		self.assertEqual(investigation.risk, AiopsInvestigation.RISK_UNKNOWN)
		self.assertEqual(investigation.confidence, 0)
		self.assertEqual(investigation._meta.db_table, 'aiops_investigation')
		self.assertEqual({value for value, _ in AiopsInvestigation.STATUS_CHOICES}, {
			'open', 'analyzing', 'completed', 'partial', 'failed',
		})

	def test_host_and_service_relations_are_supported(self):
		investigation = AiopsInvestigation.objects.create(
			title='Scoped investigation',
			window_start=timezone.now() - timedelta(hours=1),
			window_end=timezone.now(),
			risk=AiopsInvestigation.RISK_HIGH,
			confidence=80,
		)
		investigation.hosts.add(self.host)
		investigation.services.add(self.service)

		self.assertEqual(list(investigation.hosts.all()), [self.host])
		self.assertEqual(list(investigation.services.all()), [self.service])

	def test_confidence_is_bounded(self):
		investigation = AiopsInvestigation(
			title='Invalid confidence',
			window_start=timezone.now() - timedelta(hours=1),
			window_end=timezone.now(),
			confidence=101,
		)
		with self.assertRaises(ValidationError):
			investigation.full_clean()

	def test_model_has_no_raw_evidence_fields(self):
		field_names = {field.name for field in AiopsInvestigation._meta.get_fields()}
		self.assertNotIn('raw_payload', field_names)
		self.assertNotIn('raw_evidence', field_names)
		self.assertNotIn('llm_response', field_names)


class InvestigationAnalysisTests(TestCase):
	def setUp(self):
		self.host = NewLinux.objects.create(
			linux_name='analysis-host', linux_ip='192.0.2.20', linux_port='22', linux_user='ops',
		)
		self.hidden = NewLinux.objects.create(
			linux_name='hidden-host', linux_ip='192.0.2.21', linux_port='22', linux_user='ops',
		)
		self.service = ServiceCatalog.objects.create(name='analysis-api')
		self.investigation = AiopsInvestigation.objects.create(
			title='bounded analysis', window_key='24h',
			window_start=timezone.now() - timedelta(hours=2), window_end=timezone.now() + timedelta(minutes=1),
		)
		self.investigation.hosts.add(self.host, self.hidden)
		self.investigation.services.add(self.service)

	def test_scope_sensitive_fields_and_root_cause(self):
		alert = AlertEvent.objects.create(host=self.host, level=AlertEvent.LEVEL_CRITICAL,
			metric='cpu', message='private raw alert text')
		result = build_investigation_result(self.investigation, [self.host], [self.service])
		self.assertEqual(result['scope']['host_ids'], [self.host.id])
		self.assertTrue(any(item['kind'] == 'alert' for item in result['timeline']))
		serialized = repr(result)
		self.assertNotIn('private raw alert text', serialized)
		self.assertNotIn('hidden-host', serialized)
		self.assertEqual(result, build_investigation_result(self.investigation, [self.host], [self.service]))

	def test_partial_source_failure_is_safe(self):
		with patch('aiops.investigations._collect_alerts', side_effect=RuntimeError('db')):
			result = build_investigation_result(self.investigation, [self.host], [self.service])
		self.assertTrue(result['partial'])
		self.assertEqual(result['errors'], [{'source': 'alerts', 'code': 'source_unavailable'}])

	def test_all_sources_are_safe_bounded_and_root_cause_keys_are_allowlisted(self):
		now = timezone.now()
		MetricSample.objects.create(host=self.host, metric=MetricSample.METRIC_CPU, value=95, collected_at=now)
		Incident.objects.create(host=self.host, title='private incident title', status=Incident.STATUS_OPEN,
			severity=Incident.SEVERITY_HIGH)
		app = DeploymentApp.objects.create(name='analysis-app')
		release = DeploymentRelease.objects.create(app=app, version='v1', deploy_script='secret command',
			status=DeploymentRelease.STATUS_FAILED)
		release.hosts.add(self.host)
		CIDelivery.objects.create(provider=CIDelivery.PROVIDER_JENKINS, repository='repo', delivery_id='d1',
			fingerprint='f' * 64, status='failed', summary='private ci summary', release=release)
		DeploymentHealthEvaluation.objects.create(release=release, batch_identity='host_ids=%s' % self.host.id,
			status=DeploymentHealthEvaluation.STATUS_UNHEALTHY, score=10, summary='private health summary', evaluated_at=now)
		ServiceSlo.objects.create(service=self.service, metric_kind=ServiceSlo.KIND_AVAILABILITY, target=99,
			last_state=ServiceSlo.STATE_EXHAUSTED, last_evaluated_at=now)
		upstream = ServiceCatalog.objects.create(name='analysis-upstream')
		upstream.hosts.add(self.host)
		ServiceDependency.objects.create(service=self.service, upstream_service=upstream)
		self.investigation.services.add(upstream)
		result = build_investigation_result(self.investigation, [self.host], [self.service, upstream], now=now)
		self.assertTrue({'metric', 'incident', 'release', 'ci_delivery', 'deployment_health', 'slo', 'dependency'} <=
			{item['kind'] for item in result['timeline']})
		self.assertLessEqual(len(result['timeline']), 64)
		self.assertIn('recent_release', {item['key'] for item in result['root_causes']})
		self.assertIn('exhausted_slo', {item['key'] for item in result['root_causes']})
		self.assertIn('upstream_dependency', {item['key'] for item in result['root_causes']})
		self.assertTrue(all(set(item) <= {'key', 'confidence', 'summary', 'evidence_refs', 'next_action'}
			for item in result['root_causes']))
		self.assertNotIn('private ci summary', repr(result))
		self.assertNotIn('private health summary', repr(result))


class InvestigationApiTests(TestCase):
	def setUp(self):
		self.user = User.objects.create(user='api-investigator', email='api@example.com', password='pwd', confirm_pwd='pwd')
		self.host = NewLinux.objects.create(linux_name='api-host', linux_ip='192.0.2.30', linux_port='22', linux_user='ops')
		self.service = ServiceCatalog.objects.create(name='api-service')
		DevOpsRole.objects.create(user=self.user, role=DevOpsRole.ROLE_ADMIN)
		for module in (DevOpsModulePermission.MODULE_ALERT, DevOpsModulePermission.MODULE_METRIC,
					   DevOpsModulePermission.MODULE_DEPLOYMENT, DevOpsModulePermission.MODULE_SERVICE):
			DevOpsModulePermission.objects.create(user=self.user, module=module, role=DevOpsRole.ROLE_VIEWER)
		session = self.client.session
		session.update({'is_login': True, 'user_id': self.user.id, 'user_name': self.user.user})
		session.save()

	def test_create_list_and_detail_are_safe_and_scoped(self):
		response = self.client.post('/aiops/api/investigations/', data=json.dumps({
			'title': 'API investigation', 'window_key': '24h', 'host_ids': [self.host.id],
			'service_ids': [self.service.id],
			'window_start': (timezone.now() - timedelta(hours=1)).isoformat(),
			'window_end': timezone.now().isoformat(),
		}), content_type='application/json')
		self.assertEqual(response.status_code, 201)
		payload = response.json()['investigation']
		self.assertNotIn('created_by', repr(payload))
		self.assertIn('timeline', payload)
		listing = self.client.get('/aiops/api/investigations/')
		self.assertEqual(listing.status_code, 200)
		self.assertEqual(len(listing.json()['results']), 1)
		detail = self.client.get('/aiops/api/investigations/%s/' % payload['id'])
		self.assertEqual(detail.status_code, 200)
		self.assertIn('root_causes', detail.json()['investigation'])

	def test_auth_permission_and_window_validation(self):
		session = self.client.session
		session.clear()
		session.save()
		self.assertEqual(self.client.get('/aiops/api/investigations/').status_code, 401)
		session = self.client.session
		session.update({'is_login': True, 'user_id': self.user.id})
		session.save()
		DevOpsModulePermission.objects.filter(user=self.user).update(role=DevOpsModulePermission.ROLE_NONE)
		self.assertEqual(self.client.get('/aiops/api/investigations/').status_code, 403)

	def test_hidden_host_is_not_found(self):
		hidden = NewLinux.objects.create(linux_name='hidden-api-host', linux_ip='192.0.2.31', linux_port='22', linux_user='ops')
		with patch('aiops.views.visible_hosts_for_request', return_value=NewLinux.objects.filter(id=self.host.id)):
			response = self.client.post('/aiops/api/investigations/', data=json.dumps({
				'title': 'hidden', 'host_ids': [hidden.id], 'window_key': '24h',
				'window_start': (timezone.now() - timedelta(hours=1)).isoformat(),
				'window_end': timezone.now().isoformat(),
			}), content_type='application/json')
		self.assertEqual(response.status_code, 404)

	def test_detail_is_not_limited_by_list_page(self):
		first = AiopsInvestigation.objects.create(
			title='old investigation', window_key='1h',
			window_start=timezone.now() - timedelta(minutes=50), window_end=timezone.now(),
		)
		first.hosts.add(self.host)
		for index in range(201):
			item = AiopsInvestigation.objects.create(
				title='investigation %s' % index, window_key='1h',
				window_start=timezone.now() - timedelta(minutes=50), window_end=timezone.now(),
			)
			item.hosts.add(self.host)
		response = self.client.get('/aiops/api/investigations/%s/' % first.id)
		self.assertEqual(response.status_code, 200)

	def test_future_window_end_and_hidden_service_are_rejected(self):
		future = timezone.now() + timedelta(hours=1)
		response = self.client.post('/aiops/api/investigations/', data=json.dumps({
			'title': 'future', 'host_ids': [self.host.id], 'window_key': '1h',
			'window_start': timezone.now().isoformat(), 'window_end': future.isoformat(),
		}), content_type='application/json')
		self.assertEqual(response.status_code, 400)
		hidden_service = ServiceCatalog.objects.create(name='hidden-service')
		with patch('aiops.views.visible_catalog_services', return_value=ServiceCatalog.objects.filter(id=self.service.id)):
			response = self.client.post('/aiops/api/investigations/', data=json.dumps({
				'title': 'hidden service', 'host_ids': [self.host.id], 'service_ids': [hidden_service.id],
				'window_key': '1h', 'window_start': (timezone.now() - timedelta(minutes=30)).isoformat(),
				'window_end': timezone.now().isoformat(),
			}), content_type='application/json')
		self.assertEqual(response.status_code, 404)
