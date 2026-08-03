from unittest import mock

from django.test import TestCase

from RemoteLinux.models import NewLinux
from RemoteLinux.models import User
from .models import (
    AuditLog,
    DevOpsModulePermission,
    DevOpsRole,
    GitOpsCollectionRun,
    InfrastructureBlueprint,
    IntegrationConnector,
    K8sCluster,
    VulnerabilityFinding,
    VulnerabilityImportRun,
)


class ControlledIntegrationTests(TestCase):
    def setUp(self):
        self.host = NewLinux.objects.create(
            linux_name='integration-host', linux_ip='127.0.0.9', linux_hostname='integration-host',
            linux_port='22', linux_user='root', linux_passwd='not-used', linux_app='',
        )
        self.cluster = K8sCluster.objects.create(
            name='integration-cluster', api_server='https://cluster.example.test', kubeconfig='apiVersion: v1',
        )

    def test_connector_encrypts_config_and_exposes_no_secret_fields(self):
        connector = IntegrationConnector.objects.create(
            name='gitops-readonly', connector_type=IntegrationConnector.TYPE_GITOPS,
            config={'endpoint': 'https://internal.example', 'token': 'not-for-output'},
        )

        self.assertNotIn('not-for-output', connector.config_encrypted)
        self.assertEqual(connector.get_config()['endpoint'], 'https://internal.example')
        self.assertEqual(connector.safe_summary(), {
            'id': connector.id,
            'name': 'gitops-readonly',
            'connector_type': 'gitops',
            'enabled': False,
            'read_only': True,
            'status': 'blocked',
        })
        self.assertNotIn('endpoint', str(connector.safe_summary()))

    def test_disabled_connector_is_blocked_without_calling_adapter(self):
        from .integrations import collect_gitops_connector

        connector = IntegrationConnector.objects.create(
            name='disabled', connector_type=IntegrationConnector.TYPE_GITOPS,
        )
        adapter = mock.Mock()

        run = collect_gitops_connector(connector, adapter=adapter)

        self.assertEqual(run.status, 'blocked')
        self.assertEqual(run.outcome_category, 'connector_disabled')
        adapter.collect.assert_not_called()

    def test_enabled_connector_without_adapter_is_blocked_without_network_client(self):
        from .integrations import collect_gitops_connector

        connector = IntegrationConnector.objects.create(
            name='no-adapter', connector_type=IntegrationConnector.TYPE_GITOPS, enabled=True,
        )

        run = collect_gitops_connector(connector)

        self.assertEqual(run.status, GitOpsCollectionRun.STATUS_BLOCKED)
        self.assertEqual(run.outcome_category, 'provider_unconfigured')

    def test_explicit_disabled_adapter_is_blocked_without_collection(self):
        from .integrations import DisabledGitOpsAdapter, collect_gitops_connector

        connector = IntegrationConnector.objects.create(
            name='disabled-adapter', connector_type=IntegrationConnector.TYPE_GITOPS, enabled=True,
        )
        adapter = DisabledGitOpsAdapter()
        adapter.collect = mock.Mock(wraps=adapter.collect)

        run = collect_gitops_connector(connector, adapter=adapter)

        self.assertEqual(run.status, GitOpsCollectionRun.STATUS_BLOCKED)
        self.assertEqual(run.outcome_category, 'provider_unconfigured')
        adapter.collect.assert_not_called()

    def test_gitops_collection_normalizes_only_allowed_local_records(self):
        from .integrations import collect_gitops_connector

        connector = IntegrationConnector.objects.create(
            name='enabled-gitops', connector_type=IntegrationConnector.TYPE_GITOPS, enabled=True,
        )
        adapter = mock.Mock()
        adapter.collect.return_value = [{
            'cluster': self.cluster,
            'namespace': 'operations',
            'resource_name': 'api',
            'resource_kind': 'Deployment',
            'desired_manifest': {'replicas': 2},
            'observed_manifest': {'replicas': 3},
        }]

        run = collect_gitops_connector(connector, adapter=adapter)

        self.assertEqual(run.status, 'success')
        self.assertEqual(run.finding_count, 1)

    def test_gitops_normalizer_rejects_unknown_cluster_extra_fields_and_invalid_types(self):
        from .integrations import normalize_gitops_finding

        unknown_cluster = K8sCluster(name='unknown', api_server='https://unknown.example.test', kubeconfig='apiVersion: v1')
        valid = {
            'cluster': self.cluster,
            'namespace': 'operations',
            'resource_name': 'api',
            'resource_kind': 'Deployment',
            'desired_manifest': {'replicas': 2},
            'observed_manifest': {'replicas': 3},
        }
        cases = (
            dict(valid, cluster=unknown_cluster),
            dict(valid, raw_document='not allowed'),
            dict(valid, namespace=123),
            dict(valid, desired_manifest=['not', 'an', 'object']),
        )

        for row in cases:
            with self.subTest(row=row):
                with self.assertRaises(ValueError):
                    normalize_gitops_finding(row)

    def test_vulnerability_collection_rejects_unknown_host_and_raw_output(self):
        from .integrations import normalize_vulnerability_finding

        unknown_host = NewLinux(
            linux_name='unknown', linux_ip='127.0.0.8', linux_hostname='unknown',
            linux_port='22', linux_user='root', linux_passwd='not-used', linux_app='',
        )
        with self.assertRaises(ValueError):
            normalize_vulnerability_finding({
                'host': unknown_host,
                'package_name': 'openssl',
                'advisory_id': 'CVE-2026-0001',
                'severity': 'high',
            })
        with self.assertRaises(ValueError):
            normalize_vulnerability_finding({
                'host': self.host,
                'package_name': 'openssl',
                'advisory_id': 'CVE-2026-0001',
                'severity': 'high',
                'raw_output': 'not allowed',
            })

    def test_vulnerability_collection_records_only_normalized_finding(self):
        from .integrations import collect_vulnerability_connector

        connector = IntegrationConnector.objects.create(
            name='enabled-vulnerability', connector_type=IntegrationConnector.TYPE_VULNERABILITY, enabled=True,
        )
        adapter = mock.Mock()
        adapter.collect.return_value = [{
            'host': self.host,
            'package_name': 'openssl',
            'advisory_id': 'CVE-2026-0001',
            'severity': 'high',
        }]

        run = collect_vulnerability_connector(connector, adapter=adapter)

        self.assertEqual(run.status, 'success')
        self.assertEqual(run.finding_count, 1)
        self.assertEqual(VulnerabilityFinding.objects.count(), 1)

    def test_vulnerability_type_errors_are_invalid_input_run_outcomes(self):
        from .integrations import collect_vulnerability_connector

        connector = IntegrationConnector.objects.create(
            name='invalid-vulnerability', connector_type=IntegrationConnector.TYPE_VULNERABILITY, enabled=True,
        )
        adapter = mock.Mock()
        adapter.collect.return_value = [{
            'host': self.host,
            'package_name': ['openssl'],
            'advisory_id': 'CVE-2026-0001',
            'severity': 'high',
        }]

        run = collect_vulnerability_connector(connector, adapter=adapter)

        self.assertEqual(run.status, VulnerabilityImportRun.STATUS_FAILED)
        self.assertEqual(run.outcome_category, 'invalid_input')

    def test_blueprint_definition_is_digest_only_and_planning_never_applies(self):
        from .integrations import request_infrastructure_plan

        blueprint = InfrastructureBlueprint.objects.create(
            name='test-blueprint', provider_type='terraform', enabled=True,
            definition={'resources': [{'kind': 'network'}]}, summary='one planned resource',
        )

        plan = request_infrastructure_plan(blueprint, requested_by='integration-admin')

        self.assertEqual(len(blueprint.definition_digest), 64)
        self.assertFalse(hasattr(blueprint, 'definition'))
        self.assertEqual(plan.status, 'pending')
        self.assertEqual(plan.definition_digest, blueprint.definition_digest)


class ControlledIntegrationApiTests(TestCase):
    def setUp(self):
        self.user = User.objects.create(
            user='integration-admin', email='integration-admin@example.test',
            password='not-used', confirm_pwd='not-used',
        )
        self.connector = IntegrationConnector.objects.create(
            name='gitops-api-connector', connector_type=IntegrationConnector.TYPE_GITOPS,
            enabled=True, config={'endpoint': 'https://provider.example.test', 'token': 'not-for-output'},
        )
        self.blueprint = InfrastructureBlueprint.objects.create(
            name='api-blueprint', provider_type='terraform', enabled=True,
            definition={'resources': [{'kind': 'network'}]}, summary='one safe planned resource',
        )

    def login_as_security_viewer(self):
        DevOpsRole.objects.create(user=self.user, role=DevOpsRole.ROLE_VIEWER)
        DevOpsModulePermission.objects.create(
            user=self.user, module=DevOpsModulePermission.MODULE_SECURITY,
            role=DevOpsRole.ROLE_VIEWER,
        )
        self._login()

    def grant_security_admin(self):
        DevOpsRole.objects.update_or_create(
            user=self.user, defaults={'role': DevOpsRole.ROLE_ADMIN},
        )
        DevOpsModulePermission.objects.update_or_create(
            user=self.user, module=DevOpsModulePermission.MODULE_SECURITY,
            defaults={'role': DevOpsRole.ROLE_ADMIN},
        )
        self._login()

    def _login(self):
        session = self.client.session
        session['is_login'] = True
        session['user_id'] = self.user.id
        session['user_name'] = self.user.user
        session.save()

    def test_readiness_api_requires_security_admin_and_hides_sensitive_fields(self):
        response = self.client.get('/devops/api/integration-readiness/')
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json()['code'], 'unauthorized')

        self.login_as_security_viewer()
        response = self.client.get('/devops/api/integration-readiness/')
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.json()['code'], 'forbidden')

        self.grant_security_admin()
        response = self.client.get('/devops/api/integration-readiness/')
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertTrue(payload['ok'])
        self.assertEqual(payload['connectors'][0]['name'], self.connector.name)
        self.assertNotIn('config', str(payload))
        self.assertNotIn('endpoint', str(payload))
        self.assertNotIn('not-for-output', str(payload))

    def test_connector_collection_is_bounded_audited_and_never_accepts_provider_input(self):
        self.grant_security_admin()
        forbidden = self.client.post(
            '/devops/api/integration-connectors/%s/collect/' % self.connector.id,
            data='{"url":"https://attacker.example.test","manifest":{},"command":"apply"}',
            content_type='application/json',
        )
        self.assertEqual(forbidden.status_code, 400)
        self.assertEqual(forbidden.json()['code'], 'validation_error')
        self.assertEqual(GitOpsCollectionRun.objects.count(), 0)

        response = self.client.post(
            '/devops/api/integration-connectors/%s/collect/' % self.connector.id,
            data='{}', content_type='application/json',
        )
        self.assertEqual(response.status_code, 202)
        self.assertEqual(response.json()['run']['status'], 'blocked')
        self.assertEqual(response.json()['run']['outcome_category'], 'provider_unconfigured')
        self.assertEqual(AuditLog.objects.filter(
            action='触发受控集成采集', target_type='IntegrationConnector', target_id=str(self.connector.id),
        ).count(), 1)

    def test_connector_and_blueprint_lists_require_admin_and_return_safe_summaries(self):
        self.login_as_security_viewer()
        self.assertEqual(self.client.get('/devops/api/integration-connectors/').status_code, 403)
        self.assertEqual(self.client.get('/devops/api/infrastructure-blueprints/').status_code, 403)

        self.grant_security_admin()
        connectors = self.client.get('/devops/api/integration-connectors/').json()['results']
        blueprints = self.client.get('/devops/api/infrastructure-blueprints/').json()['results']
        self.assertEqual(set(connectors[0]), {
            'id', 'name', 'connector_type', 'enabled', 'read_only', 'status',
        })
        self.assertEqual(set(blueprints[0]), {
            'id', 'name', 'provider_type', 'enabled', 'read_only', 'definition_digest', 'summary',
        })
        self.assertNotIn('endpoint', str(connectors))
        self.assertNotIn('not-for-output', str(connectors))
        self.assertNotIn('resources', str(blueprints))

    def test_blueprint_plan_is_pending_audited_and_never_accepts_apply_input(self):
        self.grant_security_admin()
        forbidden = self.client.post(
            '/devops/api/infrastructure-blueprints/%s/plans/' % self.blueprint.id,
            data='{"provider":"terraform","apply":true,"command":"apply"}',
            content_type='application/json',
        )
        self.assertEqual(forbidden.status_code, 400)
        self.assertEqual(forbidden.json()['code'], 'validation_error')

        response = self.client.post(
            '/devops/api/infrastructure-blueprints/%s/plans/' % self.blueprint.id,
            data='{}', content_type='application/json',
        )
        self.assertEqual(response.status_code, 202)
        self.assertEqual(response.json()['plan']['status'], 'pending')
        self.assertEqual(response.json()['plan']['definition_digest'], self.blueprint.definition_digest)
        self.assertNotIn('provider', str(response.json()))
        self.assertEqual(AuditLog.objects.filter(
            action='创建受控基础设施计划', target_type='InfrastructureBlueprint', target_id=str(self.blueprint.id),
        ).count(), 1)
