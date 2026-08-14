from django.test import SimpleTestCase

from devops import delivery, execution, governance
from devops.ci_orchestration import parse_ci_delivery
from devops.release_impact import build_release_impact_preview
from devops.services import execute_command_record, validate_remote_path


class DevopsPackageBoundaryTests(SimpleTestCase):
    def test_execution_exports_reuse_existing_implementations(self):
        self.assertIs(execution.execute_command_record, execute_command_record)
        self.assertIs(execution.validate_remote_path, validate_remote_path)
        self.assertIn('process_next_background_job', execution.__all__)

    def test_delivery_exports_reuse_existing_implementations(self):
        self.assertIs(delivery.parse_ci_delivery, parse_ci_delivery)
        self.assertIs(delivery.build_release_impact_preview, build_release_impact_preview)
        self.assertIn('record_gitops_drift', delivery.__all__)

    def test_governance_exposes_stable_public_names(self):
        self.assertIn('build_incident_command_center', governance.__all__)
        self.assertIn('build_slo_burn_summary', governance.__all__)
        self.assertIn('platform_reliability_summary', governance.__all__)
