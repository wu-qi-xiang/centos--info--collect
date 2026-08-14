from django.test import SimpleTestCase

from aiops import analysis, investigation
from aiops.alert_groups import build_alert_groups
from aiops.evidence_pack import build_evidence_pack
from aiops.investigations import build_investigation_result
from aiops.reliability_score import build_service_reliability


class AiopsPackageBoundaryTests(SimpleTestCase):
    def test_analysis_exports_reuse_existing_implementations(self):
        self.assertIs(analysis.build_alert_groups, build_alert_groups)
        self.assertIs(analysis.build_service_reliability, build_service_reliability)
        self.assertIn('build_service_impacts', analysis.__all__)
        self.assertIn('build_signal_freshness', analysis.__all__)

    def test_investigation_exports_reuse_existing_implementations(self):
        self.assertIs(investigation.build_evidence_pack, build_evidence_pack)
        self.assertIs(investigation.build_investigation_result, build_investigation_result)
        self.assertIn('analyze_k8s_detail', investigation.__all__)
        self.assertIn('build_operator_scan', investigation.__all__)
