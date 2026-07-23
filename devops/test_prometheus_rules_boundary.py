from unittest import mock

from django.test import SimpleTestCase

from . import prometheus_rules
from . import services


class PrometheusRuleServiceBoundaryTests(SimpleTestCase):
    def test_service_wrapper_uses_focused_module_and_legacy_factory_hook(self):
        observed = {}

        class ApiClient(object):
            def close(self):
                observed['closed'] = True

        class CustomObjectsApi(object):
            def list_cluster_custom_object(self, **kwargs):
                observed['kwargs'] = kwargs
                return {'items': []}

        factory = mock.Mock(return_value=(CustomObjectsApi(), ApiClient(), ''))
        with mock.patch.object(services, '_prometheus_rule_custom_objects_api', factory):
            result = services.list_prometheus_rules(object())

        self.assertTrue(result['ok'])
        self.assertEqual(result['rules'], [])
        factory.assert_called_once()
        self.assertEqual(observed['kwargs']['plural'], prometheus_rules.PROMETHEUS_RULE_PLURAL)
        self.assertTrue(observed['closed'])
