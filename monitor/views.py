import json

try:
	import yaml
except ImportError:
	yaml = None

from django.shortcuts import get_object_or_404, render, redirect
from django.http import HttpResponseNotAllowed, JsonResponse
from django.middleware.csrf import get_token
from django.urls import reverse
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
# Create your views here.
from .models import AlertmanagerConfig, AlertNotificationConfig, Monitor, PrometheusConfig
from .forms import AlertmanagerConfigForm, AlertNotificationForm, MonitorForm, PrometheusConfigForm
from .services import (
	PROMETHEUS_RULES_FAILURE_MESSAGE,
	PROMETHEUS_RULES_FORMAT_MESSAGE,
	PROMETHEUS_DASHBOARD_QUERIES,
	PROMETHEUS_METADATA_FAILURE_MESSAGE,
	PROMETHEUS_METADATA_FORMAT_MESSAGE,
	PROMETHEUS_TARGETS_FAILURE_MESSAGE,
	PROMETHEUS_TARGETS_FORMAT_MESSAGE,
	empty_prometheus_table,
	normalize_prometheus_rules,
	normalize_alertmanager_alerts,
	normalize_prometheus_result,
	normalize_prometheus_targets,
	query_prometheus,
	query_prometheus_dashboard,
	query_prometheus_metadata,
	query_prometheus_rules,
	query_prometheus_targets,
	query_alertmanager_alerts,
	push_alertmanager_firing_alerts,
	send_alert_notification,
	test_alertmanager_connection,
	test_prometheus_connection,
)
from devops.forms import PrometheusRuleYamlForm, normalize_prometheus_rule_identity
from devops.models import AlertEvent, DevOpsModulePermission, DevOpsRole, IntegrationHealthEvent, K8sCluster
from devops.services import (
	audit,
	integration_health_summary,
	has_role,
	list_prometheus_rules,
	record_integration_health_event,
	summarize_integration_health,
)
from devops.config_governance import create_prometheus_rule_draft
from PyLinux.security import require_monitor_operator, security_context
from PyLinux.vue import form_errors, model_dict, render_vue_page
from userprofile.decorators import session_login_required


PROMETHEUS_SELECTION_ERROR = '选择的 Prometheus 对接不可用'
ALERTMANAGER_SELECTION_ERROR = '选择的 Alertmanager 对接不可用'
PROMETHEUS_RULE_SAFE_MESSAGES = {
	'conflict': '规则已存在或被其他操作更新，请刷新后重试。',
	'forbidden': '当前集群权限不足，无法操作 PrometheusRule。',
	'crd_not_found': '集群未安装 PrometheusRule CRD。',
	'timeout': '连接 Kubernetes 集群超时，请稍后重试。',
	'offline': '无法连接 Kubernetes 集群，请确认集群状态后重试。',
	'invalid_yaml': '规则 YAML 格式或资源身份无效。',
	'invalid_identity': '规则 YAML 格式或资源身份无效。',
	'validation_error': '规则 YAML 格式或资源身份无效。',
	'dependency_missing': '缺少必要依赖，无法操作 PrometheusRule。',
}


def _available_prometheus_configs():
	return [
		config
		for config in PrometheusConfig.objects.filter(enabled=True).order_by('id')
		if (config.prometheus_url or '').strip()
	]


def _available_alertmanager_configs():
	return [
		config
		for config in AlertmanagerConfig.objects.filter(enabled=True).order_by('id')
		if (config.alertmanager_url or '').strip()
	]


def _prometheus_config():
	configs = _available_prometheus_configs()
	return configs[0] if configs else None


def _resolve_prometheus_config(raw_id, configs=None):
	configs = list(configs if configs is not None else _available_prometheus_configs())
	if raw_id is None or not str(raw_id).strip():
		return (configs[0] if configs else None), ''
	try:
		config_id = int(str(raw_id).strip())
	except (TypeError, ValueError):
		return None, PROMETHEUS_SELECTION_ERROR
	for config in configs:
		if config.id == config_id:
			return config, ''
	return None, PROMETHEUS_SELECTION_ERROR


def _resolve_alertmanager_config(raw_id, configs=None):
	configs = list(configs if configs is not None else _available_alertmanager_configs())
	if raw_id is None or not str(raw_id).strip():
		return (configs[0] if configs else None), ''
	try:
		config_id = int(str(raw_id).strip())
	except (TypeError, ValueError):
		return None, ALERTMANAGER_SELECTION_ERROR
	for config in configs:
		if config.id == config_id:
			return config, ''
	return None, ALERTMANAGER_SELECTION_ERROR


def _prometheus_query_options(configs):
	base_names = [
		(config.name or '').strip() or 'Prometheus'
		for config in configs
	]
	name_counts = {}
	for name in base_names:
		name_counts[name] = name_counts.get(name, 0) + 1
	return [
		{
			'id': config.id,
			'name': '%s (#%s)' % (name, config.id) if name_counts[name] > 1 else name,
		}
		for config, name in zip(configs, base_names)
	]


def _alertmanager_query_options(configs):
	base_names = [(config.name or '').strip() or 'Alertmanager' for config in configs]
	name_counts = {}
	for name in base_names:
		name_counts[name] = name_counts.get(name, 0) + 1
	return [
		{'id': config.id, 'name': name if name_counts[name] == 1 else '%s (#%s)' % (name, config.id)}
		for config, name in zip(configs, base_names)
	]


def _prometheus_payload(config):
	return {
		'configured': bool(config and config.prometheus_url),
		'enabled': bool(config and config.enabled),
		'url_display': config.prometheus_url if config and config.prometheus_url else '',
	}


def _connection_health_category(result):
	if result.get('ok'):
		return IntegrationHealthEvent.CATEGORY_OK
	message = str(result.get('message') or '')
	if '超时' in message:
		return IntegrationHealthEvent.CATEGORY_TIMEOUT
	if '未配置' in message:
		return IntegrationHealthEvent.CATEGORY_CONFIGURATION
	if '请求失败' in message:
		return IntegrationHealthEvent.CATEGORY_REQUEST_ERROR
	return IntegrationHealthEvent.CATEGORY_HTTP_ERROR


def _safe_integration_health_payload(config, integration_type):
	try:
		summary = summarize_integration_health(integration_type, source=config)
	except Exception:
		return {}
	counts = summary.get('recent_event_counts') or {}
	state = summary.get('current_state')
	if state not in ('success', 'failed', 'unknown'):
		state = 'unknown'
	category = summary.get('latest_category') or ''
	allowed_categories = set(item[0] for item in IntegrationHealthEvent.CATEGORY_CHOICES)
	if category not in allowed_categories:
		category = ''
	try:
		consecutive_failures = max(0, int(summary.get('consecutive_failures') or 0))
		recent_failures = max(0, int(counts.get(IntegrationHealthEvent.STATUS_FAILED) or 0))
		recent_successes = max(0, int(counts.get(IntegrationHealthEvent.STATUS_SUCCESS) or 0))
	except (TypeError, ValueError):
		consecutive_failures = recent_failures = recent_successes = 0
	return {
		'state': state,
		'last_checked_at': summary.get('latest_check'),
		'category': category,
		'summary': integration_health_summary(category) if category else '',
		'consecutive_failures': consecutive_failures,
		'recent_failures': recent_failures,
		'recent_successes': recent_successes,
	}


def _integration_items(include_health=False):
	items = []
	for config in PrometheusConfig.objects.order_by('id'):
		item = {
			'id': config.id,
			'kind': 'prometheus',
			'kind_label': 'Prometheus',
			'name': config.name,
			'url': config.prometheus_url,
			'enabled': config.enabled,
			'updated_at': config.updated_at,
			'edit_url': reverse('monitor:prometheus_update', args=[config.id]),
			'delete_url': reverse('monitor:prometheus_delete', args=[config.id]),
		}
		if include_health:
			item['health'] = _safe_integration_health_payload(
				config, IntegrationHealthEvent.TYPE_PROMETHEUS)
		items.append(item)
	for config in AlertmanagerConfig.objects.order_by('id'):
		item = {
			'id': config.id,
			'kind': 'alertmanager',
			'kind_label': 'Alertmanager',
			'name': config.name,
			'url': config.alertmanager_url,
			'enabled': config.enabled,
			'updated_at': config.updated_at,
			'edit_url': reverse('monitor:alertmanager_update', args=[config.id]),
			'delete_url': reverse('monitor:alertmanager_delete', args=[config.id]),
		}
		if include_health:
			item['health'] = _safe_integration_health_payload(
				config, IntegrationHealthEvent.TYPE_ALERTMANAGER)
		items.append(item)
	return items


def _integration_lists_payload(request=None):
	include_health = bool(request and _can_view_integration_health(request))
	integrations = _integration_items(include_health=include_health)
	return {
		'integrations': integrations,
		'prometheus_integrations': [
			item for item in integrations if item.get('kind') == 'prometheus'
		],
		'alertmanager_integrations': [
			item for item in integrations if item.get('kind') == 'alertmanager'
		],
	}


def _can_manage_integrations(request):
	return bool(security_context(request).get('can_manage_monitor'))


def _can_view_integration_health(request):
	return has_role(
		request,
		DevOpsRole.ROLE_ADMIN,
		DevOpsModulePermission.MODULE_SECURITY,
	)


def _integration_form_values(kind, instance=None, form=None):
	url_field = 'prometheus_url' if kind == 'prometheus' else 'alertmanager_url'
	values = {
		'id': getattr(instance, 'id', None),
		'name': getattr(instance, 'name', '') or '',
		url_field: getattr(instance, url_field, '') or '',
		'enabled': getattr(instance, 'enabled', True) if instance is not None else True,
	}
	if not form or not form.is_bound:
		return values

	values['name'] = (form.data.get('name') or '').strip()
	values['enabled'] = bool(form.data.get('enabled'))
	# Invalid URLs may contain credentials or query secrets. Only echo a URL that
	# passed form validation; otherwise retain the existing safe value.
	if url_field not in form.errors:
		values[url_field] = form.cleaned_data.get(url_field) or ''
	return values


def _integration_form_payload(kind, instance=None, form=None):
	if kind == 'prometheus':
		create_url = reverse('monitor:prometheus_config')
		update_name = 'monitor:prometheus_update'
		test_url = reverse('monitor:prometheus_test')
	else:
		create_url = reverse('monitor:alertmanager_create')
		update_name = 'monitor:alertmanager_update'
		test_url = reverse('monitor:alertmanager_test')
	return {
		'action': reverse(update_name, args=[instance.id]) if instance and instance.id else create_url,
		'test_action': test_url,
		'editing': bool(instance and instance.id),
		'values': _integration_form_values(kind, instance, form),
	}


def _integration_page_payload(request, active_kind='', instance=None, form=None, message='', message_ok=False):
	prometheus_instance = instance if active_kind == 'prometheus' else None
	alertmanager_instance = instance if active_kind == 'alertmanager' else None
	prometheus_form = form if active_kind == 'prometheus' else None
	alertmanager_form = form if active_kind == 'alertmanager' else None
	payload = {
		'subtitle': '统一管理 Prometheus 和 Alertmanager 对接',
		'csrf': get_token(request),
		'can_manage_integrations': _can_manage_integrations(request),
		'can_view_integration_health': _can_view_integration_health(request),
		'prometheus_form': _integration_form_payload('prometheus', prometheus_instance, prometheus_form),
		'alertmanager_form': _integration_form_payload('alertmanager', alertmanager_instance, alertmanager_form),
		'errors': form_errors(form),
		'message': message,
		'message_ok': bool(message_ok),
		'actions': _monitor_actions(),
	}
	payload.update(_integration_lists_payload(request))
	return payload


def _render_integration_page(request, active_kind='', instance=None, form=None, message='', message_ok=False, status=200):
	content = security_context(request)
	payload = _integration_page_payload(request, active_kind, instance, form, message, message_ok)
	return render_vue_page(request, 'monitor-integrations', '监控对接', payload, content, status=status)


def _posted_instance(model, request):
	try:
		config_id = int(request.POST.get('id') or 0)
	except (TypeError, ValueError):
		return None
	if not config_id:
		return None
	return model.objects.filter(id=config_id).first()


def _persisted_test_config(model, config, test_config, url_field):
	if not config or not config.pk or test_config.pk != config.pk:
		return None
	persisted = model.objects.filter(pk=config.pk).first()
	if not persisted:
		return None
	if (persisted.name != test_config.name
			or getattr(persisted, url_field) != getattr(test_config, url_field)
			or persisted.enabled != test_config.enabled):
		return None
	return persisted


def _record_persisted_connection_test(config, integration_type, result):
	if not config:
		return
	try:
		record_integration_health_event(
			integration_type,
			source=config,
			status=(IntegrationHealthEvent.STATUS_SUCCESS if result.get('ok')
					else IntegrationHealthEvent.STATUS_FAILED),
			category=_connection_health_category(result),
		)
	except Exception:
		# Health telemetry must not alter the established test response.
		return


def _monitor_actions():
	return [
		{'label': '监控管理', 'url': reverse('monitor:monitor_home'), 'class': 'btn-outline-primary'},
		{'label': '监控对接', 'url': reverse('monitor:prometheus_config'), 'class': 'btn-outline-primary'},
		{'label': '指标查询', 'url': reverse('monitor:alert_query'), 'class': 'btn-outline-primary'},
		{'label': '告警通知', 'url': reverse('monitor:alert_notifications'), 'class': 'btn-outline-primary'},
		{'label': '告警列表', 'url': reverse('monitor:alert_notification_list'), 'class': 'btn-outline-primary'},
		{'label': '告警设置', 'url': reverse('monitor:monitor_index'), 'class': 'btn-outline-primary'},
	]


def _alert_notification_configs():
	configs = {}
	for item in AlertNotificationConfig.objects.filter(
			provider__in=[AlertNotificationConfig.PROVIDER_FEISHU, AlertNotificationConfig.PROVIDER_WECOM]
	).order_by('-created_at', '-updated_at', '-id'):
		if item.provider not in configs:
			configs[item.provider] = item
	return configs


def _alert_notification_config_rows():
	return AlertNotificationConfig.objects.filter(
		provider__in=[AlertNotificationConfig.PROVIDER_FEISHU, AlertNotificationConfig.PROVIDER_WECOM]
	).order_by('-created_at', '-updated_at', '-id')


def _has_stored_webhook(config):
	return bool(config and (config.webhook_url or '').strip())


def _format_notification_updated_at(value):
	if not value:
		return ''
	if timezone.is_aware(value):
		value = timezone.localtime(value)
	return value.strftime('%Y-%m-%d %H:%M')


def _alertmanager_options():
	return [
		{'id': config.id, 'name': config.name}
		for config in AlertmanagerConfig.objects.order_by('name', 'id')
	]


def _notification_integration_items(configs=None):
	configs = list(_alert_notification_config_rows()) if configs is None else configs
	if isinstance(configs, dict):
		configs = list(configs.values())
	configure_url = reverse('monitor:alert_notifications')
	items = []
	provider_labels = dict(AlertNotificationConfig.PROVIDER_CHOICES)
	for config in configs:
		if not _has_stored_webhook(config):
			continue
		provider = config.provider
		provider_label = provider_labels.get(provider, provider)
		alert_type = '飞书' if provider == AlertNotificationConfig.PROVIDER_FEISHU else '企业微信'
		items.append({
			'id': config.id,
			'provider': provider,
			'provider_label': provider_label,
			'name': (config.name or '').strip() or '%s告警' % provider_label,
			'alert_name': (config.alert_name or '').strip(),
			'alertmanager_id': config.alertmanager_id,
			'alertmanager_name': config.alertmanager.name if config.alertmanager_id and config.alertmanager else '',
			'alert_type': alert_type,
			'created_at': _format_notification_updated_at(config.created_at),
			'created_by': (config.created_by or '').strip(),
			'enabled': bool(config.enabled),
			'configured': True,
			'updated_at': _format_notification_updated_at(config.updated_at),
			'configure_url': configure_url,
			'edit_url': '%s?edit=%s' % (configure_url, config.id),
			'delete_url': reverse('monitor:alert_notification_delete', args=[config.id]),
		})
	return items


def _alert_notification_payload(
		request, configs=None, form=None, test_message='', save_message='', save_ok=False,
		clear_webhook_inputs=False, preserve_form_values=False, editing_config=None):
	configs = configs or _alert_notification_configs()
	can_manage_notifications = _can_manage_integrations(request)
	def item(provider, default_name):
		config = editing_config if editing_config and editing_config.provider == provider else configs.get(provider)
		configured = _has_stored_webhook(config)
		prefix = '%s_' % provider
		if preserve_form_values and form and form.is_bound and not save_ok:
			is_editing = bool(editing_config and editing_config.provider == provider)
			return {
				'enabled': bool(form.data.get(prefix + 'enabled')),
				'name': (form.data.get(prefix + 'name') or '').strip() or default_name,
				'alert_name': (form.data.get(prefix + 'alert_name') or '').strip(),
				'alertmanager_id': (form.data.get(prefix + 'alertmanager_id') or '').strip(),
				'editing': is_editing,
				'action': reverse('monitor:alert_notification_update', args=[editing_config.id]) if is_editing else reverse('monitor:alert_notifications'),
				'has_webhook': configured,
				'configured': configured,
				'webhook_display': '已配置' if configured else '',
				'webhook_url': (form.data.get(prefix + 'webhook_url') or '').strip(),
			}
		is_editing = bool(editing_config and editing_config.provider == provider)
		return {
			'enabled': bool(config and config.enabled),
			'name': config.name if config and config.name else default_name,
			'alert_name': config.alert_name if is_editing and config else '',
			'alertmanager_id': str(config.alertmanager_id) if config and config.alertmanager_id else '',
			'editing': is_editing,
			'action': reverse('monitor:alert_notification_update', args=[editing_config.id]) if is_editing else reverse('monitor:alert_notifications'),
			'has_webhook': configured,
			'configured': configured,
			'webhook_display': '已配置' if configured else '',
			'webhook_url': '',
		}
	return {
		'subtitle': '配置飞书和企业微信 Webhook，用于告警通知对接',
		'csrf': get_token(request),
		'action': reverse('monitor:alert_notifications'),
		'test_action': reverse('monitor:alert_notifications_test'),
		'list_url': reverse('monitor:alert_notification_list'),
		'can_manage_notifications': can_manage_notifications,
		'editing_notification_id': editing_config.id if editing_config else None,
		'editing_provider': editing_config.provider if editing_config else '',
		'alertmanager_options': _alertmanager_options(),
		'notifications': {
			'feishu': item(AlertNotificationConfig.PROVIDER_FEISHU, '飞书告警'),
			'wecom': item(AlertNotificationConfig.PROVIDER_WECOM, '企业微信告警'),
		},
		'errors': form_errors(form),
		'test_message': test_message,
		'save_message': save_message,
		'save_ok': bool(save_ok),
		'actions': _monitor_actions(),
	}


def _alert_notification_list_payload(request, configs=None):
	configure_url = reverse('monitor:alert_notifications')
	return {
		'subtitle': '查看已配置的告警通知对接',
		'csrf': get_token(request),
		'notification_integrations': _notification_integration_items(configs if configs is not None else list(_alert_notification_config_rows())),
		'configure_url': configure_url,
		'can_manage_notifications': _can_manage_integrations(request),
		'actions': _monitor_actions(),
	}


def _save_alert_notification_configs(request, form, configs, only_provider=None):
	provider_rows = (
		(AlertNotificationConfig.PROVIDER_FEISHU, '飞书告警'),
		(AlertNotificationConfig.PROVIDER_WECOM, '企业微信告警'),
	)
	created_by = (request.session.get('user_name') or '').strip()
	for provider, default_name in provider_rows:
		if only_provider and provider != only_provider:
			continue
		config = AlertNotificationConfig(provider=provider)
		config.enabled = bool(form.cleaned_data.get('%s_enabled' % provider))
		config.name = form.cleaned_data.get('%s_name' % provider) or default_name
		config.alert_name = form.cleaned_data.get('%s_alert_name' % provider) or ''
		config.alertmanager_id = form.cleaned_data.get('%s_alertmanager_id' % provider)
		config.created_at = timezone.now()
		config.created_by = created_by
		webhook = form.cleaned_data.get('%s_webhook_url' % provider)
		if not webhook:
			continue
		config.webhook_url = webhook
		config.save()


def _update_alert_notification_config(request, config, form):
	provider = config.provider
	default_name = dict(AlertNotificationConfig.PROVIDER_CHOICES).get(provider, '告警通知')
	config.enabled = bool(form.cleaned_data.get('%s_enabled' % provider))
	config.name = form.cleaned_data.get('%s_name' % provider) or default_name
	config.alert_name = form.cleaned_data.get('%s_alert_name' % provider) or ''
	config.alertmanager_id = form.cleaned_data.get('%s_alertmanager_id' % provider)
	webhook = form.cleaned_data.get('%s_webhook_url' % provider)
	if webhook:
		config.webhook_url = webhook
	config.save()


def _safe_alert_notification_test_message(result):
	if result.get('ok'):
		return '测试通知发送成功'
	message = result.get('message') or ''
	safe_messages = (
		'Webhook 地址为空或解密失败',
		'HTTPS 证书校验失败，请检查运行环境 CA 证书配置',
		'测试通知发送失败，请检查 Webhook 地址和网络',
		'通知平台返回失败，请检查通知配置',
	)
	if message in safe_messages:
		return message
	return '测试通知发送失败，请检查通知配置和网络'


def _monitor_context(request, monitor=None, form=None):
	monitor_qs = monitor if monitor is not None else Monitor.objects.all()
	has_config = monitor_qs.exists() if hasattr(monitor_qs, 'exists') else bool(monitor_qs)
	content = {
		'monitor': monitor_qs,
		'form': form,
		'has_monitor_config': has_config,
		'open_alert_count': AlertEvent.objects.filter(status=AlertEvent.STATUS_OPEN).count(),
		'latest_alert': AlertEvent.objects.order_by('-created_at').first(),
	}
	content.update(security_context(request))
	return content


def _can_view_prometheus_rules(request):
	return has_role(
		request,
		DevOpsRole.ROLE_VIEWER,
		DevOpsModulePermission.MODULE_CLUSTER,
	)


def _can_create_prometheus_rules(request):
	return has_role(
		request,
		DevOpsRole.ROLE_ADMIN,
		DevOpsModulePermission.MODULE_CLUSTER,
	)


def _prometheus_rule_message(result):
	return PROMETHEUS_RULE_SAFE_MESSAGES.get((result or {}).get('code', ''), '无法操作 PrometheusRule，请稍后重试。')


def _prometheus_rule_failure_status(code):
	if code in ('invalid_yaml', 'invalid_identity', 'validation_error'):
		return 400
	if code == 'conflict':
		return 409
	if code == 'crd_not_found':
		return 404
	return 503


def _prometheus_rule_audit_outcome(code):
	return code if code in PROMETHEUS_RULE_SAFE_MESSAGES else 'offline'


def _safe_prometheus_rule_summary(cluster, rule):
	if not isinstance(rule, dict):
		return None
	namespace, name = normalize_prometheus_rule_identity(rule.get('namespace'), rule.get('name'))
	if not namespace or not name:
		return None
	resource_version = str(rule.get('resource_version') or '').strip()
	created_at = str(rule.get('created_at') or '').strip()
	if len(resource_version) > 255 or not resource_version.isprintable():
		resource_version = ''
	if len(created_at) > 128 or not created_at.isprintable():
		created_at = ''
	return {
		'namespace': namespace,
		'name': name,
		'resource_version': resource_version,
		'created_at': created_at,
		'detail_url': reverse('devops:prometheus_rule_detail', args=[cluster.id, namespace, name]),
	}


def _prometheus_rules_payload(request, yaml_form=None, create_error='', selected_cluster=None):
	if not _can_view_prometheus_rules(request):
		return {'permission_denied': True}
	clusters = list(K8sCluster.objects.order_by('name', 'id'))
	can_create = _can_create_prometheus_rules(request)
	yaml_text = ''
	if can_create and yaml_form is not None:
		yaml_text = (yaml_form.cleaned_data.get('yaml') if yaml_form.is_valid()
			else yaml_form.data.get('yaml', '')) or ''
	payload = {
		'clusters': [{'id': cluster.id, 'name': cluster.name} for cluster in clusters],
		'list_url': reverse('monitor:monitor_index'),
		'selected_cluster_id': None,
		'selected_cluster_name': '',
		'configured': False,
		'rules': [],
		'error': '',
		'create_error': create_error,
		'notice': ('PrometheusRule 草稿已创建，正等待另一名集群管理员复核后发布。'
			if request.GET.get('draft') == 'created' else ''),
		'can_create': can_create,
		'create_url': reverse('monitor:prometheus_rule_create'),
		'revision_list_url': reverse('devops:prometheus_rule_revisions'),
		'form': {'yaml': yaml_text},
	}
	if selected_cluster is not None:
		cluster = next((item for item in clusters if item.id == selected_cluster.id), None)
		if not cluster:
			return payload
		payload['selected_cluster_id'] = cluster.id
		payload['selected_cluster_name'] = cluster.name
		payload['configured'] = True
		return payload
	try:
		cluster_id = int(request.GET.get('cluster') or 0)
	except (TypeError, ValueError):
		return payload
	if cluster_id <= 0:
		return payload
	cluster = next((item for item in clusters if item.id == cluster_id), None)
	if not cluster:
		return payload
	payload['selected_cluster_id'] = cluster.id
	payload['selected_cluster_name'] = cluster.name
	payload['configured'] = True
	result = list_prometheus_rules(cluster)
	if not result.get('ok'):
		payload['error'] = _prometheus_rule_message(result)
		return payload
	payload['rules'] = [summary for summary in (
		_safe_prometheus_rule_summary(cluster, item) for item in result.get('rules', [])
	) if summary]
	return payload


def _monitor_payload(request, monitor_obj=None, form=None, action='', prometheus_rule_form=None,
					 prometheus_rule_create_error='', prometheus_rule_cluster=None):
	payload = {
		'subtitle': '管理 Kubernetes 集群中的 PrometheusRule 规则摘要与双人复核草稿',
		'csrf': get_token(request),
		'actions': _monitor_actions(),
	}
	payload['prometheus_rules'] = _prometheus_rules_payload(
		request, prometheus_rule_form, prometheus_rule_create_error, prometheus_rule_cluster,
	)
	return payload


def _alert_query_payload(request, query, table, error, configs, selected_config):
	alertmanager_configs = _available_alertmanager_configs()
	return {
		'subtitle': '使用已对接的 Prometheus 执行即时 PromQL 查询',
		'csrf': get_token(request),
		'action': reverse('monitor:alert_query'),
		'execute_url': reverse('monitor:metric_query_execute'),
		'metadata_url': reverse('monitor:metric_query_metadata'),
		'targets_url': reverse('monitor:metric_query_targets'),
		'rules_url': reverse('monitor:metric_query_rules'),
		'alerts_url': reverse('monitor:metric_query_alerts'),
		'query': query,
		'table': table if table is not None else empty_prometheus_table(),
		'error': error,
		'prometheus_configured': bool(configs),
		'prometheus_configs': _prometheus_query_options(configs),
		'selected_prometheus_id': selected_config.id if selected_config else None,
		'alertmanager_configured': bool(alertmanager_configs),
		'alertmanager_configs': _alertmanager_query_options(alertmanager_configs),
		'selected_alertmanager_id': alertmanager_configs[0].id if alertmanager_configs else None,
		'actions': _monitor_actions(),
	}


def _dashboard_payload(request, configs, selected_config):
	return {
		'subtitle': '按 Prometheus 对接汇总主机和 Pod 资源指标',
		'csrf': get_token(request),
		'prometheus_configs': _prometheus_query_options(configs),
		'selected_prometheus_id': selected_config.id if selected_config else None,
		'dashboard_url': reverse('monitor:monitor_dashboard_data'),
		'actions': _monitor_actions(),
	}


@session_login_required
def monitor_home(request):
	config = _prometheus_config()
	first_config = PrometheusConfig.objects.order_by('id').first()
	monitor = Monitor.objects.order_by('id').first()
	open_alert_count = AlertEvent.objects.filter(status=AlertEvent.STATUS_OPEN).count()
	integration_lists = _integration_lists_payload(request)
	payload = {
		'subtitle': '统一管理 Prometheus 对接、指标查询和阈值告警配置',
		'cards': [
			{
				'label': 'Prometheus',
				'value': '已启用' if config else ('未启用' if first_config else '未配置'),
				'meta': (config or first_config).prometheus_url if config or first_config else '等待配置',
			},
			{
				'label': '告警设置',
				'value': '已配置' if monitor else '未配置',
				'meta': monitor.monitor_email if monitor and monitor.monitor_email else '未设置邮箱',
			},
			{
				'label': '未处理告警',
				'value': open_alert_count,
				'meta': 'DevOps 告警事件',
			},
		],
		'actions': _monitor_actions(),
		'prometheus': _prometheus_payload(config),
		'can_manage_integrations': _can_manage_integrations(request),
		'can_view_integration_health': _can_view_integration_health(request),
		'csrf': get_token(request),
		'alert_settings_url': reverse('monitor:monitor_index'),
		'integration_url': reverse('monitor:prometheus_config'),
		'query_url': reverse('monitor:alert_query'),
		'notification_url': reverse('monitor:alert_notification_list'),
		'notification_configure_url': reverse('monitor:alert_notifications'),
	}
	payload.update(integration_lists)
	content = {'open_alert_count': open_alert_count}
	content.update(security_context(request))
	return render_vue_page(request, 'monitor-home', '监控管理', payload, content)


@session_login_required
def prometheus_config(request):
	if request.method == 'GET':
		return _render_integration_page(request)
	if request.method != 'POST':
		return HttpResponseNotAllowed(['GET', 'POST'])
	denied = require_monitor_operator(request)
	if denied:
		return denied
	form = PrometheusConfigForm(request.POST)
	if form.is_valid():
		config = form.save()
		audit(request, '保存Prometheus对接', 'PrometheusConfig', config.id, config.name)
		return redirect('monitor:monitor_home')
	return _render_integration_page(request, 'prometheus', form=form, status=400)


@session_login_required
def prometheus_test(request):
	if request.method != 'POST':
		return HttpResponseNotAllowed(['POST'])
	denied = require_monitor_operator(request)
	if denied:
		return denied
	config = _posted_instance(PrometheusConfig, request)
	form = PrometheusConfigForm(request.POST, instance=config)
	message = ''
	message_ok = False
	status = 400
	if form.is_valid():
		test_config = form.save(commit=False)
		result = test_prometheus_connection(test_config)
		persisted = _persisted_test_config(
			PrometheusConfig, config, test_config, 'prometheus_url')
		_record_persisted_connection_test(
			persisted, IntegrationHealthEvent.TYPE_PROMETHEUS, result)
		message_ok = bool(result.get('ok'))
		message = result.get('message') or ('Prometheus 连接正常' if message_ok else 'Prometheus 连接失败')
		status = 200 if message_ok else 400
	return _render_integration_page(request, 'prometheus', config, form, message, message_ok, status)


@session_login_required
def prometheus_update(request, id):
	if request.method != 'POST':
		if request.method != 'GET':
			return HttpResponseNotAllowed(['GET', 'POST'])
	else:
		denied = require_monitor_operator(request)
		if denied:
			return denied
	config = get_object_or_404(PrometheusConfig, id=id)
	if request.method == 'GET':
		return _render_integration_page(request, 'prometheus', config)
	form = PrometheusConfigForm(request.POST, instance=config)
	if form.is_valid():
		config = form.save()
		audit(request, '更新Prometheus对接', 'PrometheusConfig', config.id, config.name)
		return redirect('monitor:monitor_home')
	return _render_integration_page(request, 'prometheus', config, form, status=400)


@session_login_required
def prometheus_delete(request, id):
	if request.method != 'POST':
		return HttpResponseNotAllowed(['POST'])
	denied = require_monitor_operator(request)
	if denied:
		return denied
	config = get_object_or_404(PrometheusConfig, id=id)
	audit(request, '删除Prometheus对接', 'PrometheusConfig', config.id, config.name)
	config.delete()
	return redirect('monitor:monitor_home')


@session_login_required
def alertmanager_create(request):
	if request.method != 'POST':
		return HttpResponseNotAllowed(['POST'])
	denied = require_monitor_operator(request)
	if denied:
		return denied
	form = AlertmanagerConfigForm(request.POST)
	if form.is_valid():
		config = form.save()
		audit(request, '保存Alertmanager对接', 'AlertmanagerConfig', config.id, config.name)
		return redirect('monitor:monitor_home')
	return _render_integration_page(request, 'alertmanager', form=form, status=400)


@session_login_required
def alertmanager_test(request):
	if request.method != 'POST':
		return HttpResponseNotAllowed(['POST'])
	denied = require_monitor_operator(request)
	if denied:
		return denied
	config = _posted_instance(AlertmanagerConfig, request)
	form = AlertmanagerConfigForm(request.POST, instance=config)
	message = ''
	message_ok = False
	status = 400
	if form.is_valid():
		test_config = form.save(commit=False)
		result = test_alertmanager_connection(test_config)
		persisted = _persisted_test_config(
			AlertmanagerConfig, config, test_config, 'alertmanager_url')
		_record_persisted_connection_test(
			persisted, IntegrationHealthEvent.TYPE_ALERTMANAGER, result)
		message_ok = bool(result.get('ok'))
		message = result.get('message') or ('Alertmanager 连接正常' if message_ok else 'Alertmanager 连接失败')
		status = 200 if message_ok else 400
	return _render_integration_page(request, 'alertmanager', config, form, message, message_ok, status)


@session_login_required
def alertmanager_update(request, id):
	if request.method != 'POST':
		if request.method != 'GET':
			return HttpResponseNotAllowed(['GET', 'POST'])
	else:
		denied = require_monitor_operator(request)
		if denied:
			return denied
	config = get_object_or_404(AlertmanagerConfig, id=id)
	if request.method == 'GET':
		return _render_integration_page(request, 'alertmanager', config)
	form = AlertmanagerConfigForm(request.POST, instance=config)
	if form.is_valid():
		config = form.save()
		audit(request, '更新Alertmanager对接', 'AlertmanagerConfig', config.id, config.name)
		return redirect('monitor:monitor_home')
	return _render_integration_page(request, 'alertmanager', config, form, status=400)


@session_login_required
def alertmanager_delete(request, id):
	if request.method != 'POST':
		return HttpResponseNotAllowed(['POST'])
	denied = require_monitor_operator(request)
	if denied:
		return denied
	config = get_object_or_404(AlertmanagerConfig, id=id)
	audit(request, '删除Alertmanager对接', 'AlertmanagerConfig', config.id, config.name)
	config.delete()
	return redirect('monitor:monitor_home')


@csrf_exempt
def alertmanager_webhook(request, id):
	if request.method != 'POST':
		return HttpResponseNotAllowed(['POST'])
	alertmanager = get_object_or_404(AlertmanagerConfig, id=id)
	try:
		payload = json.loads(request.body.decode('utf-8') or '{}')
	except (TypeError, ValueError):
		return JsonResponse({'ok': False, 'message': 'JSON 解析失败'}, status=400)
	if not isinstance(payload, dict):
		return JsonResponse({'ok': False, 'message': 'Alertmanager payload 格式异常'}, status=400)
	# Webhook and polling use one lifecycle path so maintenance-window
	# silencing, repeat handling, and delivery failures remain consistent.
	result = push_alertmanager_firing_alerts(alertmanager, payload, dedupe=True)
	result['ok'] = True
	return JsonResponse(result)


@session_login_required
def alert_query(request):
	query = (request.GET.get('query') or '').strip()
	configs = list(_available_prometheus_configs())
	config, selection_error = _resolve_prometheus_config(request.GET.get('prometheus_id'), configs)
	table = empty_prometheus_table()
	error = selection_error
	status = 400 if selection_error else 200
	if query and not selection_error:
		if len(query) > 2000:
			error = 'PromQL 查询语句不能超过 2000 个字符'
			status = 400
		else:
			if not config:
				error = '请先配置并启用 Prometheus 对接'
				status = 400
			else:
				query_result = query_prometheus(config, query)
				if isinstance(query_result, dict) and query_result.get('ok'):
					table = normalize_prometheus_result(query_result.get('body') or {})
				else:
					error = query_result.get('message') if isinstance(query_result, dict) else ''
					error = error or 'Prometheus 查询失败'
					invalid_query = (
						isinstance(query_result, dict)
						and query_result.get('error_kind') == 'invalid_query'
					)
					status = 400 if invalid_query else 502
	content = security_context(request)
	return render_vue_page(
		request,
		'alert-query',
		'指标查询',
		_alert_query_payload(request, query, table, error, configs, config),
		content,
		status=status,
	)


@session_login_required
def monitor_dashboard(request):
	if request.method != 'GET':
		return HttpResponseNotAllowed(['GET'])
	configs = list(_available_prometheus_configs())
	config, selection_error = _resolve_prometheus_config(request.GET.get('prometheus_id'), configs)
	status = 400 if selection_error else 200
	payload = _dashboard_payload(request, configs, config)
	if selection_error:
		payload['error'] = selection_error
	return render_vue_page(
		request,
		'monitor-dashboard',
		'监控看板',
		payload,
		security_context(request),
		status=status,
	)


@session_login_required
def monitor_dashboard_data(request):
	if request.method != 'POST':
		return HttpResponseNotAllowed(['POST'])
	config, selection_error = _resolve_prometheus_config(request.POST.get('prometheus_id'))
	if selection_error:
		return JsonResponse({'ok': False, 'message': selection_error}, status=400)
	if not config:
		return JsonResponse({'ok': False, 'message': '请先配置并启用 Prometheus 对接'}, status=400)
	result = query_prometheus_dashboard(config)
	hosts = result.get('hosts') or []
	pods = result.get('pods') or []
	errors = result.get('errors') or []
	if not hosts and not pods and len(errors) >= len(PROMETHEUS_DASHBOARD_QUERIES):
		return JsonResponse({
			'ok': False,
			'message': '监控看板数据暂时不可用，请稍后刷新',
		}, status=502)
	return JsonResponse({
		'ok': True,
		'prometheus_id': config.id,
		'hosts': hosts,
		'pods': pods,
		'errors': errors,
	})


@session_login_required
def metric_query_execute(request):
	if request.method != 'POST':
		return HttpResponseNotAllowed(['POST'])
	query = (request.POST.get('query') or '').strip()
	if not query:
		return JsonResponse({'ok': False, 'message': '请输入 PromQL 查询语句'}, status=400)
	if len(query) > 2000:
		return JsonResponse({'ok': False, 'message': 'PromQL 查询语句不能超过 2000 个字符'}, status=400)
	config, selection_error = _resolve_prometheus_config(request.POST.get('prometheus_id'))
	if selection_error:
		return JsonResponse({'ok': False, 'message': selection_error}, status=400)
	if not config:
		return JsonResponse({'ok': False, 'message': '请先配置并启用 Prometheus 对接'}, status=400)
	query_result = query_prometheus(config, query)
	if not isinstance(query_result, dict) or not query_result.get('ok'):
		message = query_result.get('message') if isinstance(query_result, dict) else ''
		status = 400 if isinstance(query_result, dict) and query_result.get('error_kind') == 'invalid_query' else 502
		return JsonResponse({
			'ok': False,
			'message': message or 'Prometheus 查询失败',
		}, status=status)
	return JsonResponse({
		'ok': True,
		'query': query,
		'prometheus_id': config.id,
		'table': normalize_prometheus_result(query_result.get('body') or {}),
	})


@session_login_required
def metric_query_metadata(request):
	if request.method != 'POST':
		return HttpResponseNotAllowed(['POST'])
	config, selection_error = _resolve_prometheus_config(request.POST.get('prometheus_id'))
	if selection_error:
		return JsonResponse({'ok': False, 'message': selection_error}, status=400)
	if not config:
		return JsonResponse({'ok': False, 'message': '请先配置并启用 Prometheus 对接'}, status=400)
	result = query_prometheus_metadata(config)
	if not isinstance(result, dict) or not result.get('ok'):
		message = result.get('message') if isinstance(result, dict) else ''
		if message not in (PROMETHEUS_METADATA_FAILURE_MESSAGE, PROMETHEUS_METADATA_FORMAT_MESSAGE):
			message = PROMETHEUS_METADATA_FAILURE_MESSAGE
		return JsonResponse({'ok': False, 'message': message}, status=502)
	return JsonResponse({
		'ok': True,
		'prometheus_id': config.id,
		'metrics': result.get('metrics') or [],
		'labels': result.get('labels') or [],
	})


def _metric_metadata_response(
		request, query_function, normalize_function, response_key,
		failure_message, format_message):
	config, selection_error = _resolve_prometheus_config(request.POST.get('prometheus_id'))
	if selection_error:
		return JsonResponse({'ok': False, 'message': selection_error}, status=400)
	if not config:
		return JsonResponse({'ok': False, 'message': '请先配置并启用 Prometheus 对接'}, status=400)
	query_result = query_function(config)
	if not isinstance(query_result, dict) or not query_result.get('ok'):
		message = query_result.get('message') if isinstance(query_result, dict) else ''
		if message not in (failure_message, format_message):
			message = failure_message
		return JsonResponse({'ok': False, 'message': message}, status=502)
	return JsonResponse({
		'ok': True,
		'prometheus_id': config.id,
		response_key: normalize_function(query_result.get('body') or {}),
	})


@session_login_required
def metric_query_targets(request):
	if request.method != 'POST':
		return HttpResponseNotAllowed(['POST'])
	return _metric_metadata_response(
		request,
		query_prometheus_targets,
		normalize_prometheus_targets,
		'targets',
		PROMETHEUS_TARGETS_FAILURE_MESSAGE,
		PROMETHEUS_TARGETS_FORMAT_MESSAGE,
	)


@session_login_required
def metric_query_rules(request):
	if request.method != 'POST':
		return HttpResponseNotAllowed(['POST'])
	return _metric_metadata_response(
		request,
		query_prometheus_rules,
		normalize_prometheus_rules,
		'rules',
		PROMETHEUS_RULES_FAILURE_MESSAGE,
		PROMETHEUS_RULES_FORMAT_MESSAGE,
	)


@session_login_required
def metric_query_alerts(request):
	if request.method != 'POST':
		return HttpResponseNotAllowed(['POST'])
	config, selection_error = _resolve_alertmanager_config(request.POST.get('alertmanager_id'))
	if selection_error:
		return JsonResponse({'ok': False, 'message': selection_error}, status=400)
	if not config:
		return JsonResponse({'ok': False, 'message': '请先配置并启用 Alertmanager 对接'}, status=400)
	result = query_alertmanager_alerts(config)
	if not isinstance(result, dict) or not result.get('ok'):
		return JsonResponse({'ok': False, 'message': 'Alertmanager 告警查询失败'}, status=502)
	return JsonResponse({
		'ok': True,
		'alertmanager_id': config.id,
		'alerts': normalize_alertmanager_alerts(result.get('body')),
	})


@session_login_required
def alert_notification_list(request):
	if request.method != 'GET':
		return HttpResponseNotAllowed(['GET'])
	configs = list(_alert_notification_config_rows())
	content = security_context(request)
	return render_vue_page(
		request,
		'alert-notification-list',
		'告警列表',
		_alert_notification_list_payload(request, configs),
		content,
	)


@session_login_required
def alert_notifications(request):
	configs = _alert_notification_configs()
	editing_config = None
	edit_id = request.GET.get('edit')
	if edit_id:
		try:
			editing_config = AlertNotificationConfig.objects.get(id=int(edit_id))
		except (TypeError, ValueError, AlertNotificationConfig.DoesNotExist):
			editing_config = None
	denied = None
	if request.method == "POST":
		denied = require_monitor_operator(request)
	if denied:
		return denied
	if request.method == "POST":
		provider = (request.POST.get('provider') or '').strip()
		# This endpoint always creates a new notification.  Existing records
		# must not make a blank Webhook valid for a separate new record.
		form = AlertNotificationForm(request.POST)
		if form.is_valid():
			_save_alert_notification_configs(request, form, configs, provider if provider in dict(AlertNotificationConfig.PROVIDER_CHOICES) else None)
			audit(request, '保存告警通知', 'AlertNotificationConfig', '', dict(AlertNotificationConfig.PROVIDER_CHOICES).get(provider, '飞书/企业微信'))
			configs = _alert_notification_configs()
			content = {}
			content.update(security_context(request))
			return render_vue_page(
				request,
				'alert-notifications',
				'告警通知',
				_alert_notification_payload(
					request,
					configs,
					save_message='告警通知保存成功',
					save_ok=True,
					clear_webhook_inputs=True,
				),
				content,
			)
		content = {}
		content.update(security_context(request))
		return render_vue_page(
			request,
			'alert-notifications',
			'告警通知',
				_alert_notification_payload(
					request,
					configs,
					form,
					save_message='告警通知保存失败，请检查表单信息',
					save_ok=False,
					preserve_form_values=True,
				),
			content,
			status=400,
		)
	content = {}
	content.update(security_context(request))
	return render_vue_page(request, 'alert-notifications', '告警通知', _alert_notification_payload(request, configs, editing_config=editing_config), content)


@session_login_required
def alert_notification_update(request, id):
	if request.method != 'POST':
		return HttpResponseNotAllowed(['POST'])
	denied = require_monitor_operator(request)
	if denied:
		return denied
	config = get_object_or_404(AlertNotificationConfig, id=id)
	configs = _alert_notification_configs()
	form = AlertNotificationForm(request.POST, existing={config.provider: config}, require_webhook=False)
	content = {}
	content.update(security_context(request))
	if form.is_valid():
		_update_alert_notification_config(request, config, form)
		audit(request, '更新告警通知', 'AlertNotificationConfig', config.id, config.name)
		config.refresh_from_db()
		return render_vue_page(
			request,
			'alert-notifications',
			'告警通知',
			_alert_notification_payload(
				request,
				_alert_notification_configs(),
				save_message='告警通知更新成功',
				save_ok=True,
				clear_webhook_inputs=True,
			),
			content,
		)
	return render_vue_page(
		request,
		'alert-notifications',
		'告警通知',
		_alert_notification_payload(
			request,
			configs,
			form,
			save_message='告警通知更新失败，请检查表单信息',
			save_ok=False,
			preserve_form_values=True,
			editing_config=config,
		),
		content,
		status=400,
	)


@session_login_required
def alert_notification_delete(request, id):
	if request.method != 'POST':
		return HttpResponseNotAllowed(['POST'])
	denied = require_monitor_operator(request)
	if denied:
		return denied
	config = get_object_or_404(AlertNotificationConfig, id=id)
	name = config.name
	config.delete()
	audit(request, '删除告警通知', 'AlertNotificationConfig', id, name)
	return redirect('monitor:alert_notification_list')


@session_login_required
def alert_notifications_test(request):
	configs = _alert_notification_configs()
	denied = require_monitor_operator(request)
	if denied:
		return denied
	provider = (request.POST.get('provider') or '').strip()
	form = AlertNotificationForm(request.POST or None, existing=configs)
	test_message = ''
	status = 400
	if provider not in (AlertNotificationConfig.PROVIDER_FEISHU, AlertNotificationConfig.PROVIDER_WECOM):
		test_message = '请选择要测试的通知渠道'
	elif request.method == "POST" and form.is_valid():
		config = configs.get(provider) or AlertNotificationConfig(provider=provider)
		config.enabled = bool(form.cleaned_data.get('%s_enabled' % provider))
		config.name = form.cleaned_data.get('%s_name' % provider) or dict(AlertNotificationConfig.PROVIDER_CHOICES).get(provider)
		config.alert_name = form.cleaned_data.get('%s_alert_name' % provider) or ''
		webhook = form.cleaned_data.get('%s_webhook_url' % provider)
		if webhook:
			config.webhook_url = webhook
		result = send_alert_notification(config)
		message_ok = bool(result.get('ok'))
		test_message = _safe_alert_notification_test_message(result)
		status = 200 if message_ok else 400
	content = {}
	content.update(security_context(request))
	return render_vue_page(request, 'alert-notifications', '告警通知', _alert_notification_payload(request, configs, form, test_message), content, status=status)


@session_login_required
def prometheus_rule_create(request):
	if not _can_create_prometheus_rules(request):
		return JsonResponse({'detail': '没有权限执行此操作。'}, status=403)
	if request.method != 'POST':
		return HttpResponseNotAllowed(['POST'])
	try:
		cluster_id = int(request.POST.get('cluster') or 0)
	except (TypeError, ValueError):
		cluster_id = 0
	cluster = K8sCluster.objects.filter(id=cluster_id).first() if cluster_id > 0 else None
	form = PrometheusRuleYamlForm(request.POST)
	if not cluster or not form.is_valid():
		content = _monitor_context(request, Monitor.objects.all(), form)
		return render_vue_page(
			request, 'monitor', '告警设置',
			_monitor_payload(request, Monitor.objects.order_by('id').first(), prometheus_rule_form=form,
				prometheus_rule_create_error='规则 YAML 格式或资源身份无效。', prometheus_rule_cluster=cluster),
			content, status=400,
		)
	yaml_text = form.cleaned_data['yaml']
	if not yaml:
		return render_vue_page(
			request, 'monitor', '告警设置',
			_monitor_payload(request, Monitor.objects.order_by('id').first(), prometheus_rule_form=form,
				prometheus_rule_create_error='规则 YAML 格式或资源身份无效。', prometheus_rule_cluster=cluster),
			_monitor_context(request, Monitor.objects.all(), form), status=400,
		)
	try:
		document = yaml.safe_load(yaml_text)
	except Exception:
		document = None
	metadata = document.get('metadata') if isinstance(document, dict) else None
	if (not isinstance(metadata, dict) or document.get('apiVersion') != 'monitoring.coreos.com/v1'
			or document.get('kind') != 'PrometheusRule'):
		document = None
	namespace, name = normalize_prometheus_rule_identity(
		metadata.get('namespace') if isinstance(metadata, dict) else None,
		metadata.get('name') if isinstance(metadata, dict) else None,
	)
	if not document or not namespace or not name:
		return render_vue_page(
			request, 'monitor', '告警设置',
			_monitor_payload(request, Monitor.objects.order_by('id').first(), prometheus_rule_form=form,
				prometheus_rule_create_error='规则 YAML 格式或资源身份无效。', prometheus_rule_cluster=cluster),
			_monitor_context(request, Monitor.objects.all(), form), status=400,
		)
	result = create_prometheus_rule_draft(request, cluster, yaml_text, action='create')
	if not result.get('ok'):
		audit(
			request, '创建PrometheusRule草稿', 'K8sCluster', cluster.id,
			'cluster=%s, namespace=%s, name=%s, action=create, outcome=%s' % (
				cluster.id, namespace, name,
				_prometheus_rule_audit_outcome(result.get('code', 'offline')),
			),
		)
		return render_vue_page(
			request, 'monitor', '告警设置',
			_monitor_payload(request, Monitor.objects.order_by('id').first(), prometheus_rule_form=form,
				prometheus_rule_create_error=_prometheus_rule_message(result), prometheus_rule_cluster=cluster),
			_monitor_context(request, Monitor.objects.all(), form),
			status=_prometheus_rule_failure_status(result.get('code', 'offline')),
		)
	revision = result.get('revision') if isinstance(result.get('revision'), dict) else {}
	created_namespace, created_name = normalize_prometheus_rule_identity(
		revision.get('namespace'),
		revision.get('name'),
	)
	if not created_namespace or not created_name:
		return render_vue_page(
			request, 'monitor', '告警设置',
			_monitor_payload(request, Monitor.objects.order_by('id').first(), prometheus_rule_form=form,
				prometheus_rule_create_error='无法操作 PrometheusRule，请稍后重试。', prometheus_rule_cluster=cluster),
			_monitor_context(request, Monitor.objects.all(), form), status=503,
		)
	audit(
		request, '创建PrometheusRule草稿', 'K8sCluster', cluster.id,
		'cluster=%s, namespace=%s, name=%s, action=create, outcome=draft' % (
			cluster.id, created_namespace, created_name,
		),
	)
	return redirect('%s?cluster=%s&draft=created' % (reverse('monitor:monitor_index'), cluster.id))


@session_login_required
def monitor_index(request):
	monitor = Monitor.objects.all()
	if request.method == "POST":
		denied = require_monitor_operator(request)
		if denied:
			return denied
		monitorform = MonitorForm(request.POST)
		if monitorform.is_valid():
			monitor = Monitor.objects.all()
			if monitor.count() == 0:
				monitor_obj = monitorform.save()
				audit(request, '创建监控阈值', 'Monitor', monitor_obj.id, monitor_obj.monitor_email)
				return redirect("linux")
			else:
				monitorform.add_error(None, "已存有告警数据，请点击修改来更新告警数值")
				content = _monitor_context(request, monitor, monitorform)
				return render_vue_page(request, 'monitor', '告警设置', _monitor_payload(request, monitor.first(), monitorform), content, status=400)
		else:
			content = _monitor_context(request, monitor, monitorform)
			return render_vue_page(request, 'monitor', '告警设置', _monitor_payload(request, monitor.first(), monitorform), content, status=400)
	else:
		content = _monitor_context(request, monitor)
		return render_vue_page(request, 'monitor', '告警设置', _monitor_payload(request, monitor.first()), content)


@session_login_required
def monitor_update(request, id):
	monitor = get_object_or_404(Monitor, id=id)
	denied = require_monitor_operator(request)
	if denied:
		return denied
	if request.method == "POST":
		# 将提交的数据赋值到表单实例中
		monitorform = MonitorForm(request.POST, instance=monitor)
		if monitorform.is_valid():
			monitor = monitorform.save()
			audit(request, '更新监控阈值', 'Monitor', monitor.id, monitor.monitor_email)
			return redirect('monitor:monitor_index')
		else:
			content = _monitor_context(request, monitor, monitorform)
			return render_vue_page(request, 'monitor', '编辑告警设置', _monitor_payload(request, monitor, monitorform, reverse('monitor:monitor_update', args=[monitor.id])), content, status=400)
	else:
		content = _monitor_context(request, monitor)
		return render_vue_page(request, 'monitor', '编辑告警设置', _monitor_payload(request, monitor, action=reverse('monitor:monitor_update', args=[monitor.id])), content)
