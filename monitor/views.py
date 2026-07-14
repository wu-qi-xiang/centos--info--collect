from django.shortcuts import get_object_or_404, render, redirect
from django.http import HttpResponseNotAllowed, JsonResponse
from django.middleware.csrf import get_token
from django.urls import reverse
from django.utils import timezone
# Create your views here.
from .models import AlertmanagerConfig, AlertNotificationConfig, Monitor, PrometheusConfig
from .forms import AlertmanagerConfigForm, AlertNotificationForm, MonitorForm, PrometheusConfigForm
from .services import (
	PROMETHEUS_RULES_FAILURE_MESSAGE,
	PROMETHEUS_RULES_FORMAT_MESSAGE,
	PROMETHEUS_METADATA_FAILURE_MESSAGE,
	PROMETHEUS_METADATA_FORMAT_MESSAGE,
	PROMETHEUS_TARGETS_FAILURE_MESSAGE,
	PROMETHEUS_TARGETS_FORMAT_MESSAGE,
	empty_prometheus_table,
	normalize_prometheus_rules,
	normalize_prometheus_result,
	normalize_prometheus_targets,
	query_prometheus,
	query_prometheus_metadata,
	query_prometheus_rules,
	query_prometheus_targets,
	send_alert_notification,
	test_alertmanager_connection,
	test_prometheus_connection,
)
from devops.models import AlertEvent
from devops.services import audit
from PyLinux.security import require_monitor_operator, security_context
from PyLinux.vue import form_errors, model_dict, render_vue_page
from userprofile.decorators import session_login_required


PROMETHEUS_SELECTION_ERROR = '选择的 Prometheus 对接不可用'


def _available_prometheus_configs():
	return [
		config
		for config in PrometheusConfig.objects.filter(enabled=True).order_by('id')
		if (config.prometheus_url or '').strip()
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


def _prometheus_payload(config):
	return {
		'configured': bool(config and config.prometheus_url),
		'enabled': bool(config and config.enabled),
		'url_display': config.prometheus_url if config and config.prometheus_url else '',
	}


def _integration_items():
	items = []
	for config in PrometheusConfig.objects.order_by('id'):
		items.append({
			'id': config.id,
			'kind': 'prometheus',
			'kind_label': 'Prometheus',
			'name': config.name,
			'url': config.prometheus_url,
			'enabled': config.enabled,
			'updated_at': config.updated_at,
			'edit_url': reverse('monitor:prometheus_update', args=[config.id]),
			'delete_url': reverse('monitor:prometheus_delete', args=[config.id]),
		})
	for config in AlertmanagerConfig.objects.order_by('id'):
		items.append({
			'id': config.id,
			'kind': 'alertmanager',
			'kind_label': 'Alertmanager',
			'name': config.name,
			'url': config.alertmanager_url,
			'enabled': config.enabled,
			'updated_at': config.updated_at,
			'edit_url': reverse('monitor:alertmanager_update', args=[config.id]),
			'delete_url': reverse('monitor:alertmanager_delete', args=[config.id]),
		})
	return items


def _integration_lists_payload():
	integrations = _integration_items()
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
		'prometheus_form': _integration_form_payload('prometheus', prometheus_instance, prometheus_form),
		'alertmanager_form': _integration_form_payload('alertmanager', alertmanager_instance, alertmanager_form),
		'errors': form_errors(form),
		'message': message,
		'message_ok': bool(message_ok),
		'actions': _monitor_actions(),
	}
	payload.update(_integration_lists_payload())
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
	configs = {
		item.provider: item
		for item in AlertNotificationConfig.objects.filter(
			provider__in=[AlertNotificationConfig.PROVIDER_FEISHU, AlertNotificationConfig.PROVIDER_WECOM]
		)
	}
	return configs


def _has_stored_webhook(config):
	return bool(config and (config.webhook_url or '').strip())


def _format_notification_updated_at(value):
	if not value:
		return ''
	if timezone.is_aware(value):
		value = timezone.localtime(value)
	return value.strftime('%Y-%m-%d %H:%M')


def _notification_integration_items(configs=None):
	configs = _alert_notification_configs() if configs is None else configs
	configure_url = reverse('monitor:alert_notifications')
	items = []
	for provider, provider_label in AlertNotificationConfig.PROVIDER_CHOICES:
		config = configs.get(provider)
		if not _has_stored_webhook(config):
			continue
		items.append({
			'provider': provider,
			'provider_label': provider_label,
			'name': (config.name or '').strip() or '%s告警' % provider_label,
			'enabled': bool(config.enabled),
			'configured': True,
			'updated_at': _format_notification_updated_at(config.updated_at),
			'configure_url': configure_url,
		})
	return items


def _alert_notification_payload(request, configs=None, form=None, test_message=''):
	configs = configs or _alert_notification_configs()
	def item(provider, default_name):
		config = configs.get(provider)
		configured = _has_stored_webhook(config)
		return {
			'enabled': bool(config and config.enabled),
			'name': config.name if config and config.name else default_name,
			'has_webhook': configured,
			'configured': configured,
			'webhook_display': '已配置' if configured else '',
		}
	return {
		'subtitle': '配置飞书和企业微信 Webhook，用于告警通知对接',
		'csrf': get_token(request),
		'action': reverse('monitor:alert_notifications'),
		'test_action': reverse('monitor:alert_notifications_test'),
		'list_url': reverse('monitor:alert_notification_list'),
		'can_manage_notifications': _can_manage_integrations(request),
		'notifications': {
			'feishu': item(AlertNotificationConfig.PROVIDER_FEISHU, '飞书告警'),
			'wecom': item(AlertNotificationConfig.PROVIDER_WECOM, '企业微信告警'),
		},
		'errors': form_errors(form),
		'test_message': test_message,
		'actions': _monitor_actions(),
	}


def _alert_notification_list_payload(request, configs=None):
	configure_url = reverse('monitor:alert_notifications')
	return {
		'subtitle': '查看已配置的告警通知对接',
		'notification_integrations': _notification_integration_items(configs),
		'configure_url': configure_url,
		'can_manage_notifications': _can_manage_integrations(request),
		'actions': _monitor_actions(),
	}


def _save_alert_notification_configs(form, configs, only_provider=None):
	provider_rows = (
		(AlertNotificationConfig.PROVIDER_FEISHU, '飞书告警'),
		(AlertNotificationConfig.PROVIDER_WECOM, '企业微信告警'),
	)
	for provider, default_name in provider_rows:
		if only_provider and provider != only_provider:
			continue
		config = configs.get(provider) or AlertNotificationConfig(provider=provider)
		config.enabled = bool(form.cleaned_data.get('%s_enabled' % provider))
		config.name = form.cleaned_data.get('%s_name' % provider) or default_name
		webhook = form.cleaned_data.get('%s_webhook_url' % provider)
		if webhook:
			config.webhook_url = webhook
		config.save()


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


def _monitor_payload(request, monitor_obj=None, form=None, action=''):
	return {
		'subtitle': '配置 CPU、内存、磁盘阈值和告警邮箱',
		'csrf': get_token(request),
		'action': action or reverse('monitor:monitor_index'),
		'monitor': model_dict(monitor_obj) or {},
		'errors': form_errors(form),
		'open_alert_count': AlertEvent.objects.filter(status=AlertEvent.STATUS_OPEN).count(),
		'latest_alert_message': (AlertEvent.objects.order_by('-created_at').first().message if AlertEvent.objects.exists() else ''),
		'actions': _monitor_actions(),
	}


def _alert_query_payload(request, query, table, error, configs, selected_config):
	return {
		'subtitle': '使用已对接的 Prometheus 执行即时 PromQL 查询',
		'csrf': get_token(request),
		'action': reverse('monitor:alert_query'),
		'execute_url': reverse('monitor:metric_query_execute'),
		'metadata_url': reverse('monitor:metric_query_metadata'),
		'targets_url': reverse('monitor:metric_query_targets'),
		'rules_url': reverse('monitor:metric_query_rules'),
		'query': query,
		'table': table if table is not None else empty_prometheus_table(),
		'error': error,
		'prometheus_configured': bool(configs),
		'prometheus_configs': _prometheus_query_options(configs),
		'selected_prometheus_id': selected_config.id if selected_config else None,
		'actions': _monitor_actions(),
	}


@session_login_required
def monitor_home(request):
	config = _prometheus_config()
	first_config = PrometheusConfig.objects.order_by('id').first()
	monitor = Monitor.objects.order_by('id').first()
	open_alert_count = AlertEvent.objects.filter(status=AlertEvent.STATUS_OPEN).count()
	integration_lists = _integration_lists_payload()
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
def alert_notification_list(request):
	if request.method != 'GET':
		return HttpResponseNotAllowed(['GET'])
	configs = _alert_notification_configs()
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
	denied = None
	if request.method == "POST":
		denied = require_monitor_operator(request)
	if denied:
		return denied
	if request.method == "POST":
		provider = (request.POST.get('provider') or '').strip()
		form = AlertNotificationForm(request.POST, existing=configs)
		if form.is_valid():
			_save_alert_notification_configs(form, configs, provider if provider in dict(AlertNotificationConfig.PROVIDER_CHOICES) else None)
			audit(request, '保存告警通知', 'AlertNotificationConfig', '', dict(AlertNotificationConfig.PROVIDER_CHOICES).get(provider, '飞书/企业微信'))
			return redirect('monitor:alert_notification_list')
		content = {}
		content.update(security_context(request))
		return render_vue_page(request, 'alert-notifications', '告警通知', _alert_notification_payload(request, configs, form), content, status=400)
	content = {}
	content.update(security_context(request))
	return render_vue_page(request, 'alert-notifications', '告警通知', _alert_notification_payload(request, configs), content)


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
		webhook = form.cleaned_data.get('%s_webhook_url' % provider)
		if webhook:
			config.webhook_url = webhook
		result = send_alert_notification(config)
		message_ok = bool(result.get('ok'))
		test_message = '测试通知发送成功' if message_ok else '测试通知发送失败，请检查通知配置和网络'
		status = 200 if message_ok else 400
	content = {}
	content.update(security_context(request))
	return render_vue_page(request, 'alert-notifications', '告警通知', _alert_notification_payload(request, configs, form, test_message), content, status=status)


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
