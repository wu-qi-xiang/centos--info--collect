from django.shortcuts import get_object_or_404, render, redirect
from django.http import HttpResponseNotAllowed, JsonResponse
from django.middleware.csrf import get_token
from django.urls import reverse
# Create your views here.
from .models import AlertmanagerConfig, AlertNotificationConfig, Monitor, PrometheusConfig
from .forms import AlertmanagerConfigForm, AlertNotificationForm, MonitorForm, PrometheusConfigForm
from .services import (
	empty_prometheus_table,
	normalize_prometheus_result,
	query_prometheus,
	send_alert_notification,
	test_alertmanager_connection,
	test_prometheus_connection,
)
from devops.models import AlertEvent
from devops.services import audit
from PyLinux.security import require_monitor_operator, security_context
from PyLinux.vue import form_errors, model_dict, render_vue_page
from userprofile.decorators import session_login_required


def _prometheus_config():
	return PrometheusConfig.objects.filter(enabled=True).exclude(prometheus_url='').order_by('id').first()


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
	return {
		'subtitle': '统一管理 Prometheus 和 Alertmanager 对接',
		'csrf': get_token(request),
		'integrations': _integration_items(),
		'can_manage_integrations': _can_manage_integrations(request),
		'prometheus_form': _integration_form_payload('prometheus', prometheus_instance, prometheus_form),
		'alertmanager_form': _integration_form_payload('alertmanager', alertmanager_instance, alertmanager_form),
		'errors': form_errors(form),
		'message': message,
		'message_ok': bool(message_ok),
		'actions': _monitor_actions(),
	}


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


def _masked_webhook(config):
	if not config or not config.decrypted_webhook_url:
		return ''
	value = config.decrypted_webhook_url
	if len(value) <= 18:
		return '已配置'
	return '%s...%s' % (value[:12], value[-6:])


def _alert_notification_payload(request, configs=None, form=None, test_message=''):
	configs = configs or _alert_notification_configs()
	def item(provider, default_name):
		config = configs.get(provider)
		return {
			'enabled': bool(config and config.enabled),
			'name': config.name if config and config.name else default_name,
			'has_webhook': bool(config and config.decrypted_webhook_url),
			'webhook_display': _masked_webhook(config),
		}
	return {
		'subtitle': '配置飞书和企业微信 Webhook，用于告警通知对接',
		'csrf': get_token(request),
		'action': reverse('monitor:alert_notifications'),
		'test_action': reverse('monitor:alert_notifications_test'),
		'notifications': {
			'feishu': item(AlertNotificationConfig.PROVIDER_FEISHU, '飞书告警'),
			'wecom': item(AlertNotificationConfig.PROVIDER_WECOM, '企业微信告警'),
		},
		'errors': form_errors(form),
		'test_message': test_message,
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


def _alert_query_payload(request, query='', table=None, error=''):
	config = _prometheus_config()
	return {
		'subtitle': '使用已对接的 Prometheus 执行即时 PromQL 查询',
		'csrf': get_token(request),
		'action': reverse('monitor:alert_query'),
		'execute_url': reverse('monitor:metric_query_execute'),
		'query': query,
		'table': table if table is not None else empty_prometheus_table(),
		'error': error,
		'prometheus_configured': bool(config and config.prometheus_url and config.enabled),
		'actions': _monitor_actions(),
	}


@session_login_required
def monitor_home(request):
	config = _prometheus_config()
	first_config = PrometheusConfig.objects.order_by('id').first()
	monitor = Monitor.objects.order_by('id').first()
	open_alert_count = AlertEvent.objects.filter(status=AlertEvent.STATUS_OPEN).count()
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
		'integrations': _integration_items(),
		'can_manage_integrations': _can_manage_integrations(request),
		'csrf': get_token(request),
		'alert_settings_url': reverse('monitor:monitor_index'),
		'integration_url': reverse('monitor:prometheus_config'),
		'query_url': reverse('monitor:alert_query'),
		'notification_url': reverse('monitor:alert_notifications'),
	}
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
	table = empty_prometheus_table()
	error = ''
	status = 200
	if query:
		if len(query) > 2000:
			error = 'PromQL 查询语句不能超过 2000 个字符'
			status = 400
		else:
			config = _prometheus_config()
			if not config:
				error = '请先配置并启用 Prometheus 对接'
				status = 400
			else:
				query_result = query_prometheus(config, query)
				if query_result.get('ok'):
					table = normalize_prometheus_result(query_result.get('body') or {})
				else:
					error = query_result.get('message') or 'Prometheus 查询失败'
					status = 502
	content = security_context(request)
	return render_vue_page(
		request,
		'alert-query',
		'指标查询',
		_alert_query_payload(request, query, table, error),
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
	config = _prometheus_config()
	if not config:
		return JsonResponse({'ok': False, 'message': '请先配置并启用 Prometheus 对接'}, status=400)
	query_result = query_prometheus(config, query)
	if not query_result.get('ok'):
		return JsonResponse({
			'ok': False,
			'message': query_result.get('message') or 'Prometheus 查询失败',
		}, status=502)
	return JsonResponse({
		'ok': True,
		'query': query,
		'table': normalize_prometheus_result(query_result.get('body') or {}),
	})


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
			return redirect('monitor:alert_notifications')
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
		test_message = result.get('message') or ('测试通知发送成功' if result.get('ok') else '测试通知发送失败')
		status = 200 if result.get('ok') else 400
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
