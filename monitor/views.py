from django.shortcuts import get_object_or_404, render, redirect
from django.http import HttpResponse
from django.middleware.csrf import get_token
from django.urls import reverse
# Create your views here.
from .models import Monitor
from .forms import MonitorForm
from devops.models import AlertEvent
from devops.services import audit
from PyLinux.security import require_monitor_operator, security_context
from PyLinux.vue import form_errors, model_dict, render_vue_page
from userprofile.decorators import session_login_required


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
		'actions': [{'label': 'DevOps 告警', 'url': '/devops/', 'class': 'btn-outline-primary'}],
	}


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
				return render_vue_page(request, 'monitor', '监控设置', _monitor_payload(request, monitor.first(), monitorform), content, status=400)
		else:
			content = _monitor_context(request, monitor, monitorform)
			return render_vue_page(request, 'monitor', '监控设置', _monitor_payload(request, monitor.first(), monitorform), content, status=400)
	else:
		content = _monitor_context(request, monitor)
		return render_vue_page(request, 'monitor', '监控设置', _monitor_payload(request, monitor.first()), content)


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
			return render_vue_page(request, 'monitor', '编辑监控设置', _monitor_payload(request, monitor, monitorform, reverse('monitor:monitor_update', args=[monitor.id])), content, status=400)
	else:
		content = _monitor_context(request, monitor)
		return render_vue_page(request, 'monitor', '编辑监控设置', _monitor_payload(request, monitor, action=reverse('monitor:monitor_update', args=[monitor.id])), content)
