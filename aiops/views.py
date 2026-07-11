from collections import defaultdict
import json
try:
	from urllib import request as urlrequest
except ImportError:
	import urllib.request as urlrequest
try:
	import requests
except ImportError:
	class _UrlLibResponse(object):
		def __init__(self, response):
			self.status_code = response.getcode()
			self.text = response.read().decode('utf-8', errors='ignore')

		def json(self):
			return json.loads(self.text or '{}')

	class _UrlLibRequests(object):
		@staticmethod
		def post(url, json=None, headers=None, timeout=5):
			data = None
			if json is not None:
				data = json_module.dumps(json).encode('utf-8')
			req = urlrequest.Request(url, data=data, headers=headers or {'Content-Type': 'application/json'})
			return _UrlLibResponse(urlrequest.urlopen(req, timeout=timeout))

	requests = _UrlLibRequests()
json_module = json

from django.db.models import Avg, Count, Max, Q
from django.http import HttpResponseNotAllowed, JsonResponse
from django.middleware.csrf import get_token
from django.shortcuts import redirect, render
from django.views.decorators.csrf import csrf_exempt
from django.utils import timezone

from devops.models import AlertEvent, AuditLog, CommandExecution, MetricSample, NotificationLog
from devops.services import visible_hosts_for_request
from userprofile.decorators import session_login_required
from .models import AiopsAlertAnalysis, AiopsIntegration


def _pct(value):
	if value is None:
		return None
	return round(float(value) * 100, 1)


def _host_name(host):
	if not host:
		return '未知主机'
	return host.linux_name or host.linux_ip or host.linux_hostname or '未命名主机'


def _latest_metric_map(hosts):
	host_ids = [host.id for host in hosts]
	if not host_ids:
		return {}
	latest_rows = (
		MetricSample.objects
		.filter(host_id__in=host_ids)
		.values('host_id', 'metric')
		.annotate(latest=Max('collected_at'))
	)
	latest = {}
	for row in latest_rows:
		sample = MetricSample.objects.filter(
			host_id=row['host_id'],
			metric=row['metric'],
			collected_at=row['latest'],
		).first()
		if sample:
			latest[(sample.host_id, sample.metric)] = sample
	return latest


def _build_anomalies(hosts, latest_metrics, open_alerts):
	anomalies = []
	for host in hosts:
		metrics = {
			'cpu': latest_metrics.get((host.id, MetricSample.METRIC_CPU)),
			'memory': latest_metrics.get((host.id, MetricSample.METRIC_MEMORY)),
			'disk': latest_metrics.get((host.id, MetricSample.METRIC_DISK)),
		}
		for metric, sample in metrics.items():
			if not sample:
				continue
			value = _pct(sample.value)
			if value is None:
				continue
			if value >= 90:
				level = 'critical'
				reason = '%s 已达到 %.1f%%，超过严重阈值' % (metric.upper(), value)
			elif value >= 80:
				level = 'warning'
				reason = '%s 已达到 %.1f%%，接近容量上限' % (metric.upper(), value)
			else:
				continue
			anomalies.append({
				'host': _host_name(host),
				'metric': metric.upper(),
				'value': value,
				'level': level,
				'reason': reason,
				'action': '检查进程负载、磁盘占用和近期变更；必要时执行扩容或清理。',
			})
	alert_by_host = defaultdict(int)
	for alert in open_alerts:
		alert_by_host[alert.host_id] += 1
	for host in hosts:
		count = alert_by_host.get(host.id, 0)
		if count >= 3:
			anomalies.append({
				'host': _host_name(host),
				'metric': 'ALERT',
				'value': count,
				'level': 'critical',
				'reason': '当前存在 %s 条未恢复告警，可能是同一故障扩散' % count,
				'action': '优先做事件关联，按时间线合并重复告警后定位共同主机或应用。',
			})
	return anomalies[:10]


def _build_correlations(open_alerts, failed_commands):
	groups = defaultdict(lambda: {'alerts': [], 'commands': []})
	for alert in open_alerts:
		key = alert.host_id or 'global'
		groups[key]['alerts'].append(alert)
	for command in failed_commands:
		key = command.host_id or 'global'
		groups[key]['commands'].append(command)
	correlations = []
	for item in groups.values():
		if not item['alerts'] and not item['commands']:
			continue
		host = item['alerts'][0].host if item['alerts'] else item['commands'][0].host
		score = min(99, 45 + len(item['alerts']) * 15 + len(item['commands']) * 10)
		correlations.append({
			'title': '%s 事件簇' % _host_name(host),
			'host': _host_name(host),
			'score': score,
			'alert_count': len(item['alerts']),
			'failed_command_count': len(item['commands']),
			'summary': '聚合未恢复告警 %s 条、失败命令 %s 条。' % (len(item['alerts']), len(item['commands'])),
		})
	return sorted(correlations, key=lambda row: row['score'], reverse=True)[:8]


def _build_root_causes(correlations, anomalies):
	causes = []
	for row in correlations[:5]:
		if row['alert_count'] and row['failed_command_count']:
			cause = '近期变更或修复命令失败后告警未恢复'
			confidence = min(95, row['score'])
		elif row['alert_count'] >= 2:
			cause = '同主机多指标异常，疑似资源瓶颈或服务级联故障'
			confidence = min(88, row['score'])
		else:
			cause = '自动化命令失败，需检查权限、网络或运行环境'
			confidence = min(80, row['score'])
		causes.append({
			'host': row['host'],
			'cause': cause,
			'confidence': confidence,
			'evidence': row['summary'],
		})
	for item in anomalies[:3]:
		if item['metric'] != 'ALERT':
			causes.append({
				'host': item['host'],
				'cause': '%s 资源持续高位' % item['metric'],
				'confidence': 72 if item['level'] == 'warning' else 86,
				'evidence': item['reason'],
			})
	return causes[:8]


def _build_capacity(hosts):
	host_ids = [host.id for host in hosts]
	if not host_ids:
		return []
	rows = (
		MetricSample.objects
		.filter(host_id__in=host_ids)
		.values('host_id', 'metric')
		.annotate(avg_value=Avg('value'), points=Count('id'))
	)
	host_map = {host.id: host for host in hosts}
	capacity = []
	for row in rows:
		avg = _pct(row['avg_value'])
		if avg is None:
			continue
		if avg >= 85:
			trend = '高风险'
			advice = '建议立即扩容或清理资源'
		elif avg >= 70:
			trend = '需关注'
			advice = '建议进入容量观察列表'
		else:
			trend = '稳定'
			advice = '保持现有巡检频率'
		capacity.append({
			'host': _host_name(host_map.get(row['host_id'])),
			'metric': row['metric'].upper(),
			'average': avg,
			'points': row['points'],
			'trend': trend,
			'advice': advice,
		})
	return sorted(capacity, key=lambda row: row['average'], reverse=True)[:8]


def _runbooks():
	return [
		{'title': 'CPU 异常处置', 'trigger': 'CPU > 80% 或 CPU 告警聚合', 'steps': ['查看 top 进程', '确认近期发布/批量任务', '必要时重启异常服务或扩容']},
		{'title': '内存泄漏排查', 'trigger': '内存持续增长且未恢复', 'steps': ['查看进程 RSS', '检查应用日志 OOM', '保留现场后重启服务']},
		{'title': '磁盘空间治理', 'trigger': '磁盘 > 80% 或日志增长异常', 'steps': ['定位大文件', '清理过期日志', '评估分区扩容']},
		{'title': '自动化失败恢复', 'trigger': '命令、文件分发、发布任务失败', 'steps': ['检查 SSH 连通性', '确认账号权限', '重试前检查审批和策略拦截']},
	]


def _llm_endpoint(url):
	url = (url or '').strip().rstrip('/')
	if not url:
		return ''
	if url.endswith('/v1/chat/completions') or url.endswith('/chat/completions'):
		return url
	return '%s/v1/chat/completions' % url


def _alert_text(alert):
	labels = alert.get('labels') or {}
	annotations = alert.get('annotations') or {}
	return '\n'.join([
		'告警名称：%s' % (labels.get('alertname') or alert.get('alertname') or '未知'),
		'级别：%s' % (labels.get('severity') or 'unknown'),
		'实例：%s' % (labels.get('instance') or labels.get('host') or ''),
		'摘要：%s' % (annotations.get('summary') or annotations.get('description') or alert.get('summary') or ''),
		'详情：%s' % json.dumps(alert, ensure_ascii=False)[:2500],
	])


def _fallback_suggestion(alert):
	labels = alert.get('labels') or {}
	annotations = alert.get('annotations') or {}
	alert_name = labels.get('alertname') or alert.get('alertname') or '未知告警'
	severity = labels.get('severity') or 'unknown'
	instance = labels.get('instance') or labels.get('host') or '未知实例'
	summary = annotations.get('summary') or annotations.get('description') or ''
	return (
		'告警 %s（级别：%s，实例：%s）。建议先确认告警是否仍在触发，检查主机资源、服务状态和近期变更；'
		'如果是资源类告警，优先查看 CPU/内存/磁盘最高消耗项；如果是服务类告警，检查进程、端口、日志和最近发布。%s'
	) % (alert_name, severity, instance, summary)


def _call_llm(config, alert):
	endpoint = _llm_endpoint(config.llm_url)
	if not endpoint:
		return _fallback_suggestion(alert), '', '未配置大模型地址，已生成基础建议'
	prompt = (
		'你是资深 SRE/AIOps 分析助手。请分析下面 Alertmanager 告警，输出中文处理建议，'
		'包含：1. 告警含义；2. 可能根因；3. 排查步骤；4. 临时止血；5. 长期优化。'
		'不要编造不存在的指标。\n\n%s'
	) % _alert_text(alert)
	headers = {'Content-Type': 'application/json'}
	if config.llm_api_key:
		headers['Authorization'] = 'Bearer %s' % config.llm_api_key
	body = {
		'model': config.llm_model or 'gpt-4o-mini',
		'messages': [
			{'role': 'system', 'content': '你是可靠的智能运维告警分析助手。'},
			{'role': 'user', 'content': prompt},
		],
		'temperature': 0.2,
	}
	response = requests.post(endpoint, json=body, headers=headers, timeout=20)
	response_text = response.text[:4000]
	if response.status_code >= 400:
		return _fallback_suggestion(alert), response_text, '大模型接口返回 HTTP %s' % response.status_code
	data = response.json()
	content = ''
	try:
		content = data['choices'][0]['message']['content']
	except Exception:
		content = response_text
	return content or _fallback_suggestion(alert), response_text, ''


def _save_alert_analysis(alert, config):
	labels = alert.get('labels') or {}
	annotations = alert.get('annotations') or {}
	record = AiopsAlertAnalysis.objects.create(
		alert_name=labels.get('alertname') or alert.get('alertname') or '',
		severity=labels.get('severity') or '',
		instance=labels.get('instance') or labels.get('host') or '',
		raw_payload=json.dumps(alert, ensure_ascii=False),
		summary=annotations.get('summary') or annotations.get('description') or alert.get('summary') or '',
	)
	try:
		suggestion, llm_response, error = _call_llm(config, alert)
		record.suggestion = suggestion
		record.llm_response = llm_response
		record.error = error
		record.status = AiopsAlertAnalysis.STATUS_FAILED if error and llm_response else AiopsAlertAnalysis.STATUS_ANALYZED
	except Exception as exc:
		record.suggestion = _fallback_suggestion(alert)
		record.error = str(exc)
		record.status = AiopsAlertAnalysis.STATUS_FAILED
	record.save(update_fields=['suggestion', 'llm_response', 'error', 'status', 'updated_at'])
	return record


def _analysis_queryset_for_hosts(hosts):
	queryset = AiopsAlertAnalysis.objects.all()
	if hosts is None:
		return queryset
	terms = set([''])
	for host in hosts:
		for value in (host.linux_name, host.linux_ip, host.linux_hostname, host.linux_app):
			if value:
				terms.add(value)
	query = Q(instance='')
	for term in terms:
		if term:
			query |= Q(instance__icontains=term)
	return queryset.filter(query)


def _analysis_payload(item):
	return {
		'id': item.id,
		'alert_name': item.alert_name or '未知告警',
		'severity': item.severity or '-',
		'instance': item.instance or '-',
		'summary': item.summary or '-',
		'suggestion': item.suggestion or '-',
		'status': item.status,
		'error': item.error,
		'created_at': timezone.localtime(item.created_at).strftime('%m-%d %H:%M'),
	}


@session_login_required
def dashboard(request):
	hosts = list(visible_hosts_for_request(request).order_by('id'))
	open_alerts = list(AlertEvent.objects.select_related('host').filter(status=AlertEvent.STATUS_OPEN, host__in=hosts)[:50])
	failed_commands = list(CommandExecution.objects.select_related('host').filter(host__in=hosts, status=CommandExecution.STATUS_FAILED)[:30])
	latest_metrics = _latest_metric_map(hosts)
	anomalies = _build_anomalies(hosts, latest_metrics, open_alerts)
	correlations = _build_correlations(open_alerts, failed_commands)
	root_causes = _build_root_causes(correlations, anomalies)
	capacity = _build_capacity(hosts)
	config = AiopsIntegration.current()
	alert_analyses = _analysis_queryset_for_hosts(hosts)[:20]
	payload = {
		'updated_at': timezone.localtime(timezone.now()).strftime('%Y-%m-%d %H:%M:%S'),
		'counts': {
			'hosts': len(hosts),
			'open_alerts': len(open_alerts),
			'anomalies': len(anomalies),
			'correlations': len(correlations),
			'failed_commands': len(failed_commands),
			'notification_failures': NotificationLog.objects.filter(status=NotificationLog.STATUS_FAILED).count(),
		},
		'capabilities': [
			{'name': '异常检测', 'detail': '基于指标阈值、告警密度识别异常主机'},
			{'name': '事件关联', 'detail': '按主机聚合告警、命令失败和近期操作'},
			{'name': '根因分析', 'detail': '给出置信度、证据和处置方向'},
			{'name': '自动处置建议', 'detail': '把异常映射到运行手册和 DevOps 操作入口'},
			{'name': '容量预测', 'detail': '按历史指标均值识别扩容风险'},
			{'name': '通知治理', 'detail': '统计通知失败，辅助发现告警触达问题'},
		],
		'anomalies': anomalies,
		'correlations': correlations,
		'root_causes': root_causes,
		'capacity': capacity,
		'runbooks': _runbooks(),
		'integration': {
			'alertmanager_url': config.alertmanager_url,
			'llm_url': config.llm_url,
			'llm_model': config.llm_model,
			'llm_api_key_set': bool(config.llm_api_key),
			'enabled': config.enabled,
			'csrf': get_token(request),
			'webhook_url': request.build_absolute_uri('/aiops/webhook/'),
			'config_url': '/aiops/config/',
		},
		'alert_analyses': [_analysis_payload(item) for item in alert_analyses],
		'recent_changes': [
			{'action': item.action, 'target': item.target_type, 'detail': item.detail, 'created_at': timezone.localtime(item.created_at).strftime('%m-%d %H:%M')}
			for item in AuditLog.objects.all()[:8]
		],
	}
	return render(request, 'aiops/dashboard.html', {'aiops_payload': payload})


@session_login_required
def save_config(request):
	if request.method != 'POST':
		return HttpResponseNotAllowed(['POST'])
	config = AiopsIntegration.current()
	config.alertmanager_url = (request.POST.get('alertmanager_url') or '').strip()
	config.llm_url = (request.POST.get('llm_url') or '').strip()
	config.llm_model = (request.POST.get('llm_model') or '').strip() or 'gpt-4o-mini'
	config.enabled = request.POST.get('enabled') == 'on'
	api_key = (request.POST.get('llm_api_key') or '').strip()
	if api_key:
		config.llm_api_key = api_key
	config.updated_by = request.session.get('user_name', '')
	config.save()
	return redirect('aiops:dashboard')


@csrf_exempt
def alertmanager_webhook(request):
	if request.method != 'POST':
		return HttpResponseNotAllowed(['POST'])
	config = AiopsIntegration.current()
	if not config.enabled:
		return JsonResponse({'ok': False, 'message': 'AIOps 告警接入未启用'}, status=403)
	try:
		payload = json.loads(request.body.decode('utf-8') or '{}')
	except ValueError:
		return JsonResponse({'ok': False, 'message': 'JSON 解析失败'}, status=400)
	alerts = payload.get('alerts') if isinstance(payload, dict) else None
	if not alerts:
		alerts = [payload]
	records = [_save_alert_analysis(alert, config) for alert in alerts if isinstance(alert, dict)]
	return JsonResponse({
		'ok': True,
		'created': len(records),
		'ids': [record.id for record in records],
	})
