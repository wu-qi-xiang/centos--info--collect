from collections import defaultdict
import json
import re
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
from django.urls import reverse
from django.views.decorators.csrf import csrf_exempt
from django.utils import timezone
from django.utils.dateparse import parse_datetime

from devops.models import AlertEvent, AuditLog, CommandExecution, DevOpsModulePermission, DevOpsRole, MetricSample, NotificationLog, RunbookTemplate, K8sCluster, K8sWorkloadServiceMapping, ApprovalRequest, RunbookHealthVerification, RunbookEffectivenessFeedback
from devops.api import alert_quality_governance_payload, visible_catalog_services
from devops.services import has_role, visible_hosts_for_request
from userprofile.decorators import session_login_required
from .analysis.change_impact import build_change_impacts
from .analysis.alert_groups import build_alert_groups
from .investigation.evidence_pack import build_evidence_pack
from .analysis.alert_quality import build_alert_quality_suggestions
from .investigation.investigation_timeline import build_investigation_timelines
from .runbook_effectiveness import build_runbook_effectiveness_suggestions
from .analysis.signal_freshness import build_signal_freshness
from .analysis.service_impact import build_service_impacts
from .analysis.service_workbench import build_service_workbench
from .analysis.reliability_score import build_service_reliability
from .models import AiopsAlertAnalysis, AiopsIntegration, AiopsRunbookRecommendation, AiopsInvestigation, AiopsInvestigationFeedback
from .investigation.investigations import build_investigation_result
from .investigation.k8s_analyzer import analyze_k8s_detail, safe_namespace
from .investigation.operator_mode import build_operator_scan
from .investigation.runbook_recommendations import create_runbook_recommendation, initiate_runbook_recommendation


SAFE_ALERT_LABELS = ('alertname', 'severity', 'instance', 'host', 'service', 'job', 'environment')
SAFE_ALERT_ANNOTATIONS = ('summary', 'description')
SAFE_ALERT_LIMITS = {
	'alertname': 200,
	'severity': 50,
	'instance': 200,
	'host': 200,
	'service': 200,
	'job': 200,
	'environment': 200,
	'summary': 1000,
	'description': 1500,
}
SAFE_IDENTIFIER_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._:-]*$')
SAFE_ANNOTATION_RE = re.compile(r'^[A-Za-z0-9\u4e00-\u9fff ，。；、（）()！!?%._-]+$')
ANNOTATION_WORD_RE = re.compile(r'[A-Za-z]+')
ANNOTATION_PAREN_RE = re.compile(r'\([^()]*\)')
SENSITIVE_ANNOTATION_RE = re.compile(
	r'\b(?:access\s+key|api[_ -]?(?:key|credential)|authorization|bearer|client\s+secret|credential(?:s)?|'
	r'password|private\s+key|secret(?:\s+key)?|token)\b',
	re.IGNORECASE,
)
SAFE_ANNOTATION_SUBJECTS = frozenset((
	'alert', 'api', 'application', 'cache', 'connection', 'container', 'cpu',
	'database', 'disk', 'error', 'host', 'latency', 'memory', 'network', 'nginx',
	'node', 'pod', 'process', 'redis', 'service', 'status',
))
SAFE_ANNOTATION_STATES = frozenset((
	'critical', 'degraded', 'down', 'failed', 'high', 'healthy', 'low', 'unavailable', 'up', 'warning',
))

DIAGNOSTIC_EVIDENCE_MODULES = {
	'alert': DevOpsModulePermission.MODULE_ALERT,
	'incident': DevOpsModulePermission.MODULE_ALERT,
	'metric_state': DevOpsModulePermission.MODULE_METRIC,
	'failed_command': DevOpsModulePermission.MODULE_COMMAND,
	'deployment_health': DevOpsModulePermission.MODULE_DEPLOYMENT,
	'ci_delivery': DevOpsModulePermission.MODULE_DEPLOYMENT,
}
DIAGNOSTIC_WINDOWS = {
	'6h': timezone.timedelta(hours=6),
	'24h': timezone.timedelta(hours=24),
}

INVESTIGATION_MODULES = (
	DevOpsModulePermission.MODULE_ALERT,
	DevOpsModulePermission.MODULE_METRIC,
	DevOpsModulePermission.MODULE_DEPLOYMENT,
	DevOpsModulePermission.MODULE_SERVICE,
)


def _investigation_permission_error(request):
	if not request.session.get('is_login') or not request.session.get('user_id'):
		return _diagnostic_api_error('未登录', 401, 'unauthorized')
	if not all(has_role(request, DevOpsRole.ROLE_VIEWER, module) for module in INVESTIGATION_MODULES):
		return _diagnostic_api_error('没有调查证据查看权限', 403, 'forbidden')
	return None


def k8s_analyzer(request, cluster_id):
	if not request.session.get('is_login') or not request.session.get('user_id'):
		return _diagnostic_api_error('未登录', 401, 'unauthorized')
	if not (has_role(request, DevOpsRole.ROLE_VIEWER, DevOpsModulePermission.MODULE_CLUSTER)
			and has_role(request, DevOpsRole.ROLE_VIEWER, DevOpsModulePermission.MODULE_SERVICE)):
		return _diagnostic_api_error('没有 Kubernetes 分析查看权限', 403, 'forbidden')
	cluster = K8sCluster.objects.filter(id=cluster_id).first()
	visible_services = visible_catalog_services(request)
	mappings = list(K8sWorkloadServiceMapping.objects.filter(cluster=cluster, service__in=visible_services)) if cluster else []
	if not cluster or not mappings:
		return _diagnostic_api_error('集群不存在或无权访问', 404, 'not_found')
	namespace = safe_namespace(request.GET.get('namespace'), cluster.default_namespace or 'default')
	if not namespace:
		return _diagnostic_api_error('命名空间无效', 400, 'validation_error')
	mappings = [mapping for mapping in mappings if mapping.namespace == namespace]
	if not mappings:
		return _diagnostic_api_error('集群不存在或无权访问', 404, 'not_found')
	refresh = request.GET.get('refresh') == '1'
	if refresh and not has_role(request, DevOpsRole.ROLE_ADMIN, DevOpsModulePermission.MODULE_CLUSTER):
		return _diagnostic_api_error('只有 Kubernetes 集群管理员可以刷新数据', 403, 'forbidden')
	try:
		result = analyze_k8s_detail(cluster, namespace, mappings=mappings, refresh=refresh)
	except (TimeoutError, ConnectionError):
		return _diagnostic_api_error('Kubernetes 数据源暂不可用', 503, 'source_unavailable')
	except Exception:
		return _diagnostic_api_error('Kubernetes 分析失败', 503, 'source_unavailable')
	return JsonResponse({'ok': True, 'result': result})


def operator_scan(request):
	if not request.session.get('is_login') or not request.session.get('user_id'):
		return _diagnostic_api_error('未登录', 401, 'unauthorized')
	modules = (DevOpsModulePermission.MODULE_ALERT, DevOpsModulePermission.MODULE_METRIC,
		DevOpsModulePermission.MODULE_DEPLOYMENT, DevOpsModulePermission.MODULE_SERVICE)
	if not all(has_role(request, DevOpsRole.ROLE_VIEWER, module) for module in modules):
		return _diagnostic_api_error('没有主动巡检查看权限', 403, 'forbidden')
	window = request.GET.get('window', '24h')
	if window not in ('6h', '24h', '7d'):
		return _diagnostic_api_error('时间窗口无效', 400, 'validation_error')
	hosts = list(visible_hosts_for_request(request))
	if not hosts:
		return _diagnostic_api_error('没有可见主机', 403, 'forbidden')
	return JsonResponse({'ok': True, 'result': build_operator_scan(hosts, list(visible_catalog_services(request)), window)})


def runbook_recommendation_outcome(request, recommendation_id):
	if not request.session.get('is_login') or not request.session.get('user_id'):
		return _diagnostic_api_error('未登录', 401, 'unauthorized')
	if not has_role(request, DevOpsRole.ROLE_VIEWER, DevOpsModulePermission.MODULE_COMMAND):
		return _diagnostic_api_error('没有运行手册查看权限', 403, 'forbidden')
	item = AiopsRunbookRecommendation.objects.select_related('initiated_approval', 'host', 'alert').filter(
		id=recommendation_id, host__in=visible_hosts_for_request(request)).first()
	if not item:
		return _diagnostic_api_error('运行手册建议不存在', 404, 'not_found')
	approval = item.initiated_approval
	payload = {'recommendation': {'id': item.id, 'status': item.status,
		'approval_id': approval.id if approval else None}, 'approval': None, 'execution': None,
		'health_verification': None, 'effectiveness_feedback': []}
	if approval:
		payload['approval'] = {'status': approval.status, 'created_at': approval.created_at.isoformat(),
			'decided_at': approval.decided_at.isoformat() if approval.decided_at else None}
		execution = approval.command_execution
		if execution:
			payload['execution'] = {'id': execution.id, 'status': execution.status,
				'created_at': execution.created_at.isoformat(), 'finished_at': execution.finished_at.isoformat() if execution.finished_at else None}
			verification = RunbookHealthVerification.objects.filter(command_execution=execution).first()
			if verification:
				payload['health_verification'] = {'status': verification.status, 'active_critical_alert_count': verification.active_critical_alert_count,
					'summary': verification.summary, 'verified_at': verification.verified_at.isoformat()}
		payload['effectiveness_feedback'] = [{'classification': feedback.classification, 'created_at': feedback.created_at.isoformat(),
				'author': feedback.created_by} for feedback in RunbookEffectivenessFeedback.objects.filter(command_execution=execution)[:20]]
	return JsonResponse({'ok': True, 'outcome': payload})


def _investigation_payload(item, result=None, include_detail=False):
	result = result or {}
	data = {
		'id': item.id,
		'title': item.title,
		'status': item.status,
		'window': {
			'key': item.window_key,
			'start': timezone.localtime(item.window_start).isoformat(),
			'end': timezone.localtime(item.window_end).isoformat(),
		},
		'scope': result.get('scope', {
			'host_count': item.hosts.count(), 'service_count': item.services.count(),
			'window_start': timezone.localtime(item.window_start).isoformat(),
			'window_end': timezone.localtime(item.window_end).isoformat(),
		}),
		'risk': item.risk,
		'confidence': item.confidence,
		'summary': item.summary,
		'root_cause_summary': item.root_cause_summary,
	}
	if include_detail:
		data.update({
			'root_causes': result.get('root_causes', []),
			'timeline': result.get('timeline', []),
			'partial': bool(result.get('partial', False)),
			'errors': result.get('errors', []),
		})
	return data


def _visible_investigation_queryset(request):
	visible_hosts = visible_hosts_for_request(request)
	visible_host_ids = set(visible_hosts.values_list('id', flat=True))
	visible_services = visible_catalog_services(request)
	visible_service_ids = set(visible_services.values_list('id', flat=True))
	items = []
	for item in list(AiopsInvestigation.objects.prefetch_related('hosts', 'services')[:200]):
		host_ids = {host.id for host in item._prefetched_objects_cache.get('hosts', ())}
		service_ids = {service.id for service in item._prefetched_objects_cache.get('services', ())}
		if not host_ids or not host_ids.issubset(visible_host_ids):
			continue
		if service_ids and not service_ids.issubset(visible_service_ids):
			continue
		items.append(item)
	return items, visible_hosts, visible_services


def _visible_investigation_detail(request, investigation_id):
	visible_hosts = visible_hosts_for_request(request)
	visible_services = visible_catalog_services(request)
	item = (AiopsInvestigation.objects.prefetch_related('hosts', 'services')
			.filter(id=investigation_id).first())
	if not item:
		return None, visible_hosts, visible_services
	hosts = list(item._prefetched_objects_cache.get('hosts', ()))
	services = list(item._prefetched_objects_cache.get('services', ()))
	visible_host_ids = set(visible_hosts.values_list('id', flat=True))
	visible_service_ids = set(visible_services.values_list('id', flat=True))
	if not hosts or not {host.id for host in hosts}.issubset(visible_host_ids):
		return None, visible_hosts, visible_services
	if not {service.id for service in services}.issubset(visible_service_ids):
		return None, visible_hosts, visible_services
	return item, visible_hosts, visible_services


def _parse_investigation_datetime(value):
	if not isinstance(value, str):
		return None
	parsed = parse_datetime(value)
	if parsed and timezone.is_naive(parsed):
		parsed = timezone.make_aware(parsed, timezone.get_current_timezone())
	return parsed


def investigation_feedback(request, investigation_id):
	err = _investigation_permission_error(request)
	if err: return err
	item, _hosts, _services = _visible_investigation_detail(request, investigation_id)
	if not item: return _diagnostic_api_error('调查不存在', 404, 'not_found')
	if request.method == 'GET':
		return JsonResponse({'ok': True, 'results': [{'classification': f.classification, 'note_present': bool(f.note), 'created_by': f.created_by, 'created_at': f.created_at.isoformat()} for f in item.feedback.all()[:20]]})
	if request.method != 'POST': return HttpResponseNotAllowed(['GET', 'POST'])
	try: payload = json.loads(request.body.decode('utf-8') or '{}')
	except (TypeError, ValueError, json.JSONDecodeError): return _diagnostic_api_error('JSON 格式错误', 400, 'invalid_json')
	classification = payload.get('classification'); note = payload.get('note', '')
	if classification not in dict(AiopsInvestigationFeedback.CLASSIFICATION_CHOICES) or not isinstance(note, str) or len(note) > 300:
		return _diagnostic_api_error('反馈无效', 400, 'validation_error')
	feedback = AiopsInvestigationFeedback.objects.create(investigation=item, classification=classification, note=note, created_by=str(request.session.get('user_name') or request.session.get('user_id') or ''))
	return JsonResponse({'ok': True, 'feedback': {'classification': feedback.classification, 'note_present': bool(feedback.note), 'created_by': feedback.created_by, 'created_at': feedback.created_at.isoformat()}}, status=201)


def investigations(request, investigation_id=None):
	permission_error = _investigation_permission_error(request)
	if permission_error:
		return permission_error
	if investigation_id is not None:
		if request.method != 'GET':
			return HttpResponseNotAllowed(['GET'])
		item, visible_hosts, visible_services = _visible_investigation_detail(request, investigation_id)
		if not item:
			return _diagnostic_api_error('调查不存在', 404, 'not_found')
		hosts = list(item._prefetched_objects_cache.get('hosts', ()))
		services = list(item._prefetched_objects_cache.get('services', ()))
		result = build_investigation_result(item, hosts, services)
		return JsonResponse({'ok': True, 'investigation': _investigation_payload(item, result, True)})
	if request.method == 'GET':
		items, _visible_hosts, _visible_services = _visible_investigation_queryset(request)
		return JsonResponse({'ok': True, 'results': [_investigation_payload(item) for item in items]})
	if request.method != 'POST':
		return HttpResponseNotAllowed(['GET', 'POST'])
	try:
		payload = json.loads(request.body.decode('utf-8') or '{}')
	except (TypeError, ValueError, json.JSONDecodeError):
		return _diagnostic_api_error('JSON 格式错误', 400, 'invalid_json')
	if not isinstance(payload, dict):
		return _diagnostic_api_error('JSON 格式错误', 400, 'invalid_json')
	title = payload.get('title')
	window_key = payload.get('window_key', '24h')
	host_ids = payload.get('host_ids')
	service_ids = payload.get('service_ids', [])
	start = _parse_investigation_datetime(payload.get('window_start'))
	end = _parse_investigation_datetime(payload.get('window_end'))
	if not isinstance(title, str) or not title.strip() or len(title.strip()) > 200:
		return _diagnostic_api_error('调查标题无效', 400, 'validation_error')
	if window_key not in dict(AiopsInvestigation.WINDOW_CHOICES):
		return _diagnostic_api_error('时间窗口无效', 400, 'validation_error')
	if not isinstance(host_ids, list) or not host_ids:
		return _diagnostic_api_error('至少选择一台主机', 400, 'validation_error')
	if not isinstance(service_ids, list):
		return _diagnostic_api_error('服务范围无效', 400, 'validation_error')
	try:
		host_ids = [int(value) for value in host_ids]
		service_ids = [int(value) for value in service_ids]
	except (TypeError, ValueError):
		return _diagnostic_api_error('主机或服务范围无效', 400, 'validation_error')
	if not start or not end or start >= end:
		return _diagnostic_api_error('时间窗口无效', 400, 'validation_error')
	now = timezone.now()
	if end > now + timezone.timedelta(minutes=5):
		return _diagnostic_api_error('时间窗口无效', 400, 'validation_error')
	window_limit = {
		'1h': timezone.timedelta(hours=1), '6h': timezone.timedelta(hours=6),
		'24h': timezone.timedelta(hours=24), '7d': timezone.timedelta(days=7),
	}[window_key]
	if end - start > window_limit + timezone.timedelta(minutes=5):
		return _diagnostic_api_error('时间窗口无效', 400, 'validation_error')
	visible_hosts = visible_hosts_for_request(request)
	hosts = list(visible_hosts.filter(id__in=host_ids))
	if len(hosts) != len(set(host_ids)):
		return _diagnostic_api_error('主机不存在或无权访问', 404, 'not_found')
	visible_services = visible_catalog_services(request)
	services = list(visible_services.filter(id__in=service_ids))
	if len(services) != len(set(service_ids)):
		return _diagnostic_api_error('服务不存在或无权访问', 404, 'not_found')
	item = AiopsInvestigation.objects.create(
		created_by=str(request.session.get('user_name') or request.session.get('user_id') or ''),
		title=title.strip(), window_key=window_key, window_start=start, window_end=end,
		status=AiopsInvestigation.STATUS_ANALYZING,
	)
	item.hosts.set(hosts)
	item.services.set(services)
	result = build_investigation_result(item, hosts, services, now=end)
	causes = result.get('root_causes', [])
	confidence = max([int(cause.get('confidence', 0)) for cause in causes] or [0])
	risk = (AiopsInvestigation.RISK_CRITICAL if confidence >= 85 else
		AiopsInvestigation.RISK_HIGH if confidence >= 70 else
		AiopsInvestigation.RISK_MEDIUM if confidence >= 45 else AiopsInvestigation.RISK_LOW)
	item.status = AiopsInvestigation.STATUS_PARTIAL if result.get('partial') else AiopsInvestigation.STATUS_COMPLETED
	item.confidence = confidence
	item.risk = risk
	item.summary = str(result.get('summary', ''))[:1000]
	item.root_cause_summary = '; '.join(str(cause.get('summary', '')) for cause in causes)[:2000]
	item.save(update_fields=['status', 'confidence', 'risk', 'summary', 'root_cause_summary', 'updated_at'])
	return JsonResponse({'ok': True, 'investigation': _investigation_payload(item, result, True)}, status=201)


def _runbook_recommendation_payload(item):
	return {
		'id': item.id,
		'alert_id': item.alert_id,
		'host_id': item.host_id,
		'runbook_id': item.runbook_id,
		'summary': item.summary,
		'status': item.status,
		'approval_id': item.initiated_approval_id,
		'created_by': item.created_by,
		'created_at': timezone.localtime(item.created_at).isoformat(),
	}


@session_login_required
def runbook_recommendations(request):
	if not has_role(request, DevOpsRole.ROLE_VIEWER, DevOpsModulePermission.MODULE_COMMAND):
		return _diagnostic_api_error('没有运行手册建议查看权限', 403, 'forbidden')
	hosts = visible_hosts_for_request(request)
	queryset = AiopsRunbookRecommendation.objects.select_related('alert', 'host', 'runbook').filter(host__in=hosts)
	if request.method == 'GET':
		return JsonResponse({'ok': True, 'results': [_runbook_recommendation_payload(item) for item in queryset[:100]]})
	if request.method != 'POST':
		return HttpResponseNotAllowed(['GET', 'POST'])
	if not has_role(request, DevOpsRole.ROLE_OPERATOR, DevOpsModulePermission.MODULE_COMMAND):
		return _diagnostic_api_error('没有运行手册建议操作权限', 403, 'forbidden')
	try:
		payload = json.loads(request.body.decode('utf-8') or '{}')
		alert = AlertEvent.objects.select_related('host').get(id=int(payload.get('alert_id')))
		runbook = RunbookTemplate.objects.get(id=int(payload.get('runbook_id')))
	except (ValueError, TypeError, json.JSONDecodeError, AlertEvent.DoesNotExist, RunbookTemplate.DoesNotExist):
		return _diagnostic_api_error('告警或运行手册无效', 400, 'validation_error')
	if alert.host_id not in set(hosts.values_list('id', flat=True)):
		return _diagnostic_api_error('目标主机不在当前用户授权范围内', 403, 'host_forbidden')
	summary = payload.get('summary', '')
	if not isinstance(summary, str) or len(summary) > 300:
		return _diagnostic_api_error('建议摘要无效', 400, 'validation_error')
	try:
		item = create_runbook_recommendation(request, alert, runbook, summary.strip())
	except PermissionError as exc:
		return _diagnostic_api_error(str(exc), 403, 'host_forbidden')
	except ValueError as exc:
		return _diagnostic_api_error(str(exc), 400, 'validation_error')
	return JsonResponse({'ok': True, 'recommendation': _runbook_recommendation_payload(item)}, status=201)


@session_login_required
def runbook_recommendation_initiate(request, recommendation_id):
	if request.method != 'POST':
		return HttpResponseNotAllowed(['POST'])
	if not has_role(request, DevOpsRole.ROLE_OPERATOR, DevOpsModulePermission.MODULE_COMMAND):
		return _diagnostic_api_error('没有运行手册建议操作权限', 403, 'forbidden')
	item = AiopsRunbookRecommendation.objects.select_related('host', 'runbook').filter(
		host__in=visible_hosts_for_request(request), id=recommendation_id,
	).first()
	if not item:
		return _diagnostic_api_error('运行手册建议不存在', 404, 'not_found')
	try:
		record, approval = initiate_runbook_recommendation(request, item)
	except PermissionError as exc:
		return _diagnostic_api_error(str(exc), 403, 'host_forbidden')
	except ValueError as exc:
		return _diagnostic_api_error(str(exc), 400, 'validation_error')
	except Exception:
		# Keep command/SSH details out of the AIOps response.
		return _diagnostic_api_error('运行手册建议提交失败', 400, 'initiation_failed')
	return JsonResponse({'ok': True, 'requires_approval': True, 'recommendation': _runbook_recommendation_payload(item), 'command_execution_id': record.id, 'approval_id': approval.id}, status=202)


def _diagnostic_api_error(message, status, code):
	return JsonResponse({'ok': False, 'code': code, 'message': message}, status=status)


def diagnostic_evidence(request):
	"""Return scoped, permission-filtered diagnostic evidence without side effects."""
	if request.method != 'GET':
		return _diagnostic_api_error('仅支持 GET 请求', 405, 'method_not_allowed')
	if not request.session.get('is_login') or not request.session.get('user_id'):
		return _diagnostic_api_error('未登录', 401, 'unauthorized')
	window_key = request.GET.get('window', '24h')
	window_delta = DIAGNOSTIC_WINDOWS.get(window_key)
	host_id = request.GET.get('host_id', '')
	if not window_delta or not str(host_id).isdigit():
		return _diagnostic_api_error('主机或时间窗口无效', 400, 'validation_error')
	visible_hosts = visible_hosts_for_request(request)
	selected_host = visible_hosts.filter(pk=int(host_id)).first()
	if not selected_host:
		return _diagnostic_api_error('主机不存在或无权访问', 404, 'not_found')
	allowed_modules = set(
		module for module in set(DIAGNOSTIC_EVIDENCE_MODULES.values())
		if has_role(request, DevOpsRole.ROLE_VIEWER, module)
	)
	if not allowed_modules:
		return _diagnostic_api_error('没有诊断证据查看权限', 403, 'forbidden')
	window_end = timezone.now()
	pack = build_evidence_pack(
		selected_host, visible_hosts, window_end - window_delta, window_end,
	)
	evidence = [
		item for item in pack['evidence']
		if DIAGNOSTIC_EVIDENCE_MODULES.get(item.get('kind')) in allowed_modules
	]
	return JsonResponse({
		'ok': True,
		'host_id': selected_host.id,
		'window': window_key,
		'window_start': pack['window_start'],
		'window_end': pack['window_end'],
		'evidence': evidence,
	})


def alert_groups(request):
	"""Return visible alert-group analysis without changing alert lifecycle."""
	if request.method != 'GET':
		return _diagnostic_api_error('仅支持 GET 请求', 405, 'method_not_allowed')
	if not request.session.get('is_login') or not request.session.get('user_id'):
		return _diagnostic_api_error('未登录', 401, 'unauthorized')
	if not has_role(request, DevOpsRole.ROLE_VIEWER, DevOpsModulePermission.MODULE_ALERT):
		return _diagnostic_api_error('没有告警分组查看权限', 403, 'forbidden')
	window_key = request.GET.get('window', '24h')
	window_delta = DIAGNOSTIC_WINDOWS.get(window_key)
	if not window_delta:
		return _diagnostic_api_error('时间窗口无效', 400, 'validation_error')
	return JsonResponse({
		'ok': True,
		'window': window_key,
		'results': build_alert_groups(
			list(visible_hosts_for_request(request)), timezone.now() - window_delta, timezone.now(),
		),
	})


def signal_freshness(request):
	"""Return scoped metric-signal freshness without collecting new samples."""
	if request.method != 'GET':
		return _diagnostic_api_error('仅支持 GET 请求', 405, 'method_not_allowed')
	if not request.session.get('is_login') or not request.session.get('user_id'):
		return _diagnostic_api_error('未登录', 401, 'unauthorized')
	if not has_role(request, DevOpsRole.ROLE_VIEWER, DevOpsModulePermission.MODULE_METRIC):
		return _diagnostic_api_error('没有监控信号查看权限', 403, 'forbidden')
	window_key = request.GET.get('window', '24h')
	if window_key not in DIAGNOSTIC_WINDOWS:
		return _diagnostic_api_error('时间窗口无效', 400, 'validation_error')
	return JsonResponse({
		'ok': True,
		'window': window_key,
		'results': build_signal_freshness(
			list(visible_hosts_for_request(request)), now=timezone.now(),
		),
	})


def service_impacts(request):
	"""Return host-scoped service impact summaries without changing DevOps state."""
	if request.method != 'GET':
		return _diagnostic_api_error('仅支持 GET 请求', 405, 'method_not_allowed')
	if not request.session.get('is_login') or not request.session.get('user_id'):
		return _diagnostic_api_error('未登录', 401, 'unauthorized')
	if not has_role(request, DevOpsRole.ROLE_VIEWER, DevOpsModulePermission.MODULE_SERVICE):
		return _diagnostic_api_error('没有服务影响查看权限', 403, 'forbidden')
	window_key = request.GET.get('window', '24h')
	if window_key not in DIAGNOSTIC_WINDOWS:
		return _diagnostic_api_error('时间窗口无效', 400, 'validation_error')
	visible_hosts = visible_hosts_for_request(request)
	window_end = timezone.now()
	return JsonResponse({
		'ok': True,
		'window': window_key,
		'results': build_service_impacts(
			visible_catalog_services(request).prefetch_related('hosts', 'upstream_links'),
			list(visible_hosts), now=window_end,
			window_start=window_end - DIAGNOSTIC_WINDOWS[window_key], window_end=window_end,
		),
	})


def service_workbench(request, service_id):
	"""Return one bounded, host-scoped service investigation payload."""
	if request.method != 'GET':
		return _diagnostic_api_error('仅支持 GET 请求', 405, 'method_not_allowed')
	if not request.session.get('is_login') or not request.session.get('user_id'):
		return _diagnostic_api_error('未登录', 401, 'unauthorized')
	if not has_role(request, DevOpsRole.ROLE_VIEWER, DevOpsModulePermission.MODULE_SERVICE):
		return _diagnostic_api_error('没有服务事件工作区查看权限', 403, 'forbidden')
	window_key = request.GET.get('window', '24h')
	window_delta = DIAGNOSTIC_WINDOWS.get(window_key)
	if not window_delta:
		return _diagnostic_api_error('时间窗口无效', 400, 'validation_error')
	service = visible_catalog_services(request).filter(pk=service_id).first()
	if not service:
		return _diagnostic_api_error('服务不存在或无权访问', 404, 'not_found')
	window_end = timezone.now()
	try:
		result = build_service_workbench(
			service, list(visible_hosts_for_request(request)),
			window_end - window_delta, window_end,
		)
	except ValueError:
		return _diagnostic_api_error('服务不存在或无权访问', 404, 'not_found')
	return JsonResponse({
		'ok': True,
		'window': window_key,
		'window_start': timezone.localtime(window_end - window_delta).strftime('%Y-%m-%d %H:%M:%S'),
		'window_end': timezone.localtime(window_end).strftime('%Y-%m-%d %H:%M:%S'),
		**result,
	})


def service_reliability(request):
	"""Return scoped, read-only reliability scores for catalog services."""
	if request.method != 'GET':
		return _diagnostic_api_error('仅支持 GET 请求', 405, 'method_not_allowed')
	if not request.session.get('is_login') or not request.session.get('user_id'):
		return _diagnostic_api_error('未登录', 401, 'unauthorized')
	if not has_role(request, DevOpsRole.ROLE_VIEWER, DevOpsModulePermission.MODULE_SERVICE):
		return _diagnostic_api_error('没有服务可靠性查看权限', 403, 'forbidden')
	windows = {'24h': timezone.timedelta(hours=24), '7d': timezone.timedelta(days=7), '30d': timezone.timedelta(days=30)}
	window_key = request.GET.get('window', '24h')
	if window_key not in windows:
		return _diagnostic_api_error('时间窗口无效', 400, 'validation_error')
	window_end = timezone.now()
	return JsonResponse({'ok': True, 'window': window_key, 'results': build_service_reliability(
		visible_catalog_services(request).prefetch_related('hosts'),
		list(visible_hosts_for_request(request)), window_end - windows[window_key], window_end,
		now=window_end,
	)})


def _normalize_identifier(value, limit):
	value = ''.join(char for char in str(value or '') if ord(char) >= 32 and ord(char) != 127).strip()
	if not SAFE_IDENTIFIER_RE.match(value):
		return ''
	return value[:limit]


def _normalize_annotation(value, limit):
	value = ''.join(char for char in str(value or '') if ord(char) >= 32 and ord(char) != 127).strip()
	if not SAFE_ANNOTATION_RE.match(value) or SENSITIVE_ANNOTATION_RE.search(value):
		return ''
	words = ANNOTATION_WORD_RE.findall(value)
	if words:
		base = ANNOTATION_PAREN_RE.sub('', value)
		base_words = [word.lower() for word in ANNOTATION_WORD_RE.findall(base)]
		if (
			len(base_words) < 2 or
			base_words[0] not in SAFE_ANNOTATION_SUBJECTS or
			base_words[-1] not in SAFE_ANNOTATION_STATES
		):
			return ''
	return value[:limit]


def sanitize_alert(alert):
	"""Extract the only Alertmanager fields permitted for storage or LLM analysis."""
	alert = alert if isinstance(alert, dict) else {}
	labels = alert.get('labels') if isinstance(alert.get('labels'), dict) else {}
	annotations = alert.get('annotations') if isinstance(alert.get('annotations'), dict) else {}
	safe_labels = {}
	for key in SAFE_ALERT_LABELS:
		value = labels.get(key)
		if value in (None, '') and key == 'alertname':
			value = alert.get('alertname')
		if value in (None, '') and key in SAFE_ALERT_ANNOTATIONS:
			value = alert.get(key)
		if value not in (None, ''):
			normalized = _normalize_identifier(value, SAFE_ALERT_LIMITS[key])
			if normalized:
				safe_labels[key] = normalized
	safe_annotations = {}
	for key in SAFE_ALERT_ANNOTATIONS:
		value = annotations.get(key)
		if value in (None, '') and key == 'summary':
			value = alert.get('summary')
		if value not in (None, ''):
			normalized = _normalize_annotation(value, SAFE_ALERT_LIMITS[key])
			if normalized:
				safe_annotations[key] = normalized
	return {'labels': safe_labels, 'annotations': safe_annotations}


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


def _runbooks(request, hosts):
	"""AIOps only suggests safe identifiers; it cannot initiate a runbook."""
	if not has_role(request, DevOpsRole.ROLE_VIEWER, DevOpsModulePermission.MODULE_COMMAND):
		return []
	return [
		{'id': item.id, 'name': item.name, 'version': item.version, 'initiate_url': reverse('devops:runbooks')}
		for item in RunbookTemplate.objects.filter(
			enabled=True, requires_approval=True, allowed_hosts__in=hosts,
		).distinct().order_by('name', '-version', 'id')[:20]
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
		'服务：%s' % labels.get('service', ''),
		'环境：%s' % labels.get('environment', ''),
		'详情：%s' % annotations.get('description', ''),
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
		return _fallback_suggestion(alert), '未配置大模型地址，已生成基础建议'
	prompt = (
		'你是资深 SRE/AIOps 分析助手。请分析下面 Alertmanager 告警，输出中文处理建议，'
		'包含：1. 告警含义；2. 可能根因；3. 排查步骤；4. 临时止血；5. 长期优化。'
		'不要编造不存在的指标。\n\n%s'
	) % _alert_text(alert)
	headers = {'Content-Type': 'application/json'}
	if config.decrypted_llm_api_key:
		headers['Authorization'] = 'Bearer %s' % config.decrypted_llm_api_key
	body = {
		'model': config.llm_model or 'gpt-4o-mini',
		'messages': [
			{'role': 'system', 'content': '你是可靠的智能运维告警分析助手。'},
			{'role': 'user', 'content': prompt},
		],
		'temperature': 0.2,
	}
	response = requests.post(endpoint, json=body, headers=headers, timeout=20)
	if response.status_code >= 400:
		return _fallback_suggestion(alert), '大模型接口返回 HTTP %s' % response.status_code
	# Provider output is never persisted or rendered. The local suggestion is the
	# bounded, deterministic contract for all success and failure paths.
	return _fallback_suggestion(alert), ''


def _save_alert_analysis(alert, config):
	alert = sanitize_alert(alert)
	labels = alert['labels']
	annotations = alert['annotations']
	record = AiopsAlertAnalysis.objects.create(
		alert_name=labels.get('alertname') or alert.get('alertname') or '',
		severity=labels.get('severity') or '',
		instance=labels.get('instance') or labels.get('host') or '',
		raw_payload='',
		summary=annotations.get('summary') or annotations.get('description') or alert.get('summary') or '',
	)
	try:
		suggestion, error = _call_llm(config, alert)
		record.suggestion = suggestion
		record.llm_response = ''
		record.error = error
		record.status = AiopsAlertAnalysis.STATUS_ANALYZED
	except Exception:
		record.suggestion = _fallback_suggestion(alert)
		record.error = '大模型分析失败，已生成基础建议'
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
	if request.method == 'POST':
		return save_config(request)
	hosts = list(visible_hosts_for_request(request).order_by('id'))
	open_alerts = list(AlertEvent.objects.select_related('host').filter(status=AlertEvent.STATUS_OPEN, host__in=hosts)[:50])
	failed_commands = list(CommandExecution.objects.select_related('host').filter(host__in=hosts, status=CommandExecution.STATUS_FAILED)[:30])
	latest_metrics = _latest_metric_map(hosts)
	anomalies = _build_anomalies(hosts, latest_metrics, open_alerts)
	correlations = _build_correlations(open_alerts, failed_commands)
	root_causes = _build_root_causes(correlations, anomalies)
	capacity = _build_capacity(hosts)
	change_impacts = build_change_impacts(request, open_alerts, failed_commands, hosts)
	alert_quality_suggestions = build_alert_quality_suggestions(hosts)
	investigation_timelines = build_investigation_timelines(hosts)
	runbook_effectiveness_suggestions = (
		build_runbook_effectiveness_suggestions(hosts)
		if has_role(request, DevOpsRole.ROLE_VIEWER, DevOpsModulePermission.MODULE_COMMAND)
		else []
	)
	config = AiopsIntegration.current()
	alert_analyses = _analysis_queryset_for_hosts(hosts)[:20]
	investigation_access = all(
		has_role(request, DevOpsRole.ROLE_VIEWER, module) for module in INVESTIGATION_MODULES
	)
	investigation_services = list(visible_catalog_services(request)) if investigation_access else []
	k8s_access = (has_role(request, DevOpsRole.ROLE_VIEWER, DevOpsModulePermission.MODULE_CLUSTER)
		and has_role(request, DevOpsRole.ROLE_VIEWER, DevOpsModulePermission.MODULE_SERVICE))
	k8s_clusters = []
	if k8s_access:
		k8s_clusters = list(K8sCluster.objects.filter(
			service_workload_mappings__service__in=visible_catalog_services(request)
		).distinct())
	operator_access = all(has_role(request, DevOpsRole.ROLE_VIEWER, module) for module in (
		DevOpsModulePermission.MODULE_ALERT, DevOpsModulePermission.MODULE_METRIC,
		DevOpsModulePermission.MODULE_DEPLOYMENT, DevOpsModulePermission.MODULE_SERVICE))
	payload = {
		'updated_at': timezone.localtime(timezone.now()).strftime('%Y-%m-%d %H:%M:%S'),
		'counts': {
			'hosts': len(hosts),
			'open_alerts': len(open_alerts),
			'anomalies': len(anomalies),
			'correlations': len(correlations),
			'failed_commands': len(failed_commands),
			'notification_failures': NotificationLog.objects.filter(status=NotificationLog.STATUS_FAILED).count(),
			'change_impacts': len(change_impacts),
			'alert_quality_suggestions': len(alert_quality_suggestions),
			'investigation_timelines': len(investigation_timelines),
			'runbook_effectiveness_suggestions': len(runbook_effectiveness_suggestions),
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
		'change_impacts': change_impacts,
		'alert_quality_suggestions': alert_quality_suggestions,
		'investigation_timelines': investigation_timelines,
		'investigations_endpoint': (
			reverse('aiops:api_investigations') if investigation_access else None
		),
		'investigation_feedback_endpoint_template': (
			reverse('aiops:api_investigation_feedback', args=[999999]).replace('999999', '{investigation_id}')
			if investigation_access else None
		),
		'investigation_scope': {
			'hosts': [{'id': host.id, 'name': _host_name(host)} for host in hosts],
			'services': [{'id': service.id, 'name': service.name} for service in investigation_services],
		},
		'k8s_analyzer_endpoint_template': (
			reverse('aiops:api_k8s_analyzer', args=[999999]).replace('999999', '{cluster_id}')
			if k8s_access else None
		),
		'k8s_analyzer_can_refresh': has_role(
			request, DevOpsRole.ROLE_ADMIN, DevOpsModulePermission.MODULE_CLUSTER,
		),
		'k8s_clusters': [{'id': cluster.id, 'name': cluster.name, 'default_namespace': cluster.default_namespace}
			for cluster in k8s_clusters],
		'operator_scan_endpoint': reverse('aiops:api_operator_scan') if operator_access else None,
		'runbook_recommendations_endpoint': (
			reverse('aiops:api_runbook_recommendations')
			if has_role(request, DevOpsRole.ROLE_VIEWER, DevOpsModulePermission.MODULE_COMMAND) else None
		),
		'runbook_recommendation_initiate_endpoint_template': (
			reverse('aiops:api_runbook_recommendation_initiate', args=[999999]).replace(
				'999999', '{recommendation_id}'
			)
			if has_role(request, DevOpsRole.ROLE_OPERATOR, DevOpsModulePermission.MODULE_COMMAND) else None
		),
	'runbook_effectiveness_suggestions': runbook_effectiveness_suggestions,
		'runbooks': _runbooks(request, hosts),
		'diagnostic_evidence': {
			'endpoint': reverse('aiops:api_diagnostic_evidence'),
			'hosts': [
				{'id': host.id, 'name': _host_name(host)}
				for host in hosts
			],
		},
		'alert_groups_endpoint': (
			reverse('aiops:api_alert_groups')
			if has_role(request, DevOpsRole.ROLE_VIEWER, DevOpsModulePermission.MODULE_ALERT)
			else None
		),
		'alert_quality_governance_endpoint': (
			reverse('aiops:api_alert_quality_governance')
			if has_role(request, DevOpsRole.ROLE_VIEWER, DevOpsModulePermission.MODULE_ALERT)
			else None
		),
		'alert_quality_governance_review_endpoint_template': (
			reverse('devops:api_alert_quality_governance_review', args=['__suggestion_key__']).replace(
				'__suggestion_key__', '{suggestion_key}'
			)
			if has_role(request, DevOpsRole.ROLE_OPERATOR, DevOpsModulePermission.MODULE_ALERT)
			else None
		),
		'signal_freshness_endpoint': (
			reverse('aiops:api_signal_freshness')
			if has_role(request, DevOpsRole.ROLE_VIEWER, DevOpsModulePermission.MODULE_METRIC)
			else None
		),
		'service_impacts_endpoint': (
			reverse('aiops:api_service_impacts')
			if has_role(request, DevOpsRole.ROLE_VIEWER, DevOpsModulePermission.MODULE_SERVICE)
			else None
		),
		'service_reliability_endpoint': (
			reverse('aiops:api_service_reliability')
			if has_role(request, DevOpsRole.ROLE_VIEWER, DevOpsModulePermission.MODULE_SERVICE)
			else None
		),
		'service_workbench_endpoint_template': (
			reverse('aiops:api_service_workbench', args=[999999]).replace('999999', '{service_id}')
			if has_role(request, DevOpsRole.ROLE_VIEWER, DevOpsModulePermission.MODULE_SERVICE)
			else None
		),
		'capacity_cost_simulation_endpoint': (
			reverse('devops:api_capacity_cost_simulation')
			if (has_role(request, DevOpsRole.ROLE_OPERATOR, DevOpsModulePermission.MODULE_METRIC)
				and has_role(request, DevOpsRole.ROLE_OPERATOR, DevOpsModulePermission.MODULE_SERVICE))
			else None
		),
		'integration': {
			'alertmanager_configured': bool(config.alertmanager_url),
			'llm_configured': bool(config.llm_url),
			'llm_api_key_set': bool(config.llm_api_key),
			'enabled': config.enabled,
			'can_manage': has_role(
				request, DevOpsRole.ROLE_ADMIN, DevOpsModulePermission.MODULE_ALERT,
			),
			'csrf': get_token(request),
		},
		'alert_analyses': [_analysis_payload(item) for item in alert_analyses],
		'recent_changes': [
			{'action': item.action, 'target': item.target_type, 'detail': item.detail, 'created_at': timezone.localtime(item.created_at).strftime('%m-%d %H:%M')}
			for item in AuditLog.objects.all()[:8]
		],
	}
	return render(request, 'aiops/dashboard.html', {'aiops_payload': payload})


@session_login_required
def alert_quality_governance(request):
	"""Return scoped, read-only alert-quality governance aggregates."""
	if request.method != 'GET':
		return JsonResponse({'ok': False, 'code': 'method_not_allowed', 'message': '仅支持 GET 请求'}, status=405)
	if not has_role(request, DevOpsRole.ROLE_VIEWER, DevOpsModulePermission.MODULE_ALERT):
		return JsonResponse({'ok': False, 'code': 'forbidden', 'message': '没有告警查看权限'}, status=403)
	return JsonResponse({'ok': True, **alert_quality_governance_payload(request)})


@session_login_required
def save_config(request):
	if request.method != 'POST':
		return HttpResponseNotAllowed(['POST'])
	if not has_role(request, DevOpsRole.ROLE_ADMIN, DevOpsModulePermission.MODULE_ALERT):
		return JsonResponse({'ok': False, 'code': 'forbidden', 'message': '没有 AIOps 配置管理权限'}, status=403)
	config = AiopsIntegration.current()
	alertmanager_url = (request.POST.get('alertmanager_url') or '').strip()
	llm_url = (request.POST.get('llm_url') or '').strip()
	if alertmanager_url:
		config.alertmanager_url = alertmanager_url
	if llm_url:
		config.llm_url = llm_url
	llm_model = (request.POST.get('llm_model') or '').strip()
	if llm_model:
		config.llm_model = llm_model
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
