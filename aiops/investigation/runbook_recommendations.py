"""Controlled AIOps Runbook recommendations."""

from devops.models import RunbookTemplate
from devops.services import audit, can_access_host, initiate_runbook

from ..models import AiopsRunbookRecommendation


def create_runbook_recommendation(request, alert, runbook, summary=''):
	if not alert.host_id or not can_access_host(request, alert.host):
		raise PermissionError('目标主机不在当前用户授权范围内')
	if not runbook.enabled or not runbook.requires_approval:
		raise ValueError('建议必须关联已启用且需要审批的运行手册')
	if not runbook.allowed_hosts.filter(id=alert.host_id).exists():
		raise ValueError('目标主机不在运行手册授权范围内')
	if runbook.service_id and not runbook.service.hosts.filter(id=alert.host_id).exists():
		raise ValueError('目标主机不属于运行手册关联服务')
	recommendation, _created = AiopsRunbookRecommendation.objects.get_or_create(
		alert=alert,
		runbook=runbook,
		defaults={
			'host': alert.host,
			'summary': (summary or '')[:300],
			'created_by': request.session.get('user_name', ''),
		},
	)
	audit(request, '创建 AIOps 运行手册建议', 'AiopsRunbookRecommendation', recommendation.id, '运行手册=%s' % runbook.id)
	return recommendation


def initiate_runbook_recommendation(request, recommendation):
	if recommendation.status == AiopsRunbookRecommendation.STATUS_INITIATED:
		raise ValueError('建议已提交审批')
	if not can_access_host(request, recommendation.host):
		raise PermissionError('目标主机不在当前用户授权范围内')
	# initiate_runbook only creates a queued command and pending approval;
	# execution remains behind the existing approval decision.
	record, approval = initiate_runbook(request, recommendation.runbook, recommendation.host)
	recommendation.status = AiopsRunbookRecommendation.STATUS_INITIATED
	recommendation.initiated_approval = approval
	recommendation.save(update_fields=['status', 'initiated_approval', 'updated_at'])
	audit(request, '提交 AIOps 运行手册建议审批', 'AiopsRunbookRecommendation', recommendation.id, '审批=%s' % approval.id)
	return record, approval
