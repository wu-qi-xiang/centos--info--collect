from django.http import HttpResponseForbidden

from devops.models import DevOpsModulePermission, DevOpsRole
from devops.services import audit, can_access_host, has_role


def require_role(request, minimum_role, module='', detail=''):
	if has_role(request, minimum_role, module):
		return None
	audit(request, '权限拒绝', module or 'LegacyView', '', detail or minimum_role)
	return HttpResponseForbidden('没有足够的权限')


def require_host_access(request, host):
	if can_access_host(request, host):
		return None
	audit(request, '主机范围拒绝', 'NewLinux', getattr(host, 'id', ''), getattr(host, 'linux_name', ''))
	return HttpResponseForbidden('目标主机不在当前用户授权范围内')


def require_host_operator(request, host=None):
	denied = require_role(
		request,
		DevOpsRole.ROLE_OPERATOR,
		DevOpsModulePermission.MODULE_SECURITY,
		'服务器资产管理',
	)
	if denied:
		return denied
	if host is not None:
		return require_host_access(request, host)
	return None


def require_monitor_operator(request):
	return require_role(
		request,
		DevOpsRole.ROLE_OPERATOR,
		DevOpsModulePermission.MODULE_ALERT,
		'监控告警配置',
	)


def require_command_operator(request):
	return require_role(
		request,
		DevOpsRole.ROLE_OPERATOR,
		DevOpsModulePermission.MODULE_COMMAND,
		'远程命令入口',
	)


def security_context(request):
	return {
		'can_manage_hosts': has_role(
			request,
			DevOpsRole.ROLE_OPERATOR,
			DevOpsModulePermission.MODULE_SECURITY,
		),
		'can_manage_monitor': has_role(
			request,
			DevOpsRole.ROLE_OPERATOR,
			DevOpsModulePermission.MODULE_ALERT,
		),
		'can_use_webssh': has_role(
			request,
			DevOpsRole.ROLE_OPERATOR,
			DevOpsModulePermission.MODULE_COMMAND,
		),
	}
