from .models import DevOpsModulePermission, DevOpsRole
from .services import has_role


def devops_navigation(request):
    is_logged_in = bool(request.session.get('is_login'))
    def can_view(module):
        return is_logged_in and has_role(request, DevOpsRole.ROLE_VIEWER, module)

    return {
        'devops_navigation': {
            'can_view_command': can_view(DevOpsModulePermission.MODULE_COMMAND),
            'can_view_task': can_view(DevOpsModulePermission.MODULE_TASK),
            'can_view_service': can_view(DevOpsModulePermission.MODULE_SERVICE),
            'can_view_file': can_view(DevOpsModulePermission.MODULE_FILE),
            'can_view_deployment': can_view(DevOpsModulePermission.MODULE_DEPLOYMENT),
            'can_view_approval': can_view(DevOpsModulePermission.MODULE_APPROVAL),
            'can_view_alert': can_view(DevOpsModulePermission.MODULE_ALERT),
            'can_view_metric': can_view(DevOpsModulePermission.MODULE_METRIC),
            'can_view_security': can_view(DevOpsModulePermission.MODULE_SECURITY),
            'can_view_audit': can_view(DevOpsModulePermission.MODULE_AUDIT),
            'can_view_cluster': can_view(DevOpsModulePermission.MODULE_CLUSTER),
            'can_manage_cluster': is_logged_in and has_role(
                request,
                DevOpsRole.ROLE_ADMIN,
                DevOpsModulePermission.MODULE_CLUSTER,
            ),
            'can_manage_k8s_service_discovery': is_logged_in and has_role(
                request,
                DevOpsRole.ROLE_ADMIN,
                DevOpsModulePermission.MODULE_CLUSTER,
            ) and has_role(
                request,
                DevOpsRole.ROLE_ADMIN,
                DevOpsModulePermission.MODULE_SERVICE,
            ),
        },
    }
