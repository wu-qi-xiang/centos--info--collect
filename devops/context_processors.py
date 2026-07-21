from .models import DevOpsModulePermission, DevOpsRole
from .services import has_role


def devops_navigation(request):
    is_logged_in = bool(request.session.get('is_login'))
    return {
        'devops_navigation': {
            'can_view_cluster': is_logged_in and has_role(
                request,
                DevOpsRole.ROLE_VIEWER,
                DevOpsModulePermission.MODULE_CLUSTER,
            ),
            'can_manage_cluster': is_logged_in and has_role(
                request,
                DevOpsRole.ROLE_ADMIN,
                DevOpsModulePermission.MODULE_CLUSTER,
            ),
        },
    }
