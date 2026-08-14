"""Business operations for incident postmortem action items."""

from django.utils import timezone

from ..models import IncidentActionItem
from ..services import audit


def is_overdue(item, now=None):
    now = now or timezone.now()
    return bool(
        item.due_at and item.due_at < now
        and item.status not in (IncidentActionItem.STATUS_COMPLETED, IncidentActionItem.STATUS_CANCELLED)
    )


def create_action_item(request, incident, title, description='', assignee=None,
                       priority=IncidentActionItem.PRIORITY_MEDIUM, due_at=None):
    item = IncidentActionItem.objects.create(
        incident=incident,
        title=title,
        description=description,
        assignee=assignee,
        priority=priority,
        due_at=due_at,
        created_by=request.session.get('user_name', ''),
    )
    audit(request, '创建事件复盘行动项', 'IncidentActionItem', item.id, item.title)
    return item


def update_action_item(request, item, values):
    changed = []
    for field in ('title', 'description', 'assignee', 'priority', 'due_at'):
        if field in values:
            setattr(item, field, values[field])
            changed.append(field)
    if not changed:
        return item
    item.save(update_fields=changed + ['updated_at'])
    audit(request, '更新事件复盘行动项', 'IncidentActionItem', item.id, ','.join(changed))
    return item


def update_action_status(request, item, status):
    item.status = status
    item.completed_at = timezone.now() if status == IncidentActionItem.STATUS_COMPLETED else None
    item.save(update_fields=['status', 'completed_at', 'updated_at'])
    audit(request, '更新事件复盘行动项状态', 'IncidentActionItem', item.id, status)
    return item


def delete_action_item(request, item):
    item_id = item.id
    item.delete()
    audit(request, '删除事件复盘行动项', 'IncidentActionItem', item_id)

