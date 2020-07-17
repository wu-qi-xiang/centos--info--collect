from commands.services import CommandService
from django import template
from django.utils.safestring import mark_safe
from django.core.serializers.json import DjangoJSONEncoder
import json

register = template.Library()
service = CommandService()

@register.simple_tag(takes_context=True)
def commands(context):
    commands = service.get_available_definitions(context.request)
    content = {'commands': commands}
    return mark_safe(json.dumps(content, cls=DjangoJSONEncoder))