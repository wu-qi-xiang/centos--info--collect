import json

from django.core.serializers.json import DjangoJSONEncoder
from django.forms.models import model_to_dict
from django.shortcuts import render


def model_dict(obj, fields=None, exclude=None):
	if obj is None:
		return None
	data = model_to_dict(obj, fields=fields, exclude=exclude)
	if getattr(obj, 'id', None) is not None:
		data['id'] = obj.id
	return data


def form_errors(form):
	if not form:
		return []
	errors = []
	for field, messages in form.errors.items():
		label = field
		if field in form.fields:
			label = form.fields[field].label or field
		for message in messages:
			errors.append('%s：%s' % (label, message))
	return errors


def render_vue_page(request, kind, title, data=None, context=None, status=200):
	context = context or {}
	data = data or {}
	if data.get('errors') and not data.get('error_heading'):
		data['error_heading'] = '提交失败，请检查以下内容'
	payload = {
		'kind': kind,
		'title': title,
		'data': data,
	}
	context['vue_page_title'] = title
	context['vue_page_kind'] = kind
	context['vue_page_public'] = kind in ('auth-login', 'auth-register')
	context['vue_page_payload'] = json.dumps(payload, cls=DjangoJSONEncoder, ensure_ascii=False).replace('</', '<\\/')
	return render(request, 'vue/page.html', context, status=status)
