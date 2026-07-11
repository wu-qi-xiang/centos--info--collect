from django.core.paginator import Paginator
from django.shortcuts import get_object_or_404, render, redirect
from django.http import HttpResponse, HttpResponseNotAllowed, JsonResponse
from django.db.models import Q
from django.middleware.csrf import get_token
from django.urls import reverse


from PyLinux.crypto import decrypt_text, encrypt_text
from PyLinux.security import security_context
from PyLinux.vue import form_errors, model_dict, render_vue_page
from devops.services import audit
from .models import Password
from .forms import Password_manage
from userprofile.decorators import session_login_required

# Create your views here.


def _password_form_context(request, password=None, form=None):
	content = {
		'password': password,
		'form': form,
	}
	content.update(security_context(request))
	return content


def _current_user_passwords(request):
	return Password.objects.filter(auther=request.session.get('user_name')).order_by('id')


def _password_page_context(request, password_queryset, keyword=None):
	paginator = Paginator(password_queryset, 8)
	pages = paginator.get_page(request.GET.get('page'))
	pagenum = (pages.number - 1) * 8
	content = {
		'password': password_queryset,
		'pages': pages,
		'pagenum': pagenum,
		'sum': password_queryset.count(),
	}
	if keyword is not None:
		content['pwd'] = keyword
	content.update(security_context(request))
	return content


def _password_payload(item):
	return {
		'id': item.id,
		'system_name': item.system_name,
		'account': item.account,
		'remark': item.remark,
		'update_url': reverse('password:password_update', args=[item.id]),
		'reveal_url': reverse('password:password_reveal', args=[item.id]),
	}


def _render_password_list(request, password_queryset, keyword=None):
	content = _password_page_context(request, password_queryset, keyword)
	return render_vue_page(request, 'password-list', '凭据列表', {
		'subtitle': '按当前登录用户隔离凭据记录',
		'keyword': keyword or '',
		'passwords': [_password_payload(item) for item in content['pages']],
		'system_names': [item.system_name for item in content['pages']],
		'actions': [{'label': '新增凭据', 'url': reverse('password:password_create'), 'class': 'btn-primary'}],
	}, content)


def _render_password_form(request, title, action, password=None, form=None, status=200):
	context = _password_form_context(request, password, form)
	data = model_dict(password) or {}
	if request.method == 'POST':
		data.update({
			'system_name': request.POST.get('system_name') or data.get('system_name', ''),
			'account': request.POST.get('account', data.get('account', '')),
			'remark': request.POST.get('remark', data.get('remark', '')),
		})
	return render_vue_page(request, 'password-form', title, {
		'subtitle': '密码内容不会直接渲染到页面源码',
		'csrf': get_token(request),
		'action': action,
		'password': data,
		'keep_hint': '留空则保持原密码不变' if password else '',
		'errors': form_errors(form),
		'actions': [{'label': '返回凭据列表', 'url': reverse('password:password_manage')}],
	}, context, status=status)


@session_login_required
def credential_management(request):
	if request.method != "GET":
		return HttpResponseNotAllowed(["GET"])
	context = security_context(request)
	return render(request, 'password/credential_management.html', context)


@session_login_required
def password_manage(request):
	if request.method != "GET":
		return HttpResponseNotAllowed(["GET"])
	# 只显示当前用户管理的账号密码。
	password = _current_user_passwords(request)
	return _render_password_list(request, password)


@session_login_required
def password_create(request):
	if request.method == "POST":
		post_data = request.POST.copy()
		post_data['auther'] = request.session.get('user_name')
		post_data['password'] = encrypt_text(post_data.get('password'))
		passwd_manage = Password_manage(post_data)
		if passwd_manage.is_valid():
			password = passwd_manage.save()
			audit(request, '创建密码记录', 'Password', password.id, password.system_name)
			return redirect("password:password_manage")
		else:
			return _render_password_form(request, '新增凭据', reverse('password:password_create'), form=passwd_manage, status=400)
	else:
		return _render_password_form(request, '新增凭据', reverse('password:password_create'))


@session_login_required
def password_update(request, id):
	# 获取需要修改的具体文章对象
	password = get_object_or_404(Password, id=id, auther=request.session.get('user_name'))
	if request.method == "POST":
		# 将提交的数据赋值到表单实例中
		post_data = request.POST.copy()
		post_data['auther'] = request.session.get('user_name')
		if not post_data.get('password'):
			post_data['password'] = password.password
		passwd_info = Password_manage(post_data, instance=password)
		if passwd_info.is_valid():
			password = passwd_info.save(commit=False)
			new_password = request.POST.get("password", "")
			if new_password:
				password.password = encrypt_text(new_password)
			password.auther = request.session.get('user_name')
			password.save()
			audit(request, '更新密码记录', 'Password', password.id, password.system_name)
			return redirect("password:password_manage")
		else:
			return _render_password_form(request, '编辑凭据', reverse('password:password_update', args=[password.id]), password, passwd_info, status=400)
	else:
		return _render_password_form(request, '编辑凭据', reverse('password:password_update', args=[password.id]), password)


@session_login_required
def password_delete(request, id):
	if request.method != "POST":
		return HttpResponseNotAllowed(["POST"])
	password = get_object_or_404(Password, id=id, auther=request.session.get('user_name'))
	detail = password.system_name
	# 调用.delete()方法删除文章
	password.delete()
	audit(request, '删除密码记录', 'Password', id, detail)
	return redirect('password:password_manage')


@session_login_required
def password_search(request):
	if request.method != "GET":
		return HttpResponseNotAllowed(["GET"])
	pwd = (request.GET.get('search') or '').strip()
	password = _current_user_passwords(request)
	if pwd:
		password = password.filter(Q(system_name__icontains=pwd) | Q(account__icontains=pwd) | Q(remark__icontains=pwd))
	return _render_password_list(request, password, pwd)


@session_login_required
def password_reveal(request, id):
	if request.method != "POST":
		return HttpResponseNotAllowed(["POST"])
	password = get_object_or_404(Password, id=id, auther=request.session.get('user_name'))
	audit(request, '查看密码', 'Password', password.id, password.system_name)
	return JsonResponse({'password': decrypt_text(password.password)})
