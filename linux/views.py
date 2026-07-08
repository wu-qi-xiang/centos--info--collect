from django.shortcuts import render, redirect
from django.http import HttpResponseNotAllowed
from django.core.paginator import Paginator
from PyLinux.security import security_context
from PyLinux.vue import render_vue_page
from RemoteLinux.models import NewLinux
from RemoteLinux.views import _filter_hosts, _host_list_payload
from password.models import Password
from devops.services import visible_hosts_for_request
from .collectors import collect_local_detail
from userprofile.decorators import session_login_required


# from . import models
# Create your views here.


@session_login_required
def index(request):
	pwd = Password.objects.filter(auther=request.session.get('user_name')).count()
	nwl = visible_hosts_for_request(request).count()
	content = {'nwl' : nwl, 'pwd' : pwd}
	content.update(security_context(request))
	return render_vue_page(request, 'dashboard', '工作台', {
		'subtitle': '服务器资产、密码与自动化入口',
		'counts': {'hosts': nwl, 'passwords': pwd},
		'actions': [
			{'label': '服务器列表', 'url': '/detail/'},
			{'label': '密码管理', 'url': '/password/'},
			{'label': 'DevOps', 'url': '/devops/', 'class': 'btn-primary'},
		],
	}, content)


@session_login_required
def linux(request):
	content = collect_local_detail()
	content.update(security_context(request))
	items = [
		{'label': 'CPU 核数', 'value': content.get('cpu')},
		{'label': '总内存', 'value': content.get('total_mem')},
		{'label': '已用内存', 'value': content.get('used_mem')},
		{'label': '可用内存', 'value': content.get('available_mem')},
		{'label': '系统版本', 'value': content.get('release')},
		{'label': '内核', 'value': content.get('kernel')},
		{'label': '内网 IP', 'value': content.get('intranet_ip')},
		{'label': '公网 IP', 'value': ', '.join(content.get('outside_ip') or []) or '未获取'},
		{'label': '总磁盘', 'value': content.get('total_disk')},
		{'label': '已用磁盘', 'value': content.get('used_disk')},
		{'label': '可用磁盘', 'value': content.get('available_disk')},
	]
	return render_vue_page(request, 'local-linux', '本机 Linux', {
		'subtitle': '本机系统信息',
		'items': items,
	}, content)


@session_login_required
def search(request):
	if request.method != "GET":
		return HttpResponseNotAllowed(["GET"])
	keyword = (request.GET.get('search') or '').strip()
	newlinux = _filter_hosts(visible_hosts_for_request(request).order_by('id'), keyword)
	paginator = Paginator(newlinux, 8)
	page = request.GET.get('page')
	pages = paginator.get_page(page)
	pagenum = (pages.number - 1) * 8
	# 增加主机总数
	sum = newlinux.count()

	content = {'newlinux': newlinux, 'keyword': keyword, "pages": pages, "pagenum": pagenum, "sum": sum}
	content.update(security_context(request))
	actions = []
	if content.get('can_manage_hosts'):
		actions = [
			{'label': '导入服务器', 'url': '/import/'},
			{'label': '新增服务器', 'url': '/create/', 'class': 'btn-primary'},
		]
	return render_vue_page(
		request,
		'host-list',
		'服务器列表',
		_host_list_payload(request, pages, sum, keyword, actions, '搜索和查看授权范围内服务器'),
		content,
	)


def _host_payload(host):
	return {
		'id': host.id,
		'linux_name': host.linux_name,
		'linux_ip': host.linux_ip,
		'linux_hostname': host.linux_hostname,
		'linux_port': host.linux_port,
		'linux_user': host.linux_user,
		'linux_auth_type': getattr(host, 'linux_auth_type', 'password'),
		'linux_app': host.linux_app,
	}
