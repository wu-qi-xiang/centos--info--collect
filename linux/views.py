import re

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


UNKNOWN_VALUE = '未获取'
CAPACITY_UNITS = (
	('TiB', 1024 ** 4),
	('GiB', 1024 ** 3),
	('MiB', 1024 ** 2),
	('KiB', 1024),
)


def _display_value(value):
	value = (value or '').strip()
	return value or UNKNOWN_VALUE


def _display_capacity(value, default_unit='B'):
	value = _display_value(value)
	if value == UNKNOWN_VALUE:
		return value
	normalized = value.replace(' ', '')
	match = re.match(r'^(\d+(?:\.\d+)?)([A-Za-z]*)$', normalized)
	if not match:
		return value
	number, unit = match.groups()
	unit_map = {
		'': default_unit,
		'b': 'B',
		'k': 'KB',
		'kb': 'KB',
		'ki': 'KiB',
		'kib': 'KiB',
		'm': 'MB',
		'mb': 'MB',
		'mi': 'MiB',
		'mib': 'MiB',
		'g': 'GB',
		'gb': 'GB',
		'gi': 'GiB',
		'gib': 'GiB',
		't': 'TB',
		'tb': 'TB',
		'ti': 'TiB',
		'tib': 'TiB',
	}
	display_unit = unit_map.get(unit.lower())
	if not display_unit:
		return value
	if display_unit == 'B':
		try:
			bytes_number = int(float(number))
		except ValueError:
			return value
		if bytes_number == 0:
			return '0 B'
		for label, size in CAPACITY_UNITS:
			if bytes_number >= size:
				amount = float(bytes_number) / size
				if amount.is_integer():
					amount = int(amount)
				else:
					amount = round(amount, 1)
				return '%s %s' % (amount, label)
		return '%s B' % bytes_number
	if number.endswith('.0'):
		number = number[:-2]
	return '%s %s' % (number, display_unit)


def _display_cpu(value):
	value = _display_value(value)
	if value == UNKNOWN_VALUE:
		return value
	if value.endswith('核'):
		return value
	return '%s 核' % value


def _display_typed(value, label):
	value = _display_value(value)
	if value == UNKNOWN_VALUE:
		return value
	suffix = '（%s）' % label
	if value.endswith(suffix):
		return value
	return '%s%s' % (value, suffix)


def _display_public_ips(values):
	items = []
	if isinstance(values, (list, tuple)):
		items = values
	else:
		value = _display_value(values)
		if value != UNKNOWN_VALUE:
			items = [part.strip() for part in value.split(',')]
	formatted = [_display_typed(item, 'IPv4') for item in items if _display_value(item) != UNKNOWN_VALUE]
	return ', '.join(formatted) or UNKNOWN_VALUE


# from . import models
# Create your views here.


@session_login_required
def index(request):
	pwd = Password.objects.filter(auther=request.session.get('user_name')).count()
	nwl = visible_hosts_for_request(request).count()
	content = {'nwl' : nwl, 'pwd' : pwd}
	content.update(security_context(request))
	return render_vue_page(request, 'dashboard', '工作台', {
		'subtitle': '资产、凭据与自动化入口',
		'counts': {'hosts': nwl, 'passwords': pwd},
		'actions': [
			{'label': '资产管理', 'url': '/assets/'},
			{'label': '凭据管理', 'url': '/password/credentials/'},
			{'label': 'DevOps', 'url': '/devops/', 'class': 'btn-primary'},
		],
	}, content)


@session_login_required
def asset_management(request):
	if request.method != "GET":
		return HttpResponseNotAllowed(["GET"])
	content = security_context(request)
	return render(request, 'linux/assets.html', content)


@session_login_required
def linux(request):
	content = collect_local_detail()
	content.update(security_context(request))
	items = [
		{'label': 'CPU 核数', 'value': _display_cpu(content.get('cpu'))},
		{'label': '总内存', 'value': _display_capacity(content.get('total_mem'))},
		{'label': '已用内存', 'value': _display_capacity(content.get('used_mem'))},
		{'label': '可用内存', 'value': _display_capacity(content.get('available_mem'))},
		{'label': '系统版本', 'value': _display_typed(content.get('release'), '发行版')},
		{'label': '内核', 'value': _display_typed(content.get('kernel'), '内核版本')},
		{'label': '内网 IP', 'value': _display_typed(content.get('intranet_ip'), 'IPv4')},
		{'label': '公网 IP', 'value': _display_public_ips(content.get('outside_ip'))},
		{'label': '总磁盘', 'value': _display_capacity(content.get('total_disk'))},
		{'label': '已用磁盘', 'value': _display_capacity(content.get('used_disk'))},
		{'label': '可用磁盘', 'value': _display_capacity(content.get('available_disk'))},
	]
	return render_vue_page(request, 'local-linux', '本地资产', {
		'subtitle': '本地资产系统信息',
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
		'资产列表',
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
