#coding-utf-8
# 增加webssh功能
import csv
from dwebsocket.decorators import accept_websocket
from threading import Thread
import time
import socket
from urllib.parse import urlencode


from django.conf import settings
from django.middleware.csrf import get_token
from django.urls import reverse
from django.shortcuts import get_object_or_404, render, redirect
from django.http import HttpResponse, HttpResponseNotAllowed, JsonResponse
from django.core.paginator import Paginator
from django.db.models import Q
from PyLinux.crypto import decrypt_text, encrypt_text
from PyLinux.security import require_command_operator, require_host_access, require_host_operator, security_context
from PyLinux.vue import form_errors, model_dict, render_vue_page
from .collectors import collect_remote_detail
from .forms import LinuxPostForm
from .models import NewLinux
from .ssh_utils import create_host_ssh_client, create_ssh_client, describe_ssh_error
from devops.models import DevOpsHostScope, HostGroup
from devops.services import audit, has_explicit_admin_role, visible_hosts_for_request
from userprofile.decorators import session_login_required

# Create your views here.


def _host_form_context(request, linux_obj=None, form=None, linux_list=None):
    content = {
        'form': form,
        'linux': linux_obj,
    }
    if linux_list is not None:
        content['linux_list'] = linux_list
    content.update(security_context(request))
    return content


def _host_payload(host):
    return {
        'id': getattr(host, 'id', None),
        'linux_name': getattr(host, 'linux_name', ''),
        'linux_ip': getattr(host, 'linux_ip', ''),
        'linux_hostname': getattr(host, 'linux_hostname', ''),
        'linux_port': getattr(host, 'linux_port', '') or '22',
        'linux_user': getattr(host, 'linux_user', ''),
        'linux_auth_type': getattr(host, 'linux_auth_type', NewLinux.AUTH_PASSWORD),
        'linux_app': getattr(host, 'linux_app', ''),
	}


def _filter_hosts(queryset, keyword):
	keyword = (keyword or '').strip()
	if not keyword:
		return queryset
	return queryset.filter(
		Q(linux_name__icontains=keyword) |
		Q(linux_ip__icontains=keyword) |
		Q(linux_hostname__icontains=keyword) |
		Q(linux_app__icontains=keyword)
	)


def _pagination_payload(pages, keyword):
	query = {'search': keyword} if keyword else {}
	return {
		'current': pages.number,
		'total': pages.paginator.num_pages,
		'has_previous': pages.has_previous(),
		'has_next': pages.has_next(),
		'previous_url': ('?%s' % urlencode(dict(query, page=pages.previous_page_number()))) if pages.has_previous() else '',
		'next_url': ('?%s' % urlencode(dict(query, page=pages.next_page_number()))) if pages.has_next() else '',
	}


def _host_list_payload(request, pages, total, keyword, actions, subtitle):
	return {
		'subtitle': subtitle,
		'keyword': keyword,
		'search_action': reverse('linux_detail'),
		'hosts': [_host_payload(host) for host in pages],
		'total': total,
		'pagination': _pagination_payload(pages, keyword),
		'actions': actions,
	}


def _render_host_form(request, title, action, host=None, form=None, context=None, status=200):
    context = context or {}
    host_data = _host_payload(host or NewLinux())
    if request.method == 'POST':
        for field in ('linux_name', 'linux_ip', 'linux_hostname', 'linux_port', 'linux_user', 'linux_auth_type', 'linux_app'):
            host_data[field] = request.POST.get(field, host_data.get(field, ''))
    return render_vue_page(request, 'host-form', title, {
        'subtitle': '服务器资产使用 Vue 表单渲染，提交仍由 Django 后端校验',
        'csrf': get_token(request),
        'action': action,
        'host': host_data,
        'submitted_name': request.POST.get('linux_name', '') if request.method == 'POST' else '',
        'errors': form_errors(form),
        'password_hint': '留空则保持原密码不变',
        'actions': [{'label': '返回列表', 'url': reverse('linux_detail')}],
    }, context, status=status)


def _ensure_host_visible_to_user(request, host):
    if has_explicit_admin_role(request):
        return
    user_id = request.session.get('user_id')
    user_name = request.session.get('user_name') or 'user'
    if not user_id:
        return
    group_name = '个人主机-%s' % user_name
    group, _ = HostGroup.objects.get_or_create(
        name=group_name,
        defaults={'description': '自动收纳当前用户创建或导入的主机', 'created_by': user_name},
    )
    group.hosts.add(host)
    scope, _ = DevOpsHostScope.objects.get_or_create(user_id=user_id, defaults={'created_by': user_name})
    scope.groups.add(group)


def _decode_upload(file_obj):
    raw = file_obj.read()
    for encoding in ('utf-8-sig', 'utf-8', 'gbk'):
        try:
            return raw.decode(encoding)
        except UnicodeDecodeError:
            continue
    return raw.decode('utf-8', errors='ignore')


def _csv_rows_from_upload(file_obj):
    text = _decode_upload(file_obj)
    sample = text[:2048]
    try:
        dialect = csv.Sniffer().sniff(sample, delimiters=',\t;')
    except csv.Error:
        dialect = csv.excel
    return csv.DictReader(text.splitlines(), dialect=dialect)


IMPORT_FIELDS = (
    'linux_name',
    'linux_ip',
    'linux_hostname',
    'linux_port',
    'linux_user',
    'linux_passwd',
    'linux_auth_type',
    'linux_private_key',
    'linux_private_key_passphrase',
    'linux_app',
)


IMPORT_HEADER_ALIASES = {
    'linux_name': 'linux_name',
    'name': 'linux_name',
    '名称': 'linux_name',
    '主机名称': 'linux_name',
    '服务器名称': 'linux_name',
    'linux_ip': 'linux_ip',
    'ip': 'linux_ip',
    'IP': 'linux_ip',
    '主机IP': 'linux_ip',
    '服务器IP': 'linux_ip',
    '地址': 'linux_ip',
    'linux_hostname': 'linux_hostname',
    'hostname': 'linux_hostname',
    '主机名': 'linux_hostname',
    'linux_port': 'linux_port',
    'port': 'linux_port',
    '端口': 'linux_port',
    'SSH端口': 'linux_port',
    'linux_user': 'linux_user',
    'user': 'linux_user',
    'username': 'linux_user',
    '用户': 'linux_user',
    '用户名': 'linux_user',
    'SSH用户': 'linux_user',
    'linux_passwd': 'linux_passwd',
    'password': 'linux_passwd',
    'passwd': 'linux_passwd',
    '密码': 'linux_passwd',
    'SSH密码': 'linux_passwd',
    'linux_auth_type': 'linux_auth_type',
    'auth_type': 'linux_auth_type',
    '认证方式': 'linux_auth_type',
    '认证类型': 'linux_auth_type',
    'linux_private_key': 'linux_private_key',
    'private_key': 'linux_private_key',
    '私钥': 'linux_private_key',
    'SSH私钥': 'linux_private_key',
    'linux_private_key_passphrase': 'linux_private_key_passphrase',
    'private_key_passphrase': 'linux_private_key_passphrase',
    'passphrase': 'linux_private_key_passphrase',
    '私钥口令': 'linux_private_key_passphrase',
    'linux_app': 'linux_app',
    'app': 'linux_app',
    '应用': 'linux_app',
    '应用说明': 'linux_app',
    '备注': 'linux_app',
}


def _normalize_header(value):
    return str(value or '').strip().replace(' ', '').replace('_', '_')


def _normalize_import_row(row):
    normalized = {}
    for key, value in row.items():
        header = _normalize_header(key)
        field = IMPORT_HEADER_ALIASES.get(header) or IMPORT_HEADER_ALIASES.get(header.lower())
        if field:
            normalized[field] = (value or '').strip()
    return normalized


def _host_import_payload(request, errors=None, message=''):
    return {
        'subtitle': '上传 CSV 批量导入服务器资产',
        'csrf': get_token(request),
        'action': reverse('linux_import'),
        'errors': errors or [],
        'message': message,
        'fields': ','.join(IMPORT_FIELDS),
        'actions': [
            {'label': '下载模板', 'url': reverse('linux_import_template')},
            {'label': '返回列表', 'url': reverse('linux_detail')},
        ],
    }


def _encrypt_host_credentials(linux_obj, post_data):
    linux_obj.linux_auth_type = post_data.get('linux_auth_type') or NewLinux.AUTH_PASSWORD
    linux_obj.linux_passwd = encrypt_text(post_data.get('linux_passwd', ''))
    linux_obj.linux_private_key = encrypt_text(post_data.get('linux_private_key', ''))
    linux_obj.linux_private_key_passphrase = encrypt_text(post_data.get('linux_private_key_passphrase', ''))
    return linux_obj


def _update_host_credentials(linux, post_data, old_password='', old_private_key='', old_private_key_passphrase=''):
    linux.linux_auth_type = post_data.get('linux_auth_type') or NewLinux.AUTH_PASSWORD
    password = post_data.get('linux_passwd', '')
    if password:
        linux.linux_passwd = encrypt_text(password)
    else:
        linux.linux_passwd = old_password
    private_key = post_data.get('linux_private_key', '')
    passphrase = post_data.get('linux_private_key_passphrase', '')
    if private_key:
        linux.linux_private_key = encrypt_text(private_key)
    else:
        linux.linux_private_key = old_private_key
    if passphrase:
        linux.linux_private_key_passphrase = encrypt_text(passphrase)
    else:
        linux.linux_private_key_passphrase = old_private_key_passphrase
    if linux.linux_auth_type == NewLinux.AUTH_PASSWORD:
        linux.linux_private_key = ''
        linux.linux_private_key_passphrase = ''
    return linux


@session_login_required
def linux_create(request):
    denied = require_host_operator(request)
    if denied:
        return denied
    # 判断用户是否提交数据
    # 必须先实例化表单
    linux = NewLinux.objects.all()
    if request.method == "POST":
        # 将提交的数据赋值到表单实例中
        linux_form = LinuxPostForm(request.POST)
        # 判断提交的数据是否满足模型的要求
        if linux_form.is_valid():
            linux_obj = linux_form.save(commit=False)
            _encrypt_host_credentials(linux_obj, request.POST)
            linux_obj.save()
            _ensure_host_visible_to_user(request, linux_obj)
            audit(request, '创建主机', 'NewLinux', linux_obj.id, linux_obj.linux_name or linux_obj.linux_ip)
            return redirect("linux_detail")
        else:
            content = _host_form_context(request, NewLinux(), linux_form, linux)
            return _render_host_form(request, '新增服务器', reverse('linux_create'), NewLinux(), linux_form, content, status=400)
    else:
        form = NewLinux()
        # header.html跳转到url.py，然后跳转到view.py。
        content = _host_form_context(request, linux_obj=form, linux_list=linux)
        return _render_host_form(request, '新增服务器', reverse('linux_create'), form, context=content)


@session_login_required
def linux_update(request, id):
    # 获取需要修改的具体文章对象
    linux = get_object_or_404(NewLinux, id=id)
    denied = require_host_operator(request, linux)
    if denied:
        return denied
    if request.method == "POST":
        old_password = linux.linux_passwd
        old_private_key = linux.linux_private_key
        old_private_key_passphrase = linux.linux_private_key_passphrase
        # 将提交的数据赋值到表单实例中
        linux_info = LinuxPostForm(request.POST, instance=linux)
        if linux_info.is_valid():
            # 将更改的数据保存到数据库
            linux.linux_name = request.POST["linux_name"]
            linux.linux_ip = request.POST["linux_ip"]
            linux.linux_hostname = request.POST["linux_hostname"]
            linux.linux_port = request.POST["linux_port"]
            linux.linux_user = request.POST["linux_user"]
            _update_host_credentials(linux, request.POST, old_password, old_private_key, old_private_key_passphrase)
            linux.linux_app = request.POST["linux_app"]
            linux.save()
            audit(request, '更新主机', 'NewLinux', linux.id, linux.linux_name or linux.linux_ip)
            return redirect("linux_detail")
        else:
            linux.has_private_key = bool(old_private_key)
            content = _host_form_context(request, linux, linux_info)
            return _render_host_form(request, '编辑服务器', reverse('linux_update', args=[linux.id]), linux, linux_info, content, status=400)
    else:
        linux.has_private_key = bool(linux.linux_private_key)
        content = _host_form_context(request, linux)
        return _render_host_form(request, '编辑服务器', reverse('linux_update', args=[linux.id]), linux, context=content)


@session_login_required
def linux_copy(request):
    denied = require_host_operator(request)
    if denied:
        return denied
    if request.method != "POST":
        return HttpResponseNotAllowed(["POST"])
    if request.method == "POST":
        linux_form = LinuxPostForm(request.POST)
        if linux_form.is_valid():
            linux_obj = linux_form.save(commit=False)
            _encrypt_host_credentials(linux_obj, request.POST)
            linux_obj.save()
            _ensure_host_visible_to_user(request, linux_obj)
            audit(request, '复制主机', 'NewLinux', linux_obj.id, linux_obj.linux_name or linux_obj.linux_ip)
            return HttpResponse("复制成功")
        else:
            return JsonResponse({'status': 'error', 'errors': linux_form.errors}, status=400)



@session_login_required
def linux_delete(request, id):
    denied = require_host_operator(request)
    if denied:
        return denied
    if request.method != "POST":
        return HttpResponseNotAllowed(["POST"])
    # 根据 id 获取需要删除的文章
    linux = get_object_or_404(NewLinux, id=id)
    denied = require_host_access(request, linux)
    if denied:
        return denied
    detail = linux.linux_name or linux.linux_ip
    # 调用.delete()方法删除文章
    linux.delete()
    audit(request, '删除主机', 'NewLinux', id, detail)
    return redirect('linux_detail')


@session_login_required
def linux_list_app(request, id):
    linux = get_object_or_404(NewLinux, id=id)
    denied = require_host_access(request, linux)
    if denied:
        return denied
    content = {'linux': linux}
    content.update(security_context(request))
    return render_vue_page(request, 'host-detail', '应用信息', {
        'subtitle': linux.linux_name or linux.linux_ip,
        'items': [{'label': '应用说明', 'value': linux.linux_app or '-'}],
        'actions': [{'label': '返回列表', 'url': reverse('linux_detail')}],
    }, content)


@session_login_required
def linux_detail(request):
    if request.method != "GET":
        return HttpResponseNotAllowed(["GET"])
    keyword = (request.GET.get('search') or '').strip()
    newlinux = _filter_hosts(visible_hosts_for_request(request).order_by('id'), keyword)
    paginator = Paginator(newlinux, 8)
    page = request.GET.get('page')
    pages = paginator.get_page(page)
    pagenum = (pages.number - 1) * 8
    sum = newlinux.count()
    content = {'newlinux': newlinux, 'keyword': keyword, "pages": pages, "pagenum": pagenum, "sum": sum}
    content.update(security_context(request))
    actions = []
    if content.get('can_manage_hosts'):
        actions = [
            {'label': '导入服务器', 'url': reverse('linux_import')},
            {'label': '新增服务器', 'url': reverse('linux_create'), 'class': 'btn-primary'},
        ]
    return render_vue_page(
        request,
        'host-list',
        '服务器列表',
        _host_list_payload(request, pages, sum, keyword, actions, '管理授权范围内服务器'),
        content,
    )


@session_login_required
def linux_import(request):
    denied = require_host_operator(request)
    if denied:
        return denied
    if request.method == "GET":
        return render_vue_page(request, 'host-import', '导入服务器', _host_import_payload(request), security_context(request))
    if request.method != "POST":
        return HttpResponseNotAllowed(["GET", "POST"])
    upload = request.FILES.get('file')
    if not upload:
        return render_vue_page(request, 'host-import', '导入服务器', _host_import_payload(request, ['请选择 CSV 文件']), security_context(request), status=400)

    created = 0
    errors = []
    try:
        rows = _csv_rows_from_upload(upload)
        for index, row in enumerate(rows, start=2):
            normalized = _normalize_import_row(row)
            if not any(normalized.values()):
                continue
            data = {
                'linux_name': normalized.get('linux_name', ''),
                'linux_ip': normalized.get('linux_ip', ''),
                'linux_hostname': normalized.get('linux_hostname', ''),
                'linux_port': normalized.get('linux_port') or '22',
                'linux_user': normalized.get('linux_user', ''),
                'linux_passwd': normalized.get('linux_passwd', ''),
                'linux_auth_type': normalized.get('linux_auth_type') or NewLinux.AUTH_PASSWORD,
                'linux_private_key': normalized.get('linux_private_key', ''),
                'linux_private_key_passphrase': normalized.get('linux_private_key_passphrase', ''),
                'linux_app': normalized.get('linux_app', ''),
            }
            form = LinuxPostForm(data)
            if not form.is_valid():
                errors.append('第 %s 行：%s' % (index, '；'.join(form_errors(form))))
                continue
            host = form.save(commit=False)
            _encrypt_host_credentials(host, data)
            host.save()
            _ensure_host_visible_to_user(request, host)
            created += 1
            audit(request, '导入主机', 'NewLinux', host.id, host.linux_name or host.linux_ip)
    except csv.Error as exc:
        errors.append('CSV 解析失败：%s' % exc)

    if created == 0 and not errors:
        errors.append('没有可导入的数据，请检查表头或文件内容')

    if errors:
        return render_vue_page(
            request,
            'host-import',
            '导入服务器',
            _host_import_payload(request, errors, '已导入 %s 台，部分行失败' % created),
            security_context(request),
            status=400,
        )
    audit(request, '批量导入主机', 'NewLinux', '', '导入 %s 台' % created)
    return redirect('linux_detail')


@session_login_required
def linux_import_template(request):
    denied = require_host_operator(request)
    if denied:
        return denied
    response = HttpResponse(content_type='text/csv; charset=utf-8')
    response['Content-Disposition'] = 'attachment; filename="linux_hosts_template.csv"'
    response.write('\ufeff')
    writer = csv.writer(response)
    writer.writerow(('名称', 'IP', '主机名', '端口', '用户', '密码', '认证方式', '私钥', '私钥口令', '应用说明'))
    writer.writerow(('example-host', '192.168.1.10', 'example-host', '22', 'root', 'your-password', 'password', '', '', 'nginx'))
    return response


@session_login_required
def linux_list_detail(request, id):
    # 取出对应id的linux信息
    newlinux = get_object_or_404(NewLinux, id=id)
    denied = require_host_access(request, newlinux)
    if denied:
        return denied
    detail = {}
    collect_error = ''
    if request.GET.get('collect') == '1':
        ssh = None
        try:
            ssh = create_host_ssh_client(newlinux)
            detail = collect_remote_detail(ssh)
        except Exception as e:
            collect_error = describe_ssh_error(e)
        finally:
            if ssh:
                ssh.close()
    content = {'newlinux': newlinux,
               }
    content.update(detail)
    content.update(security_context(request))
    items = [
        {'label': '名称', 'value': newlinux.linux_name},
        {'label': 'IP', 'value': newlinux.linux_ip},
        {'label': '主机名', 'value': newlinux.linux_hostname},
        {'label': '端口', 'value': newlinux.linux_port},
        {'label': '用户', 'value': newlinux.linux_user},
        {'label': '认证方式', 'value': newlinux.get_linux_auth_type_display() if hasattr(newlinux, 'get_linux_auth_type_display') else newlinux.linux_auth_type},
        {'label': '应用说明', 'value': newlinux.linux_app},
    ]
    if detail:
        items.extend([
            {'label': 'CPU', 'value': detail.get('cpu')},
            {'label': '总内存', 'value': detail.get('total_mem')},
            {'label': '已用内存', 'value': detail.get('used_mem')},
            {'label': '系统版本', 'value': detail.get('release')},
            {'label': '内核', 'value': detail.get('kernel')},
            {'label': '内网 IP', 'value': detail.get('intranet_ip')},
            {'label': '总磁盘', 'value': detail.get('total_disk')},
            {'label': '已用磁盘', 'value': detail.get('used_disk')},
            {'label': '可用磁盘', 'value': detail.get('available_disk')},
        ])
    return render_vue_page(request, 'host-detail', '服务器详情', {
        'subtitle': newlinux.linux_name or newlinux.linux_ip,
        'items': items,
        'message': ('远程采集失败：%s' % collect_error) if collect_error else '',
        'actions': [
            {'label': '采集远程信息', 'url': '%s?collect=1' % reverse('linux_list_detail', args=[newlinux.id])},
            {'label': '编辑', 'url': reverse('linux_update', args=[newlinux.id])},
            {'label': 'WebSSH', 'url': reverse('linux_connect', args=[newlinux.id]), 'class': 'btn-primary'},
            {'label': '返回列表', 'url': reverse('linux_detail')},
        ],
    }, content)


@session_login_required
def connect_test(request):
    denied = require_host_operator(request)
    if denied:
        return denied
    if request.method == "POST":
        ip = request.POST.get('linux_ip')
        port = request.POST.get('linux_port')
        user = request.POST.get('linux_user')
        auth_type = request.POST.get('linux_auth_type') or NewLinux.AUTH_PASSWORD
        host_id = request.POST.get('host_id')
        saved_host = None
        if host_id:
            try:
                saved_host = NewLinux.objects.get(id=host_id)
            except NewLinux.DoesNotExist:
                saved_host = None

        passwd = request.POST.get('linux_passwd', '')
        private_key = request.POST.get('linux_private_key', '')
        passphrase = request.POST.get('linux_private_key_passphrase', '')
        if saved_host:
            denied = require_host_access(request, saved_host)
            if denied:
                return denied
            passwd = passwd or decrypt_text(saved_host.linux_passwd)
            private_key = private_key or decrypt_text(saved_host.linux_private_key)
            passphrase = passphrase or decrypt_text(saved_host.linux_private_key_passphrase)

        if not ip or not port or not user:
            return HttpResponse("输入有误，重新输入")
        if auth_type == NewLinux.AUTH_PASSWORD and not passwd:
            return HttpResponse("测试连接失败，请填写SSH密码")
        if auth_type == NewLinux.AUTH_KEY and not private_key:
            return HttpResponse("测试连接失败，请填写SSH私钥")

        ssh = None
        try:
            if auth_type == NewLinux.AUTH_KEY:
                ssh = create_ssh_client(ip, port, user, passwd, private_key=private_key, passphrase=passphrase)
            else:
                ssh = create_ssh_client(ip, port, user, passwd)
        except Exception as e:
            # return HttpResponse('{"status": "fail"}, {"message": "测试连接失败，请检查账号or密码orIPor端口"}')
            return HttpResponse("测试连接失败，%s" % describe_ssh_error(e))
        else:
            # return HttpResponse('{"status": "success"},{"message":"测试连接成功"}')
            return HttpResponse("测试连接成功")
        finally:
            if ssh:
                ssh.close()
    else:
        return HttpResponse("请求非post")


@session_login_required
def server_status(request, id):
    try:
        linux = NewLinux.objects.get(id=id)
    except NewLinux.DoesNotExist:
        return JsonResponse({'status': 'missing'}, status=404)
    denied = require_host_access(request, linux)
    if denied:
        return JsonResponse({'status': 'forbidden'}, status=403)
    ssh = None
    try:
        ssh = create_host_ssh_client(linux, timeout=3)
        return JsonResponse({'status': 'online'})
    except Exception as exc:
        return JsonResponse({'status': 'offline', 'message': describe_ssh_error(exc)})
    finally:
        if ssh:
            ssh.close()


@accept_websocket  # 用于websocket连接的修饰器
@session_login_required
def linux_connect(request, id):
    newlinux = get_object_or_404(NewLinux, id=id)
    denied = require_host_access(request, newlinux)
    if denied:
        return denied
    denied = require_command_operator(request)
    if denied:
        return denied
    
    # 初始化变量
    client = None
    sshsession = None
    started = time.time()
    timeout_seconds = getattr(settings, 'WEBSSH_SESSION_TIMEOUT_SECONDS', 1800)
    
    if request.is_websocket():  # 判断websocket连接
        # 打开ssh通道，建立长连接
        # 如果是websocket连接就创建ssh连接，使用paramiko模块创建
        Host = newlinux.linux_ip
        Port = newlinux.linux_port  # 修正变量名
        
        try:   # 用异常抛出判定主机是否成功连接ssh
            client = create_host_ssh_client(newlinux)
            mess = f'主机{Host}:{Port}连接成功！'
            audit(request, 'WebSSH连接成功', 'NewLinux', newlinux.id, '%s:%s' % (Host, Port))
            
            sshsession = client.get_transport().open_session()  # 成功连接后获取ssh通道
            sshsession.settimeout(1.0)
            sshsession.get_pty()  # 获取一个终端
            sshsession.invoke_shell()  # 激活终端
            
            for i in range(2):   # 激活终端后会有信息流，一般都是lastlogin与bath目录，并获取其数据
                try:
                    messa = sshsession.recv(1024)
                except socket.timeout:
                    continue
                if messa:
                    request.websocket.send(messa)
                
        except Exception as e:
            reason = describe_ssh_error(e)
            mess = f'主机{Host}:{Port}连接失败！错误: {reason}'
            audit(request, 'WebSSH连接失败', 'NewLinux', newlinux.id, reason)
            request.websocket.send(mess.encode('utf-8'))
            return
            
        # 从ssh通道获取输出data，并发送到前端
        def srecv():
            try:
                while True:
                    if timeout_seconds and time.time() - started > timeout_seconds:
                        return
                    if getattr(sshsession, 'closed', False):
                        return
                    if sshsession:
                        try:
                            sshmess = sshsession.recv(2048)
                        except socket.timeout:
                            continue
                        except Exception:
                            return
                        if not len(sshmess):
                            # print('退出监听发送循环')
                            return
                        request.websocket.send(sshmess)
                        # print('ssh回复的信息：' + sshmess.decode('utf-8'))
            except Exception as e:
                return

        sshrecvthre = Thread(target=srecv, args=())
        sshrecvthre.daemon = True
        sshrecvthre.start()

        # 获取前端的shelldata并且发送到服务器执行
        try:
            for shell in request.websocket:
                if not sshsession:
                    break
                if timeout_seconds and time.time() - started > timeout_seconds:
                    request.websocket.send('WebSSH会话已超时，连接即将关闭。'.encode('utf-8'))
                    audit(request, 'WebSSH会话超时', 'NewLinux', newlinux.id, '%s秒' % timeout_seconds)
                    break
                    
                deshell = shell.decode('utf-8')
                # print('deshell:'+deshell)
                sshsession.send(deshell)
                
        except Exception as e:
            audit(request, 'WebSSH处理异常', 'NewLinux', newlinux.id, str(e))
        finally:
            audit(request, 'WebSSH连接关闭', 'NewLinux', newlinux.id, '%s:%s' % (Host, Port))
            # 清理资源
            if sshsession:
                try:
                    sshsession.close()
                except:
                    pass
            if client:
                try:
                    client.close()
                except:
                    pass
    else:
        audit(request, '打开WebSSH页面', 'NewLinux', newlinux.id, newlinux.linux_name or newlinux.linux_ip)
        content = {'newlinux': newlinux}
        content.update(security_context(request))
        return render_vue_page(request, 'webssh', 'WebSSH', {
            'subtitle': newlinux.linux_name or newlinux.linux_ip,
            'ws_url': reverse('linux_connect', args=[newlinux.id]),
        }, content)
