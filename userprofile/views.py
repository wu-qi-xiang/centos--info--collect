import secrets

from django.shortcuts import render, redirect
from django.contrib.auth.hashers import check_password, identify_hasher, make_password
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.middleware.csrf import get_token
from django.core.validators import validate_email
from django.utils.crypto import constant_time_compare
from django.utils import timezone

from PyLinux.vue import render_vue_page
from RemoteLinux.forms import UserForm
from RemoteLinux.models import User
from . import external_auth
# Create your views here.

LOGIN_FAILURE_LIMIT = 5
LOGIN_LOCK_SECONDS = 300


def is_password_hashed(password):
	try:
		identify_hasher(password)
		return True
	except ValueError:
		return False


def verify_user_password(user, raw_password):
	if is_password_hashed(user.password):
		return check_password(raw_password, user.password)
	return user.password == raw_password


def login_success(request, user):
	if not is_password_hashed(user.password):
		user.password = make_password(user.password)
		user.confirm_pwd = user.password
		user.save()
	request.session.cycle_key()
	request.session['is_login'] = True
	request.session['user_id'] = user.id
	request.session['user_name'] = user.user
	request.session.pop('login_failed_count', None)
	request.session.pop('login_locked_until', None)
	return redirect("index")


def login_locked(request):
	locked_until = request.session.get('login_locked_until')
	if not locked_until:
		return False
	now = int(timezone.now().timestamp())
	if int(locked_until) > now:
		return True
	request.session.pop('login_locked_until', None)
	request.session['login_failed_count'] = 0
	return False


def record_login_failure(request):
	failed_count = int(request.session.get('login_failed_count', 0) or 0) + 1
	request.session['login_failed_count'] = failed_count
	if failed_count >= LOGIN_FAILURE_LIMIT:
		request.session['login_locked_until'] = int(timezone.now().timestamp()) + LOGIN_LOCK_SECONDS


def login(request):
	if request.session.get('is_login', None):
		return redirect('index')

	if request.method == "POST":
		if login_locked(request):
			error_msg = "登录失败次数过多，请稍后再试"
			return _render_login(request, error_msg)
		puser = (request.POST.get("user") or '').strip()
		pwd = request.POST.get("pwd") or ''
		if not puser or not pwd:
			error_msg = "用户名和密码不能为空"
			return _render_login(request, error_msg)
		if not User.objects.exists():
			error_msg = "当前还没有注册用户，快去做第一个注册的人吧"
			return _render_login(request, error_msg)

		try:
			user_pwd = User.objects.get(user=puser)
		except User.DoesNotExist:
			record_login_failure(request)
			error_msg = "用户名不存在"
			return _render_login(request, error_msg)

		if verify_user_password(user_pwd, pwd):
			return login_success(request, user_pwd)

		record_login_failure(request)
		error_msg = "密码错误，请检查"
		return _render_login(request, error_msg)
	else:
		return _render_login(request)


def oidc_login_start(request):
	if request.session.get('is_login', None):
		return redirect('index')
	if not external_auth.oidc_is_available():
		return _render_login(request, '外部认证暂不可用')

	state = secrets.token_urlsafe(32)
	nonce = secrets.token_urlsafe(32)
	request.session['external_oidc_state'] = state
	request.session['external_oidc_nonce'] = nonce
	try:
		authorization_url = external_auth.build_oidc_authorization_url(state, nonce)
	except Exception:
		request.session.pop('external_oidc_state', None)
		request.session.pop('external_oidc_nonce', None)
		return _render_login(request, '外部认证暂不可用')
	return redirect(authorization_url)


def oidc_login_callback(request):
	# Pop before validation so a callback state can never be replayed.
	expected_state = request.session.pop('external_oidc_state', None)
	nonce = request.session.pop('external_oidc_nonce', None)
	provided_state = request.GET.get('state') or ''
	code = request.GET.get('code') or ''
	if not expected_state or not nonce or not code or not constant_time_compare(expected_state, provided_state):
		return _render_login(request, '外部认证失败，请重试')

	try:
		user = external_auth.authenticate_oidc_callback(request, code, nonce)
	except Exception:
		user = None
	if user is None:
		return _render_login(request, '外部认证失败，请重试')
	return login_success(request, user)


def ldap_login(request):
	if request.session.get('is_login', None):
		return redirect('index')
	if request.method != 'POST' or not external_auth.ldap_is_available():
		return _render_login(request, '外部认证暂不可用')

	username = (request.POST.get('username') or '').strip()
	password = request.POST.get('password') or ''
	if not username or not password:
		return _render_login(request, '外部认证失败，请重试')
	try:
		user = external_auth.authenticate_ldap(request, username, password)
	except Exception:
		user = None
	if user is None:
		return _render_login(request, '外部认证失败，请重试')
	return login_success(request, user)


def _render_login(request, error_msg=''):
	return render_vue_page(request, 'auth-login', '登录', {
		'subtitle': '进入 Linux 运维管理平台',
		'csrf': get_token(request),
		'errors': [error_msg] if error_msg else [],
		'form': {'user': (request.POST.get('user') or '').strip()},
		'external_auth': {
			'oidc_available': external_auth.oidc_is_available(),
			'ldap_available': external_auth.ldap_is_available(),
		},
	}, {'error': error_msg})


def index(request):
	return render(request, "linux/index.html")


def logout(request):
	request.session.flush()
	return redirect('userprofile:login')


def register(request):
	if request.method == "POST":
		user = (request.POST.get("user") or '').strip()
		email = (request.POST.get("email") or '').strip()
		pwd1 = request.POST.get("password") or ''
		pwd2 = request.POST.get("confirm_pwd") or ''
		if not user or not email or not pwd1 or not pwd2:
			error_msg = "用户名、邮箱和密码不能为空"
			return _render_register(request, error_msg)
		try:
			validate_email(email)
		except ValidationError:
			error_msg = "邮箱格式不正确"
			return _render_register(request, error_msg)
		if User.objects.filter(user=user).exists():
			error_msg = "用户名已经存在"
			return _render_register(request, error_msg)
		if User.objects.filter(email=email).exists():
			error_msg = "邮箱已经存在"
			return _render_register(request, error_msg)
		if pwd1 != pwd2:
			error_msg = "密码不一致，请重新设置"
			return _render_register(request, error_msg)
		try:
			validate_password(pwd1)
		except ValidationError as exc:
			error_msg = "密码强度不足：%s" % "；".join(exc.messages)
			return _render_register(request, error_msg)

		post_data = request.POST.copy()
		post_data["user"] = user
		post_data["email"] = email
		post_data["password"] = make_password(pwd1)
		post_data["confirm_pwd"] = post_data["password"]
		user_form = UserForm(post_data)
		if user_form.is_valid():
			user_form.save()
			error_msg = "注册成功，可以登录了"
			return _render_register(request, error_msg)

		error_msg = "注册信息有误，请重新输入"
		return _render_register(request, error_msg)
	else:
		return _render_register(request)


def _render_register(request, error_msg=''):
	return render_vue_page(request, 'auth-register', '注册', {
		'subtitle': '创建平台账号',
		'csrf': get_token(request),
		'errors': [error_msg] if error_msg else [],
		'form': {
			'user': (request.POST.get('user') or '').strip(),
			'email': (request.POST.get('email') or '').strip(),
		},
	}, {'error': error_msg})
