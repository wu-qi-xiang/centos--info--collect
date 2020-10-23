from django.shortcuts import render, redirect
from django.db.models import Q
from django.http import HttpResponse
import subprocess
import re
import urllib.request
from django.core.paginator import Paginator, PageNotAnInteger, EmptyPage, InvalidPage
from RemoteLinux.forms import LinuxPostForm, UserForm
from RemoteLinux.models import NewLinux, User


# from . import models
# Create your views here.

# def login(request):
# 	if request.session.get('is_login', None):
# 		return redirect('index')
#
# 	if request.method == "POST":
# 		puser = request.POST.get("user", None)
# 		pwd = request.POST.get("pwd", None)
# 		NweUser = User.objects.all()
# 		if len(NweUser) > 0:
# 			for userdata in NweUser:
# 				if userdata.user == puser:
# 					user_pwd = User.objects.get(user=puser)
# 					if user_pwd.password == pwd:
# 						request.session['is_login'] = True
# 						request.session['user_id'] = user_pwd.id
# 						request.session['user_name'] = user_pwd.user
# 						return redirect("index")
# 					else:
# 						error_msg = "密码错误，请检查"
# 						return render(request, "login.html", {"error": error_msg})
# 			error_msg = "用户名不存在"
# 			return render(request, "login.html", {"error": error_msg})
# 		else:
# 			error_msg = "当前还没有注册用户，快去做第一个注册的人吧"
# 			return render(request, "login.html", {"error": error_msg})
# 	else:
# 		return render(request, 'login.html')
#
#
# def index(request):
# 	return render(request, "linux/index.html")
#
#
# def logout(request):
# 	return render(request, 'login.html')
def index(request):
	return render(request, "linux/index.html")


def register(request):
	if request.method == "POST":
		NweUser = User.objects.all()
		user = request.POST.get("user")
		if len(NweUser) > 0:
			for userdata in NweUser:
				if userdata.user == user:
					error_msg = "用户名已经存在"
					return render(request, "register.html", {"error": error_msg})
			user_form = UserForm(request.POST)
			pwd1 = request.POST.get("password", None)
			pwd2 = request.POST.get("confirm_pwd", None)
			if user_form.is_valid() and pwd1 == pwd2:
				user_form.save()
				error_msg = "注册成功，可以登录了"
				return render(request, "register.html", {"error": error_msg})
			else:
				error_msg = "密码不一致，请重新设置"
				return render(request, "register.html", {"error": error_msg})
		else:
			user_form = UserForm(request.POST)
			pwd1 = request.POST.get("password", None)
			pwd2 = request.POST.get("confirm_pwd", None)
			if user_form.is_valid() and pwd1 == pwd2:
				user_form.save()
				error_msg = "注册成功，可以登录了"
				return render(request, "register.html", {"error": error_msg})
			else:
				error_msg = "密码不一致，请重新设置"
				return render(request, "register.html", {"error": error_msg})
			error_msg = "恭喜，第一个注册的用户"
			return render(request, "login.html", {"error": error_msg})
	else:
		return render(request, 'register.html')


def linux(request):
	# 系统cpu
	cpu_cmd = "lscpu |grep '^CPU(s)' |awk '{print $2}'"
	cpu = subprocess.getoutput(cpu_cmd)
	# 系统内存
	total_cmd = "free -h |grep Mem |awk '{print $2}'"
	used_cmd = "free -h |grep Mem |awk '{print $3}'"
	free_cmd = "free -h |grep Mem |awk '{print $4}'"
	available_cmd = "free -h |grep Mem |awk '{print $7}'"
	total_mem = subprocess.getoutput(total_cmd)
	used_mem = subprocess.getoutput(used_cmd)
	free_mem = subprocess.getoutput(free_cmd)
	available_mem = subprocess.getoutput(available_cmd)
	# 系统版本
	re_cmd = 'cat /etc/redhat-release'
	ke_cmd = "uname -a |awk '{print $3}'"
	release = subprocess.getoutput(re_cmd)
	kernel = subprocess.getoutput(ke_cmd)
	# 系统IP
	# outside_cmd = "curl ifconfig.me"
	url = urllib.request.urlopen("http://txt.go.sohu.com/ip/soip")
	text = url.read()
	intranet_cmd = "ip addr |grep eth0 |awk -F '/' 'NR == 2 {print $1}'|awk '{print $2}'"
	# outside_ip1 = subprocess.getoutput(outside_cmd)
	outside_ip = re.findall(r'\d+.\d+.\d+.\d+', text.decode('utf-8'))
	intranet_ip = subprocess.getoutput(intranet_cmd)
	# 系统磁盘
	total_cmd = "df -h |awk 'NR==2{print $2}'"
	used_cmd = "df -h |awk 'NR==2{print $3}'"
	available_cmd = "df -h |awk 'NR==2{print $4}'"
	total_disk = subprocess.getoutput(total_cmd)
	used_disk = subprocess.getoutput(used_cmd)
	available_disk = subprocess.getoutput(available_cmd)

	content = {'total_mem': total_mem,
			   'used_mem': used_mem,
			   'free_mem': free_mem,
			   'available_mem': available_mem,
			   'cpu': cpu,
			   'release': release,
			   'kernel': kernel,
			   'outside_ip': outside_ip,
			   'intranet_ip': intranet_ip,
			   'total_disk': total_disk,
			   'used_disk': used_disk,
			   'available_disk': available_disk}

	return render(request, 'linux/local.html', content)


def search(request):
	global search
	keyword = request.GET.get('search')
	if keyword:
		search = keyword
		newlinux = NewLinux.objects.filter(Q(linux_name__icontains=keyword) | Q(linux_ip__icontains=keyword) | Q(linux_hostname__icontains=keyword) | Q(linux_app__icontains=keyword))
	else:
		keyword = search
		newlinux = NewLinux.objects.filter(Q(linux_name__icontains=keyword) | Q(linux_ip__icontains=keyword) | Q(linux_hostname__icontains=keyword) | Q(linux_app__icontains=keyword))
	paginator = Paginator(newlinux, 8)
	if request.method == "GET":
		page = request.GET.get('page')
		try:
			pages = paginator.page(page)
		# todo: 注意捕获异常
		except PageNotAnInteger:
			# 如果请求的页数不是整数, 返回第一页。
			pages = paginator.page(1)
		except InvalidPage:
			# 如果请求的页数不存在, 重定向页面
			return HttpResponse('找不到页面的内容')
		except EmptyPage:
			# 如果请求的页数不在合法的页数范围内，返回结果的最后一页。
			pages = paginator.page(paginator.num_pages)
		pagenum = (pages.number - 1) * 8
		# 增加主机总数
		sum = 0
		for list in newlinux:
			sum = sum + 1

		content = {'newlinux': newlinux, 'keyword': keyword, "pages": pages, "pagenum": pagenum,"sum": sum}
		return render(request, 'linux/detail.html', content)
	else:
		return HttpResponse("非GET请求")
