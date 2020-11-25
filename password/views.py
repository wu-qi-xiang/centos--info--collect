from django.shortcuts import render
from django.core.paginator import Paginator, PageNotAnInteger, EmptyPage, InvalidPage
from django.shortcuts import render, redirect
from django.http import HttpResponse
from django.db.models import Q


from .models import Password
from .forms import Password_manage

# Create your views here.


def password_manage(request):
	# 只显示当前用户管理的账号密码。
	password = Password.objects.filter(auther=request.session.get('user_name'))
	paginator = Paginator(password, 8)
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
	# 序号问题处理
	sum = 0
	for list in password:
		sum = sum + 1
	content = {'password': password, "pages": pages, "pagenum": pagenum, "sum": sum}
	return render(request, "password/password_manage.html", content)


def password_create(request):
	if request.method == "POST":
		passwd_manage = Password_manage(request.POST)
		print(passwd_manage)
		if passwd_manage.is_valid():
			# auther = request.user
			passwd_manage.save()
			return redirect("password:password_manage")
		else:
			return HttpResponse("输入有误，请重新输入")
	else:
		return render(request, "password/password_create.html")


def password_update(request, id):
	# 获取需要修改的具体文章对象
	password = Password.objects.get(id=id)
	if request.method == "POST":
		# 将提交的数据赋值到表单实例中
		passwd_info = Password_manage(request.POST)
		if passwd_info.is_valid():
			# 将更改的数据保存到数据库
			password.system_name = request.POST["system_name"]
			password.account = request.POST["account"]
			password.password = request.POST["password"]
			password.remark = request.POST["remark"]
			password.save()
			return redirect("password:password_manage")
		else:
			return HttpResponse("输入错误，请重新输入")
	else:
		# 将数据回填到界面
		content = {'password': password, }
		return render(request, 'password/password_update.html', content)


def password_delete(request, id):
	password = Password.objects.get(id=id)
	# 调用.delete()方法删除文章
	password.delete()
	return redirect('password:password_manage')


def password_search(request):
	global search
	pwd = request.GET.get('search')
	if pwd:
		search = pwd
		password = Password.objects.filter(Q(system_name__icontains=pwd) | Q(account__icontains=pwd) | Q(remark__icontains=pwd))
	else:
		pwd = search
		password = Password.objects.filter(Q(system_name__icontains=pwd) | Q(account__icontains=pwd) | Q(remark__icontains=pwd))
	paginator = Paginator(password, 8)
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
		for list in password:
			sum = sum + 1

		content = {'password': password, 'pwd': pwd, "pages": pages, "pagenum": pagenum,"sum": sum}
		return render(request, 'password/password_manage.html', content)
	else:
		return HttpResponse("非GET请求")
