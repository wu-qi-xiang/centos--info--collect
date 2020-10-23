from django.shortcuts import render, redirect

from RemoteLinux.forms import UserForm
from RemoteLinux.models import User
# Create your views here.


def login(request):
	if request.session.get('is_login', None):
		return redirect('index')

	if request.method == "POST":
		puser = request.POST.get("user", None)
		pwd = request.POST.get("pwd", None)
		NweUser = User.objects.all()
		if len(NweUser) > 0:
			for userdata in NweUser:
				if userdata.user == puser:
					user_pwd = User.objects.get(user=puser)
					if user_pwd.password == pwd:
						request.session['is_login'] = True
						request.session['user_id'] = user_pwd.id
						request.session['user_name'] = user_pwd.user
						return redirect("index")
					else:
						error_msg = "密码错误，请检查"
						return render(request, "login.html", {"error": error_msg})
			error_msg = "用户名不存在"
			return render(request, "login.html", {"error": error_msg})
		else:
			error_msg = "当前还没有注册用户，快去做第一个注册的人吧"
			return render(request, "login.html", {"error": error_msg})
	else:
		return render(request, 'login.html')


def index(request):
	return render(request, "linux/index.html")


def logout(request):
	request.session['is_login']=False
	return render(request, 'login.html')


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