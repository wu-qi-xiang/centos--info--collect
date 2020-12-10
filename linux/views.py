from django.shortcuts import render, redirect
from django.db.models import Q
from django.http import HttpResponse
import subprocess
import re
import urllib.request
from django.core.paginator import Paginator, PageNotAnInteger, EmptyPage, InvalidPage
# 增加柱状图
import matplotlib.pyplot as plt
from matplotlib.font_manager import *
from RemoteLinux.models import NewLinux
from password.models import Password


# from . import models
# Create your views here.


def index(request):
	# 增加柱状图
	pwd = Password.objects.filter(auther=request.session.get('user_name')).count()
	passwd = Password.objects.all().count()
	nwl = NewLinux.objects.all().count()
	plt.switch_backend('agg')
	plt.figure(figsize=(5, 3.37))
	plt.style.use('seaborn')
	myfont = FontProperties(fname='./static/Font/simhei.ttf')
	width = 0.3
	# 增加矩形图
	rects1 = plt.bar('1', pwd, width=width)
	rects2 = plt.bar('2', passwd, width=width)
	rects3 = plt.bar('3', nwl, width=width)
	# 增加矩形上的数字

	def add_labels(rects):
		for rect in rects:
			height = rect.get_height()
			plt.text(rect.get_x() + rect.get_width() / 2, height, height, ha='center', va='bottom')
			# rect.set_edgecolor('white')
	add_labels(rects1)
	add_labels(rects2)
	add_labels(rects3)
	plt.title(u'服务器信息', fontproperties=myfont)
	plt.xlabel(u'名称', fontproperties=myfont)
	plt.ylabel(u'数量', fontproperties=myfont)
	# 增加图例
	plt.legend((u"当前用户密码列表", u"所以的密码列表", u"服务器列表"), loc='best', prop=myfont)
	plt.savefig('./static/images/rectangle.jpg', bbox_inches='tight')
	plt.close()
	return render(request, "linux/index.html")


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
