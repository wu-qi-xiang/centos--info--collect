from django.shortcuts import render
from django.db.models import Q
from django.http import HttpResponse
import subprocess
import re
import urllib.request
from RemoteLinux.forms import LinuxPostForm
from RemoteLinux.models import NewLinux


# from . import models


# Create your views here.

def index(request):
	return render(request, 'linux/index.html')


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
	if request.method == "GET":
		keyword = request.GET.get('search')
		newlinux = NewLinux.objects.filter(Q(linux_name__icontains=keyword) | Q(linux_ip__icontains=keyword) | Q(linux_hostname__icontains=keyword) | Q(linux_app__icontains=keyword))
		content = {'newlinux': newlinux, 'keyword': keyword}
		return render(request, 'linux/detail.html', content)
	else:
		return HttpResponse("非GET请求")
