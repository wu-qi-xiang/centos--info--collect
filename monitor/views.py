from django.shortcuts import render
from django.shortcuts import render, redirect
from django.http import HttpResponse
# Create your views here.
import subprocess
import urllib
import re
from .models import Monitor
from .forms import MonitorForm


def monitor_index(request):
	monitor = Monitor.objects.all()
	if request.method == "POST":
		monitorform = MonitorForm(request.POST)
		if monitorform.is_valid():
			monitor = Monitor.objects.all()
			if monitor.count() == 0:
				monitorform.save()
				return redirect("linux")
			else:
				return HttpResponse("已存有告警数据,请点击修改,修改告警数值")
		else:
			return HttpResponse("输入类型存在错误，请重新输入")
	else:
		content = {'monitor': monitor}
		return render(request, "monitor/index.html", content)


def monitor_update(request, id):
	monitor = Monitor.objects.get(id=id)
	if request.method == "POST":
		# 将提交的数据赋值到表单实例中
		monitorform = MonitorForm(request.POST)
		if monitorform.is_valid():
			# 将更改的数据保存到数据库
			monitor.monitor_email = request.POST["monitor_email"]
			monitor.monitor_cpu = request.POST["monitor_cpu"]
			monitor.monitor_disk = request.POST["monitor_disk"]
			monitor.monitor_men= request.POST["monitor_men"]
			monitor.save()
			return render(request, 'monitor/index.html')
		else:
			return HttpResponse("输入错误，请重新输入")
	else:
		content = {'monitor': monitor}
		return render(request, 'monitor/monitor_update.html', content)