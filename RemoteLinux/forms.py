from django import forms
from django.db import models
from .models import NewLinux, User


class LinuxPostForm(forms.ModelForm):
	class Meta:
		# 指明数据模型来源、
		model = NewLinux
		# 定义表单包含的字段
		# fields = ('linux_name', 'linux_ip', 'linux_port', 'linux_user', 'linux_passwd')
		fields = "__all__"


class UserForm(forms.ModelForm):
	class Meta:
		model = User
		fields = "__all__"