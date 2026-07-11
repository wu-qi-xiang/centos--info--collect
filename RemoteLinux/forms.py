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

	def clean(self):
		cleaned_data = super().clean()
		auth_type = cleaned_data.get('linux_auth_type') or NewLinux.AUTH_PASSWORD
		password = cleaned_data.get('linux_passwd')
		private_key = cleaned_data.get('linux_private_key')
		if auth_type == NewLinux.AUTH_PASSWORD and not password and not getattr(self.instance, 'linux_passwd', ''):
			self.add_error('linux_passwd', '密码认证需要填写密码')
		if auth_type == NewLinux.AUTH_KEY and not private_key and not getattr(self.instance, 'linux_private_key', ''):
			self.add_error('linux_private_key', 'SSH Key认证需要填写私钥')
		return cleaned_data


class UserForm(forms.ModelForm):
	class Meta:
		model = User
		fields = "__all__"
