from django import forms
from .models import NewLinux


class LinuxPostForm(forms.ModelForm):
	class Meta:
		# 指明数据模型来源、
		model = NewLinux
		# 定义表单包含的字段
		# fields = ('linux_name', 'linux_ip', 'linux_port', 'linux_user', 'linux_passwd')
		fields = "__all__"
