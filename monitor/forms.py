from django import forms
from .models import Monitor


class MonitorForm(forms.ModelForm):
    class Meta:
        # 指明数据模型来源
        model = Monitor
        # 定义表单包含的字段
        fields = "__all__"
