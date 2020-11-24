from django import forms
from .models import Password


class Password_manage(forms.ModelForm):
    class Meta:
        # 指明数据模型来源
        model = Password
        # 定义表单包含的字段
        fields = "__all__"