from django import forms
from .models import Monitor


class MonitorForm(forms.ModelForm):
    class Meta:
        # 指明数据模型来源
        model = Monitor
        # 定义表单包含的字段
        fields = "__all__"

    def clean(self):
        cleaned_data = super().clean()
        for field in ('monitor_cpu', 'monitor_men', 'monitor_disk'):
            value = cleaned_data.get(field)
            if not self._valid_percent(value):
                self.add_error(field, '请输入 0 到 100 之间的百分比，或 0 到 1 之间的小数')
        return cleaned_data

    def _valid_percent(self, value):
        if value in (None, ''):
            return False
        try:
            number = float(str(value).strip().strip('%'))
        except (TypeError, ValueError):
            return False
        if number > 1:
            number = number / 100.0
        return 0 <= number <= 1
