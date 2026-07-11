from django import forms
try:
    from urllib import parse as urlparse
except ImportError:
    import urllib.parse as urlparse

from .models import AlertNotificationConfig, Monitor, PrometheusConfig


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


class PrometheusConfigForm(forms.ModelForm):
    class Meta:
        model = PrometheusConfig
        fields = ('prometheus_url', 'enabled')

    def clean_prometheus_url(self):
        value = (self.cleaned_data.get('prometheus_url') or '').strip().rstrip('/')
        if not value:
            raise forms.ValidationError('请输入 Prometheus 地址')
        parsed = urlparse.urlparse(value)
        if parsed.scheme not in ('http', 'https') or not parsed.netloc:
            raise forms.ValidationError('Prometheus 地址必须是 http:// 或 https:// 开头的完整地址')
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise forms.ValidationError('Prometheus 地址只填写基础地址，不要包含用户名、密码、Token 或查询参数')
        return value


class AlertNotificationForm(forms.Form):
    feishu_enabled = forms.BooleanField(required=False)
    feishu_name = forms.CharField(required=False, max_length=100)
    feishu_webhook_url = forms.CharField(required=False)
    wecom_enabled = forms.BooleanField(required=False)
    wecom_name = forms.CharField(required=False, max_length=100)
    wecom_webhook_url = forms.CharField(required=False)

    PROVIDERS = (
        AlertNotificationConfig.PROVIDER_FEISHU,
        AlertNotificationConfig.PROVIDER_WECOM,
    )

    def __init__(self, *args, **kwargs):
        self.existing = kwargs.pop('existing', {}) or {}
        super(AlertNotificationForm, self).__init__(*args, **kwargs)

    def clean(self):
        cleaned_data = super().clean()
        for provider in self.PROVIDERS:
            url_field = '%s_webhook_url' % provider
            enabled_field = '%s_enabled' % provider
            value = (cleaned_data.get(url_field) or '').strip()
            existing = self.existing.get(provider)
            if cleaned_data.get(enabled_field) and not value and not (existing and existing.decrypted_webhook_url):
                self.add_error(url_field, '启用前请填写 Webhook 地址')
                continue
            if value and not self._valid_webhook_url(value):
                self.add_error(url_field, 'Webhook 地址必须是 http:// 或 https:// 开头的完整地址，且不要包含用户名、密码或查询参数')
            cleaned_data[url_field] = value
        return cleaned_data

    def _valid_webhook_url(self, value):
        parsed = urlparse.urlparse(value)
        if parsed.scheme not in ('http', 'https') or not parsed.netloc:
            return False
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            return False
        return True
