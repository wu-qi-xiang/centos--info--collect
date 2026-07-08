from django import forms
import re
import posixpath
try:
    from urllib import parse as urlparse
except ImportError:
    import urllib.parse as urlparse

from RemoteLinux.models import NewLinux, User
from .models import (
    AlertEvent,
    AlertSilence,
    ApprovalRequest,
    CommandPolicy,
    DevOpsHostScope,
    DevOpsModulePermission,
    DevOpsSetting,
    DevOpsRole,
    DeploymentApp,
    DeploymentRelease,
    FileDistribution,
    HostGroup,
    HostTag,
    NotificationChannel,
)


class HostGroupForm(forms.ModelForm):
    hosts = forms.ModelMultipleChoiceField(
        queryset=NewLinux.objects.all(),
        required=False,
        widget=forms.CheckboxSelectMultiple,
    )

    class Meta:
        model = HostGroup
        fields = ('name', 'description', 'hosts')


class HostTagForm(forms.ModelForm):
    hosts = forms.ModelMultipleChoiceField(
        queryset=NewLinux.objects.all(),
        required=False,
        widget=forms.CheckboxSelectMultiple,
    )

    class Meta:
        model = HostTag
        fields = ('name', 'color', 'description', 'hosts')


class CommandExecutionForm(forms.Form):
    host = forms.ModelChoiceField(queryset=NewLinux.objects.all())
    command = forms.CharField(widget=forms.Textarea(attrs={'rows': 4}))


class CommandApprovalForm(forms.Form):
    host = forms.ModelChoiceField(queryset=NewLinux.objects.all())
    command = forms.CharField(widget=forms.Textarea(attrs={'rows': 4}))
    reason = forms.CharField(max_length=500, required=False)


class CommandPolicyForm(forms.ModelForm):
    class Meta:
        model = CommandPolicy
        fields = ('name', 'pattern', 'action', 'enabled', 'reason')


class DevOpsRoleForm(forms.ModelForm):
    user = forms.ModelChoiceField(queryset=User.objects.all())

    class Meta:
        model = DevOpsRole
        fields = ('user', 'role')


class DevOpsModulePermissionForm(forms.ModelForm):
    user = forms.ModelChoiceField(queryset=User.objects.all())

    class Meta:
        model = DevOpsModulePermission
        fields = ('user', 'module', 'role')


class DevOpsHostScopeForm(forms.ModelForm):
    user = forms.ModelChoiceField(queryset=User.objects.all())
    groups = forms.ModelMultipleChoiceField(
        queryset=HostGroup.objects.all(),
        required=False,
        widget=forms.CheckboxSelectMultiple,
    )
    tags = forms.ModelMultipleChoiceField(
        queryset=HostTag.objects.all(),
        required=False,
        widget=forms.CheckboxSelectMultiple,
    )

    class Meta:
        model = DevOpsHostScope
        fields = ('user', 'groups', 'tags')


class DevOpsSettingForm(forms.ModelForm):
    class Meta:
        model = DevOpsSetting
        fields = ('force_deploy_approval', 'force_rollback_approval')


class BatchTaskForm(forms.Form):
    name = forms.CharField(max_length=100)
    hosts = forms.ModelMultipleChoiceField(
        queryset=NewLinux.objects.all(),
        widget=forms.CheckboxSelectMultiple,
    )
    command = forms.CharField(widget=forms.Textarea(attrs={'rows': 4}))


class ServiceOperationForm(forms.Form):
    host = forms.ModelChoiceField(queryset=NewLinux.objects.all())
    service_name = forms.CharField(max_length=100)
    action = forms.ChoiceField(choices=(
        ('status', '查看状态'),
        ('start', '启动'),
        ('stop', '停止'),
        ('restart', '重启'),
    ))

    def clean_service_name(self):
        value = (self.cleaned_data.get('service_name') or '').strip()
        if not re.match(r'^[A-Za-z0-9_.@:-]+$', value):
            raise forms.ValidationError('服务名只能包含字母、数字、点、下划线、横线、冒号和 @')
        return value


class FileDistributionForm(forms.ModelForm):
    hosts = forms.ModelMultipleChoiceField(
        queryset=NewLinux.objects.all(),
        widget=forms.CheckboxSelectMultiple,
    )

    class Meta:
        model = FileDistribution
        fields = ('name', 'source_file', 'remote_path', 'hosts')

    def clean_remote_path(self):
        value = self.cleaned_data.get('remote_path')
        valid, result = validate_remote_path_value(value)
        if not valid:
            raise forms.ValidationError(result)
        return result


class DeploymentAppForm(forms.ModelForm):
    class Meta:
        model = DeploymentApp
        fields = ('name', 'description')


class DeploymentReleaseForm(forms.ModelForm):
    hosts = forms.ModelMultipleChoiceField(
        queryset=NewLinux.objects.all(),
        widget=forms.CheckboxSelectMultiple,
    )

    class Meta:
        model = DeploymentRelease
        fields = ('app', 'version', 'description', 'deploy_script', 'rollback_script', 'hosts')
        widgets = {
            'deploy_script': forms.Textarea(attrs={'rows': 4}),
            'rollback_script': forms.Textarea(attrs={'rows': 4}),
        }


class ApprovalDecisionForm(forms.Form):
    action = forms.ChoiceField(choices=(
        ('approve', '批准'),
        ('reject', '拒绝'),
    ))
    comment = forms.CharField(max_length=500, required=False)


class AlertEventForm(forms.ModelForm):
    class Meta:
        model = AlertEvent
        fields = ('status', 'handler', 'remark')


class AlertSilenceForm(forms.ModelForm):
    starts_at = forms.DateTimeField(
        input_formats=['%Y-%m-%d %H:%M', '%Y-%m-%dT%H:%M'],
        widget=forms.DateTimeInput(attrs={'type': 'datetime-local'}),
    )
    ends_at = forms.DateTimeField(
        input_formats=['%Y-%m-%d %H:%M', '%Y-%m-%dT%H:%M'],
        widget=forms.DateTimeInput(attrs={'type': 'datetime-local'}),
    )

    class Meta:
        model = AlertSilence
        fields = ('host', 'metric', 'reason', 'starts_at', 'ends_at')

    def clean(self):
        cleaned_data = super().clean()
        starts_at = cleaned_data.get('starts_at')
        ends_at = cleaned_data.get('ends_at')
        if starts_at and ends_at and ends_at <= starts_at:
            self.add_error('ends_at', '结束时间必须晚于开始时间')
        return cleaned_data


class NotificationChannelForm(forms.ModelForm):
    webhook_url = forms.CharField(
        label='Webhook URL',
        required=False,
        widget=forms.Textarea(attrs={'rows': 2}),
    )
    secret = forms.CharField(
        label='签名密钥',
        required=False,
        widget=forms.PasswordInput(render_value=False),
    )

    class Meta:
        model = NotificationChannel
        fields = (
            'name',
            'channel_type',
            'webhook_url',
            'secret',
            'notify_alert',
            'notify_approval',
            'notify_deployment',
            'enabled',
        )

    def clean_webhook_url(self):
        value = self.cleaned_data.get('webhook_url')
        if value:
            value = value.strip()
            parsed = urlparse.urlparse(value)
            if parsed.scheme not in ('http', 'https') or not parsed.netloc:
                raise forms.ValidationError('Webhook URL 必须是 http 或 https 地址')
            return value
        if self.instance and self.instance.pk:
            return self.instance.webhook_url
        raise forms.ValidationError('Webhook URL 不能为空')

    def clean_secret(self):
        value = self.cleaned_data.get('secret')
        if value:
            return value.strip()
        if self.instance and self.instance.pk:
            return self.instance.secret
        return ''


def validate_remote_path_value(remote_path):
    if not remote_path or not remote_path.startswith('/'):
        return False, '远端路径必须是绝对路径'
    normalized = posixpath.normpath(remote_path)
    if normalized in ('/', '.', ''):
        return False, '不能分发到根目录'
    if '..' in remote_path.split('/'):
        return False, '远端路径不能包含 ..'
    return True, normalized
