from django import forms
import re
import posixpath
import yaml
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
    K8sCluster,
    NotificationChannel,
    ComplianceBaseline,
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


class ComplianceBaselineForm(forms.ModelForm):
    hosts = forms.ModelMultipleChoiceField(queryset=NewLinux.objects.all(), widget=forms.CheckboxSelectMultiple)

    class Meta:
        model = ComplianceBaseline
        fields = ('name', 'baseline_type', 'service_name', 'file_path', 'expected_sha256', 'hosts')

    def clean(self):
        cleaned = super(ComplianceBaselineForm, self).clean()
        baseline_type = cleaned.get('baseline_type')
        if baseline_type == ComplianceBaseline.TYPE_SERVICE_ACTIVE:
            valid, value = validate_compliance_service_name(cleaned.get('service_name'))
            if not valid:
                self.add_error('service_name', value)
            cleaned['service_name'] = value if valid else ''
            cleaned['file_path'] = ''
            cleaned['expected_sha256'] = ''
        elif baseline_type == ComplianceBaseline.TYPE_FILE_SHA256:
            valid, value = validate_compliance_file_path(cleaned.get('file_path'))
            if not valid:
                self.add_error('file_path', value)
            cleaned['file_path'] = value if valid else ''
            sha = (cleaned.get('expected_sha256') or '').strip().lower()
            if not re.match(r'^[a-f0-9]{64}$', sha):
                self.add_error('expected_sha256', '请输入 64 位 SHA-256 十六进制值')
            cleaned['expected_sha256'] = sha
            cleaned['service_name'] = ''
        return cleaned


def validate_compliance_service_name(value):
    value = (value or '').strip()
    if not re.match(r'^[A-Za-z0-9_.@:-]+$', value):
        return False, '服务名只能包含字母、数字、点、下划线、横线、冒号和 @'
    return True, value


def validate_compliance_file_path(value):
    value = (value or '').strip()
    if not value.startswith('/') or '\x00' in value or '\n' in value or '\r' in value:
        return False, '文件路径必须是安全的绝对路径'
    normalized = posixpath.normpath(value)
    if normalized != value or normalized.startswith('/../') or normalized == '/..':
        return False, '文件路径不能包含路径跳转'
    return True, normalized


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


class K8sClusterForm(forms.ModelForm):
    kubeconfig = forms.CharField(
        label='Kubeconfig',
        required=False,
        strip=False,
        widget=forms.Textarea(attrs={
            'class': 'form-control',
            'rows': 8,
            'placeholder': '粘贴 kubeconfig；编辑时留空表示保持原配置',
            'autocomplete': 'off',
            'spellcheck': 'false',
        }),
    )

    class Meta:
        model = K8sCluster
        fields = ('name', 'api_server', 'default_namespace', 'kubeconfig')
        widgets = {
            'name': forms.TextInput(attrs={'class': 'form-control', 'autocomplete': 'off'}),
            'api_server': forms.URLInput(attrs={'class': 'form-control', 'placeholder': 'https://kubernetes.example.com:6443'}),
            'default_namespace': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'default'}),
        }

    def clean_name(self):
        return (self.cleaned_data.get('name') or '').strip()

    def clean_api_server(self):
        return (self.cleaned_data.get('api_server') or '').strip()

    def clean_default_namespace(self):
        return (self.cleaned_data.get('default_namespace') or '').strip() or 'default'

    def clean_kubeconfig(self):
        value = self.cleaned_data.get('kubeconfig')
        if value and value.strip():
            return value
        if self.instance and self.instance.pk:
            return self.instance.kubeconfig
        raise forms.ValidationError('Kubeconfig 不能为空')


class K8sClusterConnectionForm(forms.ModelForm):
    MAX_KUBECONFIG_SIZE = 1024 * 1024
    NAMESPACE_PATTERN = re.compile(r'^[a-z0-9]([-a-z0-9]*[a-z0-9])?$')

    kubeconfig_file = forms.FileField(
        label='Kubeconfig',
        required=True,
        widget=forms.ClearableFileInput(attrs={
            'class': 'form-control',
        }),
    )

    class Meta:
        model = K8sCluster
        fields = ('name',)
        widgets = {
            'name': forms.TextInput(attrs={'class': 'form-control', 'autocomplete': 'off'}),
        }

    def __init__(self, *args, **kwargs):
        super(K8sClusterConnectionForm, self).__init__(*args, **kwargs)
        self._parsed_kubeconfig = None

    def clean_name(self):
        return (self.cleaned_data.get('name') or '').strip()

    def clean_kubeconfig_file(self):
        uploaded = self.cleaned_data.get('kubeconfig_file')
        if not uploaded:
            return uploaded
        if uploaded.size > self.MAX_KUBECONFIG_SIZE:
            raise forms.ValidationError('Kubeconfig 文件不能超过 1 MiB')

        try:
            content = uploaded.read().decode('utf-8-sig')
        except UnicodeDecodeError:
            raise forms.ValidationError('Kubeconfig 文件必须使用 UTF-8 编码')
        finally:
            uploaded.seek(0)

        try:
            config = yaml.safe_load(content)
        except yaml.YAMLError:
            raise forms.ValidationError('Kubeconfig 文件格式无效')
        if not isinstance(config, dict):
            raise forms.ValidationError('Kubeconfig 必须是有效的 YAML 映射')

        contexts = config.get('contexts')
        clusters = config.get('clusters')
        if not isinstance(contexts, list) or not contexts:
            raise forms.ValidationError('Kubeconfig 缺少 contexts 配置')
        if not isinstance(clusters, list) or not clusters:
            raise forms.ValidationError('Kubeconfig 缺少 clusters 配置')

        raw_context_name = config.get('current-context')
        if raw_context_name is not None and not isinstance(raw_context_name, str):
            raise forms.ValidationError('Kubeconfig 无法解析 current-context')
        context_name = self._clean_text(raw_context_name)
        if not context_name:
            first_context = contexts[0] if isinstance(contexts[0], dict) else {}
            context_name = self._clean_text(first_context.get('name'))
        context_entry = self._find_named_entry(contexts, context_name)
        context = context_entry.get('context') if context_entry else None
        if not isinstance(context, dict):
            raise forms.ValidationError('Kubeconfig 无法解析 current-context')

        cluster_name = self._clean_text(context.get('cluster'))
        cluster_entry = self._find_named_entry(clusters, cluster_name)
        cluster_config = cluster_entry.get('cluster') if cluster_entry else None
        if not isinstance(cluster_config, dict):
            raise forms.ValidationError('Kubeconfig 中 current-context 引用的集群不存在')

        api_server = self._clean_text(cluster_config.get('server'))
        if not self._valid_api_server(api_server):
            raise forms.ValidationError('Kubeconfig 中的 API Server 必须是有效的 http 或 https 地址')

        namespace = self._clean_text(context.get('namespace')) or 'default'
        namespace = namespace.lower()
        if len(namespace) > 63 or not self.NAMESPACE_PATTERN.match(namespace):
            raise forms.ValidationError('Kubeconfig 中的 Namespace 格式无效')

        self._parsed_kubeconfig = {
            'api_server': api_server,
            'default_namespace': namespace,
            'kubeconfig': content,
        }
        return uploaded

    @staticmethod
    def _find_named_entry(entries, name):
        if not name:
            return None
        for entry in entries:
            if isinstance(entry, dict) and entry.get('name') == name:
                return entry
        return None

    @staticmethod
    def _clean_text(value):
        return value.strip() if isinstance(value, str) else ''

    @staticmethod
    def _valid_api_server(value):
        try:
            parsed = urlparse.urlparse(value)
            parsed.port
        except (TypeError, ValueError):
            return False
        return bool(
            parsed.scheme in ('http', 'https')
            and len(value) <= 300
            and not any(character.isspace() for character in value)
            and parsed.netloc
            and parsed.hostname
            and not parsed.username
            and not parsed.password
            and not parsed.query
            and not parsed.fragment
        )

    def save(self, commit=True):
        cluster = super(K8sClusterConnectionForm, self).save(commit=False)
        if not self._parsed_kubeconfig:
            raise ValueError('Kubeconfig must be validated before saving')
        cluster.api_server = self._parsed_kubeconfig['api_server']
        cluster.default_namespace = self._parsed_kubeconfig['default_namespace']
        cluster.kubeconfig = self._parsed_kubeconfig['kubeconfig']
        if commit:
            cluster.save()
        return cluster


def validate_remote_path_value(remote_path):
    if not remote_path or not remote_path.startswith('/'):
        return False, '远端路径必须是绝对路径'
    normalized = posixpath.normpath(remote_path)
    if normalized in ('/', '.', ''):
        return False, '不能分发到根目录'
    if '..' in remote_path.split('/'):
        return False, '远端路径不能包含 ..'
    return True, normalized
