from django import forms
from django.db.models import Q
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
    NotificationTemplate,
    AlertNotificationEscalation,
    ServiceOnCallPolicy,
    ServiceOnCallRotationMember,
    ComplianceBaseline,
    ServiceCatalog,
    ServiceSlo,
    RunbookTemplate,
    DevOpsProject,
)
from .services import normalize_prometheus_rule_resource_version


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


class DevOpsModulePermissionClearForm(forms.Form):
    user = forms.ModelChoiceField(queryset=User.objects.all())


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


class ServiceCatalogForm(forms.ModelForm):
    hosts = forms.ModelMultipleChoiceField(
        queryset=NewLinux.objects.all(),
        required=False,
        widget=forms.CheckboxSelectMultiple,
    )
    upstream_services = forms.ModelMultipleChoiceField(
        queryset=ServiceCatalog.objects.all(),
        required=False,
        widget=forms.CheckboxSelectMultiple,
        label='上游依赖服务',
    )

    class Meta:
        model = ServiceCatalog
        fields = ('name', 'owner', 'environment', 'description', 'hosts')

    def __init__(self, *args, **kwargs):
        upstream_services_queryset = kwargs.pop('upstream_services_queryset', None)
        super(ServiceCatalogForm, self).__init__(*args, **kwargs)
        if upstream_services_queryset is not None:
            self.fields['upstream_services'].queryset = upstream_services_queryset
        if self.instance and self.instance.pk:
            self.fields['upstream_services'].queryset = self.fields['upstream_services'].queryset.exclude(id=self.instance.id)
            self.initial['upstream_services'] = self.instance.upstream_links.values_list('upstream_service_id', flat=True)

    def clean_upstream_services(self):
        services = self.cleaned_data.get('upstream_services')
        if self.instance and self.instance.pk and services.filter(id=self.instance.id).exists():
            raise forms.ValidationError('服务不能依赖自身')
        return services


class ServiceSloForm(forms.ModelForm):
    class Meta:
        model = ServiceSlo
        fields = ('service', 'metric_kind', 'target', 'window_minutes', 'enabled')


class RunbookTemplateForm(forms.ModelForm):
    allowed_hosts = forms.ModelMultipleChoiceField(
        queryset=NewLinux.objects.all(), widget=forms.CheckboxSelectMultiple,
    )

    class Meta:
        model = RunbookTemplate
        fields = (
            'name', 'version', 'trigger_kind', 'command_template', 'service',
            'allowed_hosts', 'rollback_runbook', 'enabled', 'requires_approval',
        )

    def clean(self):
        cleaned = super(RunbookTemplateForm, self).clean()
        rollback = cleaned.get('rollback_runbook')
        allowed_hosts = cleaned.get('allowed_hosts')
        if rollback and allowed_hosts is not None:
            rollback_host_ids = set(rollback.allowed_hosts.values_list('id', flat=True))
            missing_host_ids = set(host.id for host in allowed_hosts) - rollback_host_ids
            if missing_host_ids:
                self.add_error('rollback_runbook', '回滚运行手册必须覆盖当前运行手册的所有允许主机')
        return cleaned


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
        fields = ('name', 'repository', 'description')

    def clean_repository(self):
        value = (self.cleaned_data.get('repository') or '').strip().lower()
        if not value:
            return None
        if not re.match(r'^[a-z0-9](?:[a-z0-9-]{0,38})/[a-z0-9][a-z0-9._-]{0,99}$', value):
            raise forms.ValidationError('仓库必须是 owner/repo 格式，不能包含 URL、凭据或查询参数')
        return value


class ProjectOnboardingForm(forms.ModelForm):
    hosts = forms.ModelMultipleChoiceField(queryset=NewLinux.objects.all(), required=False, widget=forms.CheckboxSelectMultiple)
    groups = forms.ModelMultipleChoiceField(queryset=HostGroup.objects.all(), required=False, widget=forms.CheckboxSelectMultiple)
    tags = forms.ModelMultipleChoiceField(queryset=HostTag.objects.all(), required=False, widget=forms.CheckboxSelectMultiple)
    services = forms.ModelMultipleChoiceField(queryset=ServiceCatalog.objects.all(), required=False, widget=forms.CheckboxSelectMultiple)
    deployment_apps = forms.ModelMultipleChoiceField(queryset=DeploymentApp.objects.all(), required=False, widget=forms.CheckboxSelectMultiple)
    create_group_name = forms.CharField(max_length=100, required=False, label='新建主机组')
    create_tag_name = forms.CharField(max_length=50, required=False, label='新建标签')
    create_service_name = forms.CharField(max_length=100, required=False, label='新建服务')
    create_app_name = forms.CharField(max_length=100, required=False, label='新建部署应用')
    create_app_repository = forms.CharField(max_length=140, required=False, label='新建应用仓库')

    class Meta:
        model = DevOpsProject
        fields = ('name', 'owner', 'description', 'monitoring_enabled', 'monitor_cpu', 'monitor_memory', 'monitor_disk', 'hosts', 'groups', 'tags', 'services', 'deployment_apps')

    def _clean_new_name(self, field, model):
        value = (self.cleaned_data.get(field) or '').strip()
        if value and model.objects.filter(name__iexact=value).exists():
            self.add_error(field, '该名称已存在')
        return value

    def clean(self):
        cleaned = super(ProjectOnboardingForm, self).clean()
        self._clean_new_name('create_group_name', HostGroup)
        self._clean_new_name('create_tag_name', HostTag)
        self._clean_new_name('create_service_name', ServiceCatalog)
        self._clean_new_name('create_app_name', DeploymentApp)
        repository = (cleaned.get('create_app_repository') or '').strip().lower()
        if repository and not re.match(r'^[a-z0-9](?:[a-z0-9-]{0,38})/[a-z0-9][a-z0-9._-]{0,99}$', repository):
            self.add_error('create_app_repository', '仓库必须是 owner/repo 格式，不能包含 URL、凭据或查询参数')
        elif repository and DeploymentApp.objects.filter(repository=repository).exists():
            self.add_error('create_app_repository', '该仓库已关联其他部署应用')
        cleaned['create_app_repository'] = repository
        for field in ('monitor_cpu', 'monitor_memory', 'monitor_disk'):
            value = (cleaned.get(field) or '').strip()
            try:
                number = float(value.rstrip('%'))
            except (TypeError, ValueError):
                number = -1
            if not 0 <= number <= 100:
                self.add_error(field, '请输入 0 到 100 的百分比')
            else:
                cleaned[field] = '%s%%' % ('%g' % number)
        return cleaned


class DeploymentReleaseForm(forms.ModelForm):
    hosts = forms.ModelMultipleChoiceField(
        queryset=NewLinux.objects.all(),
        widget=forms.CheckboxSelectMultiple,
    )
    rollout_batch_size = forms.IntegerField(
        required=False, min_value=0, max_value=100, initial=0,
        label='分批发布大小（0 表示关闭）',
    )

    class Meta:
        model = DeploymentRelease
        fields = ('app', 'version', 'description', 'deploy_script', 'rollback_script', 'rollout_batch_size', 'hosts')
        widgets = {
            'deploy_script': forms.Textarea(attrs={'rows': 4}),
            'rollback_script': forms.Textarea(attrs={'rows': 4}),
        }

    def clean_rollout_batch_size(self):
        value = self.cleaned_data.get('rollout_batch_size')
        return 0 if value is None else value


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


class ServiceOnCallPolicyForm(forms.ModelForm):
    class Meta:
        model = ServiceOnCallPolicy
        fields = (
            'service',
            'primary_user',
            'primary_channel',
            'backup_user',
            'backup_channel',
            'enabled',
        )

    def __init__(self, *args, **kwargs):
        super(ServiceOnCallPolicyForm, self).__init__(*args, **kwargs)
        channels = NotificationChannel.objects.filter(enabled=True).order_by('name')
        if self.instance and self.instance.pk:
            channels = NotificationChannel.objects.filter(
                Q(enabled=True)
                | Q(id=self.instance.primary_channel_id)
                | Q(id=self.instance.backup_channel_id)
            ).order_by('name')
        self.fields['primary_channel'].queryset = channels
        self.fields['backup_channel'].queryset = channels
        self.fields['primary_user'].queryset = User.objects.order_by('user')
        self.fields['backup_user'].queryset = User.objects.order_by('user')

    def clean(self):
        cleaned = super(ServiceOnCallPolicyForm, self).clean()
        primary_user = cleaned.get('primary_user')
        backup_user = cleaned.get('backup_user')
        primary_channel = cleaned.get('primary_channel')
        backup_channel = cleaned.get('backup_channel')
        if primary_user and backup_user and primary_user == backup_user:
            self.add_error('backup_user', '主值班人与备值班人不能是同一用户')
        if primary_channel and backup_channel and primary_channel == backup_channel:
            self.add_error('backup_channel', '主值班与备值班不能使用同一通知渠道')
        return cleaned


class ServiceOnCallRotationMemberForm(forms.ModelForm):
    class Meta:
        model = ServiceOnCallRotationMember
        fields = ('user', 'channel', 'position', 'enabled')

    def __init__(self, *args, **kwargs):
        super(ServiceOnCallRotationMemberForm, self).__init__(*args, **kwargs)
        channels = NotificationChannel.objects.filter(enabled=True).order_by('name')
        if self.instance and self.instance.pk:
            channels = NotificationChannel.objects.filter(
                Q(enabled=True) | Q(id=self.instance.channel_id)
            ).order_by('name')
        self.fields['user'].queryset = User.objects.order_by('user')
        self.fields['channel'].queryset = channels

    def clean_position(self):
        position = self.cleaned_data.get('position')
        if position is None or position < 1:
            raise forms.ValidationError('轮换顺序必须从 1 开始')
        return position

    def clean(self):
        cleaned = super(ServiceOnCallRotationMemberForm, self).clean()
        policy = getattr(self.instance, 'policy', None)
        position = cleaned.get('position')
        user = cleaned.get('user')
        channel = cleaned.get('channel')
        if policy and user and user == policy.backup_user:
            self.add_error('user', '轮换成员不能使用固定备值班用户')
        if policy and channel and channel == policy.backup_channel:
            self.add_error('channel', '轮换成员不能使用固定备值班通知渠道')
        if policy and position:
            duplicate = ServiceOnCallRotationMember.objects.filter(
                policy=policy, position=position,
            ).exclude(pk=self.instance.pk).exists()
            if duplicate:
                self.add_error('position', '该轮换顺序已被占用')
        return cleaned


class NotificationTemplateForm(forms.ModelForm):
    class Meta:
        model = NotificationTemplate
        fields = ('title_template', 'content_template')
        widgets = {
            'content_template': forms.Textarea(attrs={'rows': 3}),
        }


class AlertNotificationEscalationForm(forms.ModelForm):
    class Meta:
        model = AlertNotificationEscalation
        fields = ('enabled', 'minimum_level', 'channel')

    def clean(self):
        cleaned_data = super(AlertNotificationEscalationForm, self).clean()
        if cleaned_data.get('enabled'):
            channel = cleaned_data.get('channel')
            if not channel:
                self.add_error('channel', '启用升级规则时必须选择渠道')
            elif not channel.enabled:
                self.add_error('channel', '升级渠道必须处于启用状态')
        return cleaned_data


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


PROMETHEUS_RULE_NAMESPACE_PATTERN = re.compile(r'^[a-z0-9]([-a-z0-9]*[a-z0-9])?$')
PROMETHEUS_RULE_NAME_PATTERN = re.compile(r'^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$')


def normalize_prometheus_rule_identity(namespace, name):
    namespace = (namespace or '').strip().lower()
    name = (name or '').strip()
    if (not namespace or len(namespace) > 63 or not PROMETHEUS_RULE_NAMESPACE_PATTERN.match(namespace)
            or not name or len(name) > 253 or not PROMETHEUS_RULE_NAME_PATTERN.match(name)):
        return None, None
    return namespace, name


class PrometheusRuleYamlForm(forms.Form):
    yaml = forms.CharField(
        label='PrometheusRule YAML',
        widget=forms.Textarea(attrs={
            'class': 'form-control font-monospace',
            'rows': 24,
            'spellcheck': 'false',
            'autocomplete': 'off',
        }),
    )


class PrometheusRuleDeleteForm(forms.Form):
    confirmation = forms.CharField(
        label='删除确认',
        max_length=16,
        strip=False,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'autocomplete': 'off',
        }),
    )
    resource_version = forms.CharField(widget=forms.HiddenInput(), max_length=255)

    def clean_confirmation(self):
        confirmation = self.cleaned_data.get('confirmation') or ''
        if confirmation != 'DELETE':
            raise forms.ValidationError('请输入 DELETE 确认删除。')
        return confirmation

    def clean_resource_version(self):
        resource_version = normalize_prometheus_rule_resource_version(
            self.cleaned_data.get('resource_version'),
        )
        if not resource_version:
            raise forms.ValidationError('资源版本无效。')
        return resource_version


class PrometheusRuleRevisionReviewForm(forms.Form):
    decision = forms.ChoiceField(choices=(('approve', '批准'), ('reject', '拒绝')))
    comment = forms.CharField(max_length=500, required=False)


K8S_DISCOVERY_NAMESPACE_PATTERN = re.compile(r'^[a-z0-9]([-a-z0-9]*[a-z0-9])?$')
K8S_DISCOVERY_WORKLOAD_NAME_PATTERN = re.compile(r'^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$')
K8S_DISCOVERY_WORKLOAD_KINDS = (
    ('Deployment', 'Deployment'),
    ('StatefulSet', 'StatefulSet'),
    ('DaemonSet', 'DaemonSet'),
)


class K8sServiceDiscoveryForm(forms.Form):
    cluster = forms.ModelChoiceField(queryset=K8sCluster.objects.all().order_by('name'))
    namespace = forms.CharField(max_length=63, initial='default')

    def clean_namespace(self):
        namespace = (self.cleaned_data.get('namespace') or '').strip().lower()
        if not K8S_DISCOVERY_NAMESPACE_PATTERN.match(namespace):
            raise forms.ValidationError('命名空间格式无效')
        return namespace


class K8sWorkloadServiceAssociationForm(K8sServiceDiscoveryForm):
    workload_kind = forms.ChoiceField(choices=K8S_DISCOVERY_WORKLOAD_KINDS)
    workload_name = forms.CharField(max_length=253)
    service = forms.ModelChoiceField(queryset=ServiceCatalog.objects.all().order_by('name'))

    def clean_workload_name(self):
        name = (self.cleaned_data.get('workload_name') or '').strip()
        if not K8S_DISCOVERY_WORKLOAD_NAME_PATTERN.match(name):
            raise forms.ValidationError('工作负载名称格式无效')
        return name


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
