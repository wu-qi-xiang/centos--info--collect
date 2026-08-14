import hashlib
import json

from django.db import models
from django.core.exceptions import ValidationError
from django.utils import timezone

from PyLinux.crypto import decrypt_text, encrypt_text
from RemoteLinux.models import NewLinux, User


class DevOpsRole(models.Model):
    ROLE_VIEWER = 'viewer'
    ROLE_OPERATOR = 'operator'
    ROLE_ADMIN = 'admin'

    ROLE_CHOICES = (
        (ROLE_VIEWER, '只读'),
        (ROLE_OPERATOR, '运维操作'),
        (ROLE_ADMIN, '管理员'),
    )

    user = models.OneToOneField(User, on_delete=models.CASCADE)
    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default=ROLE_VIEWER)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "devops_role"

    def __str__(self):
        return '%s:%s' % (self.user.user, self.role)


class DevOpsModulePermission(models.Model):
    ROLE_NONE = 'none'
    MODULE_COMMAND = 'command'
    MODULE_TASK = 'task'
    MODULE_SERVICE = 'service'
    MODULE_FILE = 'file'
    MODULE_DEPLOYMENT = 'deployment'
    MODULE_APPROVAL = 'approval'
    MODULE_ALERT = 'alert'
    MODULE_METRIC = 'metric'
    MODULE_SECURITY = 'security'
    MODULE_AUDIT = 'audit'
    MODULE_CLUSTER = 'cluster'

    MODULE_CHOICES = (
        (MODULE_COMMAND, '命令执行'),
        (MODULE_TASK, '批量任务'),
        (MODULE_SERVICE, '服务管理'),
        (MODULE_FILE, '文件分发'),
        (MODULE_DEPLOYMENT, '发布部署'),
        (MODULE_APPROVAL, '审批流'),
        (MODULE_ALERT, '告警治理'),
        (MODULE_METRIC, '监控历史'),
        (MODULE_SECURITY, '安全策略'),
        (MODULE_AUDIT, '审计日志'),
        (MODULE_CLUSTER, 'K8s集群'),
    )
    ROLE_CHOICES = DevOpsRole.ROLE_CHOICES + ((ROLE_NONE, '禁止访问'),)

    user = models.ForeignKey(User, on_delete=models.CASCADE)
    module = models.CharField(max_length=30, choices=MODULE_CHOICES)
    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default=DevOpsRole.ROLE_VIEWER)
    created_by = models.CharField(max_length=100, blank=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "devops_module_permission"
        unique_together = ('user', 'module')
        ordering = ['user__user', 'module']

    def __str__(self):
        return '%s:%s:%s' % (self.user.user, self.module, self.role)


class ChatOpsIdentity(models.Model):
    """A revocable WeCom identity binding; no incoming message data is stored."""
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='chatops_identity')
    wecom_user_id = models.CharField(max_length=128, unique=True)
    enabled = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'devops_chatops_identity'
        ordering = ['wecom_user_id']

    def __str__(self):
        return '%s:%s' % (self.wecom_user_id, self.user.user)


class DevOpsHostScope(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    groups = models.ManyToManyField('HostGroup', blank=True)
    tags = models.ManyToManyField('HostTag', blank=True)
    created_by = models.CharField(max_length=100, blank=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "devops_host_scope"
        ordering = ['user__user']

    def __str__(self):
        return self.user.user


class DevOpsSetting(models.Model):
    force_deploy_approval = models.BooleanField(default=False)
    force_rollback_approval = models.BooleanField(default=False)
    updated_by = models.CharField(max_length=100, blank=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "devops_setting"

    def __str__(self):
        return 'DevOpsSetting'

    @classmethod
    def current(cls):
        setting = cls.objects.first()
        if setting:
            return setting
        return cls.objects.create()


class HostGroup(models.Model):
    name = models.CharField(max_length=100, unique=True)
    description = models.CharField(max_length=300, blank=True)
    hosts = models.ManyToManyField(NewLinux, blank=True)
    created_by = models.CharField(max_length=100, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "devops_host_group"

    def __str__(self):
        return self.name


class HostTag(models.Model):
    name = models.CharField(max_length=50, unique=True)
    color = models.CharField(max_length=20, default='secondary')
    description = models.CharField(max_length=200, blank=True)
    hosts = models.ManyToManyField(NewLinux, blank=True)
    created_by = models.CharField(max_length=100, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "devops_host_tag"
        ordering = ['name']

    def __str__(self):
        return self.name


class ServiceCatalog(models.Model):
    ENV_DEVELOPMENT = 'development'
    ENV_TEST = 'test'
    ENV_STAGING = 'staging'
    ENV_PRODUCTION = 'production'

    ENVIRONMENT_CHOICES = (
        (ENV_DEVELOPMENT, '开发'),
        (ENV_TEST, '测试'),
        (ENV_STAGING, '预发布'),
        (ENV_PRODUCTION, '生产'),
    )

    LIFECYCLE_ACTIVE = 'active'
    LIFECYCLE_MAINTENANCE = 'maintenance'
    LIFECYCLE_RETIRED = 'retired'
    LIFECYCLE_CHOICES = (
        (LIFECYCLE_ACTIVE, '运行中'),
        (LIFECYCLE_MAINTENANCE, '维护中'),
        (LIFECYCLE_RETIRED, '已退役'),
    )

    CRITICALITY_LOW = 'low'
    CRITICALITY_MEDIUM = 'medium'
    CRITICALITY_HIGH = 'high'
    CRITICALITY_CRITICAL = 'critical'
    CRITICALITY_CHOICES = (
        (CRITICALITY_LOW, '低'),
        (CRITICALITY_MEDIUM, '中'),
        (CRITICALITY_HIGH, '高'),
        (CRITICALITY_CRITICAL, '关键'),
    )

    name = models.CharField(max_length=100, unique=True)
    owner = models.CharField(max_length=100, blank=True)
    environment = models.CharField(max_length=20, choices=ENVIRONMENT_CHOICES, default=ENV_PRODUCTION)
    lifecycle = models.CharField(max_length=20, choices=LIFECYCLE_CHOICES, default=LIFECYCLE_ACTIVE)
    criticality = models.CharField(max_length=20, choices=CRITICALITY_CHOICES, default=CRITICALITY_MEDIUM)
    description = models.CharField(max_length=300, blank=True)
    created_by = models.CharField(max_length=100, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    hosts = models.ManyToManyField(NewLinux, blank=True, related_name='topology_services')

    class Meta:
        db_table = 'devops_service_catalog'
        ordering = ['environment', 'name']

    def __str__(self):
        return self.name


class CloudResourceSummary(models.Model):
    """Safe cloud inventory summary; it deliberately contains no provider credentials."""
    PROVIDER_AWS = 'aws'
    PROVIDER_AZURE = 'azure'
    PROVIDER_GCP = 'gcp'
    PROVIDER_ALIYUN = 'aliyun'
    PROVIDER_CHOICES = (
        (PROVIDER_AWS, 'AWS'),
        (PROVIDER_AZURE, 'Azure'),
        (PROVIDER_GCP, 'GCP'),
        (PROVIDER_ALIYUN, '阿里云'),
    )

    service = models.ForeignKey(ServiceCatalog, on_delete=models.CASCADE, related_name='cloud_resources')
    provider = models.CharField(max_length=20, choices=PROVIDER_CHOICES)
    resource_type = models.CharField(max_length=64)
    resource_identifier = models.CharField(max_length=160)
    region = models.CharField(max_length=64)
    tag_digest = models.CharField(max_length=64)
    last_seen_at = models.DateTimeField(auto_now=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'devops_cloud_resource_summary'
        ordering = ['provider', 'region', 'resource_type', 'resource_identifier']
        unique_together = ('provider', 'resource_type', 'resource_identifier', 'region')

    def __str__(self):
        return '%s:%s' % (self.provider, self.resource_identifier)


class CloudDailyCostSummary(models.Model):
    resource = models.ForeignKey(CloudResourceSummary, on_delete=models.CASCADE, related_name='daily_costs')
    cost_date = models.DateField()
    amount = models.DecimalField(max_digits=14, decimal_places=4)
    currency = models.CharField(max_length=3, default='USD')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'devops_cloud_daily_cost_summary'
        ordering = ['-cost_date', 'resource__provider', 'resource__resource_identifier']
        unique_together = ('resource', 'cost_date', 'currency')


class K8sWorkloadServiceMapping(models.Model):
    """A deliberate service-directory association for one K8s workload."""
    KIND_DEPLOYMENT = 'Deployment'
    KIND_STATEFUL_SET = 'StatefulSet'
    KIND_DAEMON_SET = 'DaemonSet'
    WORKLOAD_KIND_CHOICES = (
        (KIND_DEPLOYMENT, 'Deployment'),
        (KIND_STATEFUL_SET, 'StatefulSet'),
        (KIND_DAEMON_SET, 'DaemonSet'),
    )

    service = models.ForeignKey(
        ServiceCatalog, on_delete=models.CASCADE, related_name='k8s_workload_mappings'
    )
    cluster = models.ForeignKey(
        'K8sCluster', on_delete=models.PROTECT, related_name='service_workload_mappings'
    )
    namespace = models.CharField(max_length=63)
    workload_kind = models.CharField(max_length=20, choices=WORKLOAD_KIND_CHOICES)
    workload_name = models.CharField(max_length=253)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'devops_k8s_workload_service_mapping'
        ordering = ['cluster__name', 'namespace', 'workload_kind', 'workload_name']
        unique_together = ('cluster', 'namespace', 'workload_kind', 'workload_name')

    def __str__(self):
        return '%s/%s %s:%s' % (
            self.cluster, self.namespace, self.workload_kind, self.workload_name,
        )


class ServiceSlo(models.Model):
    """A bounded, safe-to-display service level objective configuration."""
    KIND_AVAILABILITY = 'availability'
    KIND_LATENCY = 'latency'
    KIND_ERROR_RATE = 'error_rate'
    KIND_CHOICES = (
        (KIND_AVAILABILITY, '可用性'),
        (KIND_LATENCY, '延迟'),
        (KIND_ERROR_RATE, '错误率'),
    )

    STATE_HEALTHY = 'healthy'
    STATE_EXHAUSTED = 'exhausted'
    STATE_UNAVAILABLE = 'unavailable'
    STATE_CHOICES = (
        (STATE_HEALTHY, '健康'),
        (STATE_EXHAUSTED, '预算耗尽'),
        (STATE_UNAVAILABLE, '指标不可用'),
    )

    service = models.ForeignKey(ServiceCatalog, on_delete=models.CASCADE, related_name='slos')
    metric_kind = models.CharField(max_length=20, choices=KIND_CHOICES)
    target = models.DecimalField(max_digits=8, decimal_places=3)
    window_minutes = models.PositiveIntegerField(default=60)
    enabled = models.BooleanField(default=True)
    last_state = models.CharField(max_length=20, choices=STATE_CHOICES, default=STATE_UNAVAILABLE)
    # Separately tracks the state that has claimed an exhaustion notification.
    # It is updated conditionally by the scheduler to prevent duplicate sends.
    last_notification_state = models.CharField(max_length=20, choices=STATE_CHOICES, default=STATE_UNAVAILABLE)
    last_summary = models.CharField(max_length=200, blank=True)
    last_evaluated_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'devops_service_slo'
        ordering = ['service__name', 'metric_kind', 'id']
        unique_together = ('service', 'metric_kind')

    def clean(self):
        super(ServiceSlo, self).clean()
        if self.metric_kind not in dict(self.KIND_CHOICES):
            raise ValidationError({'metric_kind': '不支持的 SLO 指标类型'})
        if self.target is None or self.target <= 0:
            raise ValidationError({'target': '目标值必须大于 0'})
        maximum = 60000 if self.metric_kind == self.KIND_LATENCY else 100
        if self.target > maximum:
            raise ValidationError({'target': '目标值超出允许范围'})
        if not self.window_minutes or self.window_minutes > 10080:
            raise ValidationError({'window_minutes': '统计窗口必须介于 1 到 10080 分钟'})

    def __str__(self):
        return '%s:%s' % (self.service, self.metric_kind)


class ServiceSloEvaluation(models.Model):
    """A safe, bounded history record for scheduled SLO evaluations."""
    slo = models.ForeignKey(ServiceSlo, on_delete=models.CASCADE, related_name='evaluations')
    state = models.CharField(max_length=20, choices=ServiceSlo.STATE_CHOICES)
    summary = models.CharField(max_length=200)
    observed_value = models.DecimalField(max_digits=12, decimal_places=4, null=True, blank=True)
    budget_remaining_percent = models.DecimalField(max_digits=7, decimal_places=4, null=True, blank=True)
    burn_rate = models.DecimalField(max_digits=9, decimal_places=4, null=True, blank=True)
    evaluated_at = models.DateTimeField()

    class Meta:
        db_table = 'devops_service_slo_evaluation'
        ordering = ['-evaluated_at', '-id']
        indexes = [
            models.Index(fields=['slo', '-evaluated_at'], name='devops_slo_eval_time_idx'),
        ]


class RunbookTemplate(models.Model):
    """A fixed command template which can only enter the existing approval flow."""
    TRIGGER_ALERT = 'alert'
    TRIGGER_SERVICE = 'service'
    TRIGGER_MANUAL = 'manual'
    TRIGGER_CHOICES = (
        (TRIGGER_ALERT, '告警'),
        (TRIGGER_SERVICE, '服务处置'),
        (TRIGGER_MANUAL, '人工发起'),
    )

    name = models.CharField(max_length=120)
    version = models.PositiveIntegerField(default=1)
    trigger_kind = models.CharField(max_length=20, choices=TRIGGER_CHOICES, default=TRIGGER_MANUAL)
    command_template = models.TextField()
    service = models.ForeignKey(ServiceCatalog, null=True, blank=True, on_delete=models.SET_NULL, related_name='runbook_templates')
    rollback_runbook = models.ForeignKey(
        'self', null=True, blank=True, on_delete=models.PROTECT,
        related_name='primary_runbooks',
    )
    allowed_hosts = models.ManyToManyField(NewLinux, blank=True, related_name='runbook_templates')
    enabled = models.BooleanField(default=True)
    requires_approval = models.BooleanField(default=True)
    created_by = models.CharField(max_length=100, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'devops_runbook_template'
        ordering = ['name', '-version', 'id']
        unique_together = ('name', 'version')

    def clean(self):
        super(RunbookTemplate, self).clean()
        if self.pk:
            original = RunbookTemplate.objects.filter(id=self.pk).values('name', 'version', 'command_template').first()
            if original:
                immutable_fields = {}
                if original['name'] != self.name:
                    immutable_fields['name'] = '已创建运行手册的名称不可修改，请创建新版本'
                if original['version'] != self.version:
                    immutable_fields['version'] = '已创建运行手册的版本不可修改，请创建新版本'
                if original['command_template'] != self.command_template:
                    immutable_fields['command_template'] = '已创建运行手册的命令不可修改，请创建新版本'
                if immutable_fields:
                    raise ValidationError(immutable_fields)
        command = self.command_template or ''
        forbidden = ('{', '}', '$', '`', '\n', '\r', '%s', '%(')
        if not command.strip() or any(token in command for token in forbidden):
            raise ValidationError({'command_template': '运行手册命令必须是固定的单行命令，不能包含插值、替换或调用方参数'})
        if not self.requires_approval:
            raise ValidationError({'requires_approval': '受控运行手册必须经过审批'})
        if self.rollback_runbook_id:
            if self.rollback_runbook_id == self.id:
                raise ValidationError({'rollback_runbook': '回滚运行手册不能关联自身'})
            if not self.rollback_runbook.enabled or not self.rollback_runbook.requires_approval:
                raise ValidationError({'rollback_runbook': '回滚运行手册必须启用且需要审批'})

    def __str__(self):
        return '%s v%s' % (self.name, self.version)


class ServiceDependency(models.Model):
    service = models.ForeignKey(ServiceCatalog, on_delete=models.CASCADE, related_name='upstream_links')
    upstream_service = models.ForeignKey(ServiceCatalog, on_delete=models.CASCADE, related_name='downstream_links')
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'devops_service_dependency'
        unique_together = ('service', 'upstream_service')
        ordering = ['service__name', 'upstream_service__name']

    def __str__(self):
        return '%s -> %s' % (self.service, self.upstream_service)


class MaintenanceWindow(models.Model):
    """A bounded maintenance period that affects explicit hosts or services."""
    name = models.CharField(max_length=120)
    reason = models.CharField(max_length=500, blank=True)
    starts_at = models.DateTimeField()
    ends_at = models.DateTimeField()
    enabled = models.BooleanField(default=True)
    hosts = models.ManyToManyField(NewLinux, blank=True, related_name='maintenance_windows')
    services = models.ManyToManyField(ServiceCatalog, blank=True, related_name='maintenance_windows')
    created_by = models.CharField(max_length=100, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'devops_maintenance_window'
        ordering = ['starts_at', 'id']
        indexes = [
            models.Index(fields=['enabled', 'starts_at', 'ends_at'], name='devops_mw_active_7ed7d1_idx'),
        ]

    def clean(self):
        if self.starts_at and self.ends_at and self.ends_at <= self.starts_at:
            raise ValidationError({'ends_at': '结束时间必须晚于开始时间'})

    def __str__(self):
        return self.name


class AuditLog(models.Model):
    user = models.CharField(max_length=100, blank=True)
    action = models.CharField(max_length=100)
    target_type = models.CharField(max_length=100, blank=True)
    target_id = models.CharField(max_length=100, blank=True)
    detail = models.TextField(blank=True)
    ip_address = models.CharField(max_length=100, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "devops_audit_log"
        ordering = ['-created_at']


class K8sCluster(models.Model):
    STATUS_UNKNOWN = 'unknown'
    STATUS_ONLINE = 'online'
    STATUS_OFFLINE = 'offline'

    STATUS_CHOICES = (
        (STATUS_UNKNOWN, '未检测'),
        (STATUS_ONLINE, '在线'),
        (STATUS_OFFLINE, '离线'),
    )

    name = models.CharField(max_length=100, unique=True)
    api_server = models.CharField(max_length=300, blank=True)
    default_namespace = models.CharField(max_length=100, default='default')
    kubeconfig = models.TextField()
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default=STATUS_UNKNOWN)
    last_error = models.CharField(max_length=300, blank=True)
    created_by = models.CharField(max_length=100, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    last_checked_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = "devops_k8s_cluster"
        ordering = ['name']

    def __str__(self):
        return self.name

    @property
    def decrypted_kubeconfig(self):
        return decrypt_text(self.kubeconfig)

    def save(self, *args, **kwargs):
        self.kubeconfig = encrypt_text(self.kubeconfig)
        super(K8sCluster, self).save(*args, **kwargs)


class PrometheusRuleRevision(models.Model):
    """Server-side desired state for a PrometheusRule change request."""
    ACTION_CREATE = 'create'
    ACTION_UPDATE = 'update'
    ACTION_DELETE = 'delete'
    ACTION_CHOICES = (
        (ACTION_CREATE, '创建'),
        (ACTION_UPDATE, '更新'),
        (ACTION_DELETE, '删除'),
    )
    STATUS_DRAFT = 'draft'
    STATUS_SUBMITTED = 'submitted'
    STATUS_APPROVED = 'approved'
    STATUS_REJECTED = 'rejected'
    STATUS_PUBLISHED = 'published'
    STATUS_FAILED = 'failed'
    STATUS_CHOICES = (
        (STATUS_DRAFT, '草稿'),
        (STATUS_SUBMITTED, '待复核'),
        (STATUS_APPROVED, '已批准'),
        (STATUS_REJECTED, '已拒绝'),
        (STATUS_PUBLISHED, '已发布'),
        (STATUS_FAILED, '发布失败'),
    )

    cluster = models.ForeignKey(K8sCluster, on_delete=models.PROTECT, related_name='prometheus_rule_revisions')
    namespace = models.CharField(max_length=63)
    name = models.CharField(max_length=253)
    action = models.CharField(max_length=20, choices=ACTION_CHOICES)
    # Desired YAML is intentionally never serialized by the governance API.
    desired_yaml = models.TextField(blank=True)
    desired_digest = models.CharField(max_length=64, blank=True)
    baseline_resource_version = models.CharField(max_length=255, blank=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default=STATUS_DRAFT)
    created_by = models.ForeignKey(User, on_delete=models.PROTECT, related_name='prometheus_rule_revisions')
    submitted_at = models.DateTimeField(null=True, blank=True)
    approved_at = models.DateTimeField(null=True, blank=True)
    publish_claimed_at = models.DateTimeField(null=True, blank=True)
    published_at = models.DateTimeField(null=True, blank=True)
    failure_code = models.CharField(max_length=40, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'devops_prometheus_rule_revision'
        ordering = ['-created_at', '-id']
        indexes = [
            models.Index(fields=['cluster', 'namespace', 'name']),
            models.Index(fields=['status']),
        ]

    def clean(self):
        if not self.pk:
            return
        original = PrometheusRuleRevision.objects.get(pk=self.pk)
        immutable_fields = ('cluster_id', 'namespace', 'name', 'action', 'desired_yaml',
                            'desired_digest', 'baseline_resource_version', 'created_by_id')
        for field in immutable_fields:
            if getattr(original, field) != getattr(self, field):
                raise ValidationError('PrometheusRule 修订内容创建后不可修改。')


class PrometheusRuleRevisionReview(models.Model):
    DECISION_APPROVE = 'approve'
    DECISION_REJECT = 'reject'
    DECISION_CHOICES = (
        (DECISION_APPROVE, '批准'),
        (DECISION_REJECT, '拒绝'),
    )

    revision = models.ForeignKey(PrometheusRuleRevision, on_delete=models.PROTECT, related_name='reviews')
    reviewer = models.ForeignKey(User, on_delete=models.PROTECT, related_name='prometheus_rule_reviews')
    decision = models.CharField(max_length=20, choices=DECISION_CHOICES)
    comment = models.CharField(max_length=500, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'devops_prometheus_rule_revision_review'
        ordering = ['created_at', 'id']

    def save(self, *args, **kwargs):
        if self.pk:
            raise ValidationError('PrometheusRule 复核记录不可修改。')
        super(PrometheusRuleRevisionReview, self).save(*args, **kwargs)


class CommandExecution(models.Model):
    STATUS_PENDING = 'pending'
    STATUS_RUNNING = 'running'
    STATUS_SUCCESS = 'success'
    STATUS_FAILED = 'failed'
    STATUS_BLOCKED = 'blocked'

    STATUS_CHOICES = (
        (STATUS_PENDING, '等待执行'),
        (STATUS_RUNNING, '执行中'),
        (STATUS_SUCCESS, '执行成功'),
        (STATUS_FAILED, '执行失败'),
        (STATUS_BLOCKED, '已拦截'),
    )

    host = models.ForeignKey(NewLinux, on_delete=models.CASCADE)
    runbook_template = models.ForeignKey(RunbookTemplate, null=True, blank=True, on_delete=models.PROTECT, related_name='command_executions')
    command = models.TextField()
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default=STATUS_PENDING)
    output = models.TextField(blank=True)
    error = models.TextField(blank=True)
    duration_ms = models.IntegerField(default=0)
    created_by = models.CharField(max_length=100, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    finished_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = "devops_command_execution"
        ordering = ['-created_at']


class RunbookHealthVerification(models.Model):
    """Safe local health evidence for one approved, terminal runbook execution."""
    STATUS_HEALTHY = 'healthy'
    STATUS_UNHEALTHY = 'unhealthy'
    STATUS_CHOICES = (
        (STATUS_HEALTHY, '健康'),
        (STATUS_UNHEALTHY, '不健康'),
    )

    command_execution = models.OneToOneField(
        CommandExecution, on_delete=models.CASCADE, related_name='health_verification',
    )
    status = models.CharField(max_length=20, choices=STATUS_CHOICES)
    active_critical_alert_count = models.PositiveIntegerField(default=0)
    summary = models.CharField(max_length=200)
    rollback_approval = models.ForeignKey(
        'ApprovalRequest', null=True, blank=True, on_delete=models.SET_NULL,
        related_name='runbook_health_verifications',
    )
    verified_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'devops_runbook_health_verification'
        ordering = ['-verified_at', '-id']
        indexes = [
            models.Index(fields=['status', '-verified_at'], name='devops_runbook_health_idx'),
        ]


class RunbookEffectivenessFeedback(models.Model):
    """Append-only, safe operator feedback for an approved runbook execution."""
    CLASSIFICATION_EFFECTIVE = 'effective'
    CLASSIFICATION_PARTIAL = 'partial'
    CLASSIFICATION_INEFFECTIVE = 'ineffective'
    CLASSIFICATION_CHOICES = (
        (CLASSIFICATION_EFFECTIVE, '有效'),
        (CLASSIFICATION_PARTIAL, '部分有效'),
        (CLASSIFICATION_INEFFECTIVE, '无效'),
    )

    command_execution = models.ForeignKey(
        CommandExecution, on_delete=models.CASCADE, related_name='effectiveness_feedbacks',
    )
    classification = models.CharField(max_length=20, choices=CLASSIFICATION_CHOICES)
    note = models.CharField(max_length=300, blank=True)
    created_by = models.CharField(max_length=100, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'devops_runbook_effectiveness_feedback'
        ordering = ['-created_at', '-id']
        indexes = [
            models.Index(fields=['command_execution', '-created_at'], name='devops_runbook_effect_idx'),
        ]


class CommandPolicy(models.Model):
    ACTION_BLOCK = 'block'
    ACTION_REQUIRE_ADMIN = 'require_admin'
    ACTION_ALLOW = 'allow'

    ACTION_CHOICES = (
        (ACTION_BLOCK, '拦截'),
        (ACTION_REQUIRE_ADMIN, '仅管理员可执行'),
        (ACTION_ALLOW, '允许'),
    )

    name = models.CharField(max_length=100)
    pattern = models.CharField(max_length=200, unique=True)
    action = models.CharField(max_length=20, choices=ACTION_CHOICES, default=ACTION_BLOCK)
    enabled = models.BooleanField(default=True)
    reason = models.CharField(max_length=300, blank=True)
    created_by = models.CharField(max_length=100, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "devops_command_policy"
        ordering = ['pattern']

    def __str__(self):
        return self.pattern


class BatchTask(models.Model):
    STATUS_PENDING = 'pending'
    STATUS_RUNNING = 'running'
    STATUS_SUCCESS = 'success'
    STATUS_PARTIAL = 'partial'
    STATUS_FAILED = 'failed'
    STATUS_BLOCKED = 'blocked'

    STATUS_CHOICES = (
        (STATUS_PENDING, '等待执行'),
        (STATUS_RUNNING, '执行中'),
        (STATUS_SUCCESS, '全部成功'),
        (STATUS_PARTIAL, '部分成功'),
        (STATUS_FAILED, '全部失败'),
        (STATUS_BLOCKED, '已拦截'),
    )

    name = models.CharField(max_length=100)
    command = models.TextField()
    hosts = models.ManyToManyField(NewLinux, blank=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default=STATUS_PENDING)
    summary = models.CharField(max_length=300, blank=True)
    created_by = models.CharField(max_length=100, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    finished_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = "devops_batch_task"
        ordering = ['-created_at']


class BatchTaskResult(models.Model):
    task = models.ForeignKey(BatchTask, on_delete=models.CASCADE, related_name='results')
    host = models.ForeignKey(NewLinux, on_delete=models.CASCADE)
    command_execution = models.ForeignKey(CommandExecution, null=True, blank=True, on_delete=models.SET_NULL)
    status = models.CharField(max_length=20, choices=CommandExecution.STATUS_CHOICES, default=CommandExecution.STATUS_PENDING)
    output = models.TextField(blank=True)
    error = models.TextField(blank=True)
    duration_ms = models.IntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "devops_batch_task_result"
        ordering = ['id']


class ServiceOperation(models.Model):
    ACTION_STATUS = 'status'
    ACTION_START = 'start'
    ACTION_STOP = 'stop'
    ACTION_RESTART = 'restart'

    ACTION_CHOICES = (
        (ACTION_STATUS, '查看状态'),
        (ACTION_START, '启动'),
        (ACTION_STOP, '停止'),
        (ACTION_RESTART, '重启'),
    )

    host = models.ForeignKey(NewLinux, on_delete=models.CASCADE)
    service_name = models.CharField(max_length=100)
    action = models.CharField(max_length=20, choices=ACTION_CHOICES)
    status = models.CharField(max_length=20, default=CommandExecution.STATUS_PENDING)
    output = models.TextField(blank=True)
    created_by = models.CharField(max_length=100, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "devops_service_operation"
        ordering = ['-created_at']


class AlertEvent(models.Model):
    LEVEL_INFO = 'info'
    LEVEL_WARNING = 'warning'
    LEVEL_CRITICAL = 'critical'

    STATUS_OPEN = 'open'
    STATUS_PROCESSING = 'processing'
    STATUS_RESOLVED = 'resolved'
    STATUS_CLOSED = 'closed'
    STATUS_SILENCED = 'silenced'

    host = models.ForeignKey(NewLinux, on_delete=models.SET_NULL, null=True, blank=True)
    level = models.CharField(max_length=20, default=LEVEL_WARNING)
    metric = models.CharField(max_length=50, blank=True)
    message = models.TextField()
    status = models.CharField(max_length=20, default=STATUS_OPEN)
    fingerprint = models.CharField(max_length=120, blank=True, db_index=True)
    repeat_count = models.IntegerField(default=1)
    first_seen_at = models.DateTimeField(null=True, blank=True)
    last_seen_at = models.DateTimeField(null=True, blank=True)
    handler = models.CharField(max_length=100, blank=True)
    remark = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "devops_alert_event"
        ordering = ['-created_at']


class AlertSilence(models.Model):
    host = models.ForeignKey(NewLinux, on_delete=models.CASCADE, null=True, blank=True)
    metric = models.CharField(max_length=50, blank=True)
    reason = models.CharField(max_length=300)
    starts_at = models.DateTimeField()
    ends_at = models.DateTimeField()
    created_by = models.CharField(max_length=100, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "devops_alert_silence"
        ordering = ['-ends_at']

    def __str__(self):
        return '%s:%s' % (self.host or '*', self.metric or '*')


class AlertHistory(models.Model):
    alert = models.ForeignKey(AlertEvent, on_delete=models.CASCADE, related_name='histories')
    from_status = models.CharField(max_length=20, blank=True)
    to_status = models.CharField(max_length=20)
    handler = models.CharField(max_length=100, blank=True)
    remark = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "devops_alert_history"
        ordering = ['-created_at']


class AlertQualityFeedback(models.Model):
    CLASSIFICATION_VALID = 'valid'
    CLASSIFICATION_NOISE = 'noise'
    CLASSIFICATION_DUPLICATE = 'duplicate'
    CLASSIFICATION_THRESHOLD = 'threshold'
    CLASSIFICATION_CHOICES = (
        (CLASSIFICATION_VALID, '有效告警'),
        (CLASSIFICATION_NOISE, '噪声告警'),
        (CLASSIFICATION_DUPLICATE, '重复告警'),
        (CLASSIFICATION_THRESHOLD, '阈值待优化'),
    )

    alert = models.ForeignKey(AlertEvent, on_delete=models.CASCADE, related_name='quality_feedbacks')
    classification = models.CharField(max_length=20, choices=CLASSIFICATION_CHOICES)
    note = models.CharField(max_length=300, blank=True)
    created_by = models.CharField(max_length=100, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'devops_alert_quality_feedback'
        ordering = ['-created_at', '-id']
        indexes = [models.Index(fields=['alert', '-created_at'], name='devops_alert_quality_idx')]


class AlertQualityGovernanceReview(models.Model):
    """Auditable review state for a deterministic alert-quality suggestion."""
    STATUS_OPEN = 'open'
    STATUS_ACCEPTED = 'accepted'
    STATUS_REJECTED = 'rejected'
    STATUS_IMPLEMENTED = 'implemented'
    STATUS_CHOICES = (
        (STATUS_OPEN, '待审核'),
        (STATUS_ACCEPTED, '已接受'),
        (STATUS_REJECTED, '已拒绝'),
        (STATUS_IMPLEMENTED, '已实施'),
    )

    suggestion_key = models.CharField(max_length=96, unique=True)
    metric = models.CharField(max_length=50)
    classification = models.CharField(max_length=20, choices=AlertQualityFeedback.CLASSIFICATION_CHOICES)
    action = models.CharField(max_length=50)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default=STATUS_OPEN)
    review_note = models.CharField(max_length=500, blank=True)
    reviewed_by = models.ForeignKey(User, null=True, blank=True, on_delete=models.SET_NULL,
                                    related_name='alert_quality_governance_reviews')
    rule_revision = models.ForeignKey(PrometheusRuleRevision, null=True, blank=True,
                                      on_delete=models.SET_NULL,
                                      related_name='alert_quality_governance_reviews')
    first_seen_at = models.DateTimeField(auto_now_add=True)
    last_seen_at = models.DateTimeField(auto_now=True)
    reviewed_at = models.DateTimeField(null=True, blank=True)
    implemented_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'devops_alert_quality_governance_review'
        ordering = ['status', '-last_seen_at', '-id']
        indexes = [
            models.Index(fields=['status', '-last_seen_at'], name='devops_aqgr_status_seen_idx'),
            models.Index(fields=['metric', 'classification'], name='devops_aqgr_metric_class_idx'),
        ]

    def clean(self):
        if not self.pk:
            return
        original = AlertQualityGovernanceReview.objects.get(pk=self.pk)
        immutable_fields = ('suggestion_key', 'metric', 'classification', 'action')
        for field in immutable_fields:
            if getattr(original, field) != getattr(self, field):
                raise ValidationError('告警质量建议身份创建后不可修改。')


class Incident(models.Model):
    SEVERITY_LOW = 'low'
    SEVERITY_MEDIUM = 'medium'
    SEVERITY_HIGH = 'high'
    SEVERITY_CRITICAL = 'critical'

    STATUS_OPEN = 'open'
    STATUS_PROCESSING = 'processing'
    STATUS_RESOLVED = 'resolved'
    STATUS_CLOSED = 'closed'

    SEVERITY_CHOICES = (
        (SEVERITY_LOW, '低'),
        (SEVERITY_MEDIUM, '中'),
        (SEVERITY_HIGH, '高'),
        (SEVERITY_CRITICAL, '严重'),
    )
    STATUS_CHOICES = (
        (STATUS_OPEN, '已打开'),
        (STATUS_PROCESSING, '处理中'),
        (STATUS_RESOLVED, '已解决'),
        (STATUS_CLOSED, '已关闭'),
    )

    title = models.CharField(max_length=200)
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES, default=SEVERITY_MEDIUM)
    description = models.TextField(blank=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default=STATUS_OPEN)
    host = models.ForeignKey(NewLinux, null=True, blank=True, on_delete=models.SET_NULL)
    alert = models.ForeignKey(AlertEvent, null=True, blank=True, on_delete=models.SET_NULL)
    deployment_release = models.ForeignKey('DeploymentRelease', null=True, blank=True, on_delete=models.SET_NULL)
    command_execution = models.ForeignKey('CommandExecution', null=True, blank=True, on_delete=models.SET_NULL)
    root_cause = models.TextField(blank=True)
    resolution = models.TextField(blank=True)
    follow_up = models.TextField(blank=True)
    owner = models.CharField(max_length=100, blank=True)
    assigned_at = models.DateTimeField(null=True, blank=True)
    sla_due_at = models.DateTimeField(null=True, blank=True)
    created_by = models.CharField(max_length=100, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    resolved_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = 'devops_incident'
        ordering = ['-created_at']

    def __str__(self):
        return self.title


class IncidentTimeline(models.Model):
    incident = models.ForeignKey(Incident, on_delete=models.CASCADE, related_name='timeline')
    note = models.TextField()
    created_by = models.CharField(max_length=100, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'devops_incident_timeline'
        ordering = ['created_at', 'id']


class IncidentActionItem(models.Model):
    STATUS_OPEN = 'open'
    STATUS_IN_PROGRESS = 'in_progress'
    STATUS_COMPLETED = 'completed'
    STATUS_CANCELLED = 'cancelled'
    STATUS_CHOICES = (
        (STATUS_OPEN, '待处理'),
        (STATUS_IN_PROGRESS, '处理中'),
        (STATUS_COMPLETED, '已完成'),
        (STATUS_CANCELLED, '已取消'),
    )
    PRIORITY_LOW = 'low'
    PRIORITY_MEDIUM = 'medium'
    PRIORITY_HIGH = 'high'
    PRIORITY_CRITICAL = 'critical'
    PRIORITY_CHOICES = (
        (PRIORITY_LOW, '低'),
        (PRIORITY_MEDIUM, '中'),
        (PRIORITY_HIGH, '高'),
        (PRIORITY_CRITICAL, '紧急'),
    )

    incident = models.ForeignKey(Incident, on_delete=models.CASCADE, related_name='action_items')
    title = models.CharField(max_length=300)
    description = models.TextField(blank=True)
    assignee = models.ForeignKey(
        'RemoteLinux.User', null=True, blank=True, on_delete=models.SET_NULL,
        related_name='incident_action_items',
    )
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default=STATUS_OPEN)
    priority = models.CharField(max_length=20, choices=PRIORITY_CHOICES, default=PRIORITY_MEDIUM)
    due_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    created_by = models.CharField(max_length=100, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'devops_incident_action_item'
        ordering = ['status', 'due_at', '-created_at', '-id']
        indexes = [
            models.Index(fields=['incident', 'status'], name='devops_ia_incident_status_idx'),
            models.Index(fields=['status', 'due_at'], name='devops_ia_status_due_idx'),
        ]

    def __str__(self):
        return self.title


class InspectionRecommendation(models.Model):
    STATUS_RECOMMENDED = 'recommended'
    STATUS_INITIATED = 'initiated'
    STATUS_CHOICES = (
        (STATUS_RECOMMENDED, '已建议'),
        (STATUS_INITIATED, '已提交审批'),
    )

    compliance_result = models.ForeignKey('ComplianceResult', on_delete=models.CASCADE, related_name='recommendations')
    host = models.ForeignKey(NewLinux, on_delete=models.CASCADE, related_name='inspection_recommendations')
    runbook = models.ForeignKey('RunbookTemplate', on_delete=models.PROTECT, related_name='inspection_recommendations')
    summary = models.CharField(max_length=300, blank=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default=STATUS_RECOMMENDED)
    initiated_approval = models.ForeignKey('ApprovalRequest', null=True, blank=True, on_delete=models.SET_NULL)
    created_by = models.CharField(max_length=100, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'devops_inspection_recommendation'
        unique_together = ('compliance_result', 'runbook')
        ordering = ['-created_at']


class MetricSample(models.Model):
    METRIC_CPU = 'cpu'
    METRIC_MEMORY = 'memory'
    METRIC_DISK = 'disk'

    METRIC_CHOICES = (
        (METRIC_CPU, 'CPU'),
        (METRIC_MEMORY, '内存'),
        (METRIC_DISK, '磁盘'),
    )

    host = models.ForeignKey(NewLinux, on_delete=models.CASCADE)
    metric = models.CharField(max_length=50, choices=METRIC_CHOICES)
    value = models.FloatField()
    unit = models.CharField(max_length=20, default='percent')
    collected_at = models.DateTimeField()
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "devops_metric_sample"
        ordering = ['-collected_at']
        indexes = [
            models.Index(fields=['host', 'metric', '-collected_at']),
        ]


class NotificationChannel(models.Model):
    TYPE_WECOM = 'wecom'
    TYPE_DINGTALK = 'dingtalk'
    TYPE_WEBHOOK = 'webhook'

    TYPE_CHOICES = (
        (TYPE_WECOM, '企业微信'),
        (TYPE_DINGTALK, '钉钉'),
        (TYPE_WEBHOOK, 'Webhook'),
    )

    name = models.CharField(max_length=100)
    channel_type = models.CharField(max_length=20, choices=TYPE_CHOICES, default=TYPE_WEBHOOK)
    webhook_url = models.TextField()
    secret = models.TextField(blank=True)
    notify_alert = models.BooleanField(default=True)
    notify_approval = models.BooleanField(default=True)
    notify_deployment = models.BooleanField(default=True)
    enabled = models.BooleanField(default=True)
    created_by = models.CharField(max_length=100, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "devops_notification_channel"
        ordering = ['name']

    def __str__(self):
        return self.name

    @property
    def decrypted_webhook_url(self):
        return decrypt_text(self.webhook_url)

    @property
    def decrypted_secret(self):
        return decrypt_text(self.secret)

    def save(self, *args, **kwargs):
        self.webhook_url = encrypt_text(self.webhook_url)
        self.secret = encrypt_text(self.secret)
        super(NotificationChannel, self).save(*args, **kwargs)


class NotificationLog(models.Model):
    EVENT_ALERT = 'alert'
    EVENT_APPROVAL = 'approval'
    EVENT_DEPLOYMENT = 'deployment'
    EVENT_TEST = 'test'
    EVENT_INTEGRATION_HEALTH = 'integration_health'

    EVENT_CHOICES = (
        (EVENT_ALERT, '告警'),
        (EVENT_APPROVAL, '审批'),
        (EVENT_DEPLOYMENT, '发布'),
        (EVENT_TEST, '测试'),
        (EVENT_INTEGRATION_HEALTH, '集成健康'),
    )

    STATUS_SUCCESS = 'success'
    STATUS_FAILED = 'failed'

    STATUS_CHOICES = (
        (STATUS_SUCCESS, '成功'),
        (STATUS_FAILED, '失败'),
    )

    channel = models.ForeignKey(NotificationChannel, null=True, blank=True, on_delete=models.SET_NULL, related_name='logs')
    event_type = models.CharField(max_length=30, choices=EVENT_CHOICES)
    title = models.CharField(max_length=150)
    content = models.TextField()
    status = models.CharField(max_length=20, choices=STATUS_CHOICES)
    response = models.TextField(blank=True)
    failure_category = models.CharField(max_length=30, blank=True)
    attempt_count = models.PositiveSmallIntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "devops_notification_log"
        ordering = ['-created_at']


class NotificationTemplate(models.Model):
    EVENT_ALERT = NotificationLog.EVENT_ALERT
    EVENT_APPROVAL = NotificationLog.EVENT_APPROVAL
    EVENT_DEPLOYMENT = NotificationLog.EVENT_DEPLOYMENT

    EVENT_CHOICES = (
        (EVENT_ALERT, '告警'),
        (EVENT_APPROVAL, '审批'),
        (EVENT_DEPLOYMENT, '发布'),
    )

    event_type = models.CharField(max_length=30, choices=EVENT_CHOICES, unique=True)
    title_template = models.CharField(max_length=150, blank=True)
    content_template = models.TextField(blank=True)
    updated_by = models.CharField(max_length=100, blank=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'devops_notification_template'
        ordering = ['event_type']


class AlertNotificationEscalation(models.Model):
    LEVEL_CHOICES = (
        (AlertEvent.LEVEL_INFO, '信息'),
        (AlertEvent.LEVEL_WARNING, '警告'),
        (AlertEvent.LEVEL_CRITICAL, '严重'),
    )

    enabled = models.BooleanField(default=False)
    minimum_level = models.CharField(max_length=20, choices=LEVEL_CHOICES, default=AlertEvent.LEVEL_CRITICAL)
    channel = models.ForeignKey(NotificationChannel, null=True, blank=True, on_delete=models.SET_NULL, related_name='escalation_rules')
    updated_by = models.CharField(max_length=100, blank=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'devops_alert_notification_escalation'

    @classmethod
    def current(cls):
        return cls.objects.first() or cls()


class IntegrationHealthEscalationPolicy(models.Model):
    """Opt-in notification policy for repeated external integration failures."""
    enabled = models.BooleanField(default=False)
    consecutive_failures = models.PositiveSmallIntegerField(default=3)
    cooldown_minutes = models.PositiveIntegerField(default=60)
    notify_recovery = models.BooleanField(default=True)
    channel = models.ForeignKey(
        NotificationChannel, null=True, blank=True, on_delete=models.SET_NULL,
        related_name='integration_health_policies',
    )
    updated_by = models.CharField(max_length=100, blank=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'devops_integration_health_escalation'

    @classmethod
    def current(cls):
        return cls.objects.select_related('channel').first() or cls()


class ServiceOnCallPolicy(models.Model):
    """The current, explicitly maintained on-call route for one service."""
    service = models.OneToOneField(ServiceCatalog, on_delete=models.CASCADE, related_name='oncall_policy')
    primary_user = models.ForeignKey(
        'RemoteLinux.User', on_delete=models.PROTECT, related_name='primary_oncall_policies'
    )
    primary_channel = models.ForeignKey(
        NotificationChannel, on_delete=models.PROTECT, related_name='primary_oncall_policies'
    )
    backup_user = models.ForeignKey(
        'RemoteLinux.User', on_delete=models.PROTECT, related_name='backup_oncall_policies'
    )
    backup_channel = models.ForeignKey(
        NotificationChannel, on_delete=models.PROTECT, related_name='backup_oncall_policies'
    )
    enabled = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'devops_service_oncall_policy'
        ordering = ['service__name']

    def __str__(self):
        return '%s 值班策略' % self.service


class ServiceOnCallRotationMember(models.Model):
    """One ordered weekly primary on-call route for a service policy."""
    policy = models.ForeignKey(
        ServiceOnCallPolicy, on_delete=models.CASCADE, related_name='rotation_members'
    )
    user = models.ForeignKey(
        'RemoteLinux.User', on_delete=models.PROTECT, related_name='oncall_rotation_members'
    )
    channel = models.ForeignKey(
        NotificationChannel, on_delete=models.PROTECT, related_name='oncall_rotation_members'
    )
    position = models.PositiveIntegerField()
    enabled = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'devops_service_oncall_rotation_member'
        ordering = ['policy_id', 'position', 'id']
        unique_together = ('policy', 'position')

    def __str__(self):
        return '%s #%s' % (self.policy, self.position)


class AlertOnCallEscalation(models.Model):
    """One immutable delivery path for an alert matched to a service policy."""
    STATUS_ACTIVE = 'active'
    STATUS_ACKNOWLEDGED = 'acknowledged'
    STATUS_ESCALATED = 'escalated'
    STATUS_CANCELLED = 'cancelled'
    STATUS_FAILED = 'failed'
    STATUS_CHOICES = (
        (STATUS_ACTIVE, '等待确认'),
        (STATUS_ACKNOWLEDGED, '已确认'),
        (STATUS_ESCALATED, '已升级'),
        (STATUS_CANCELLED, '已取消'),
        (STATUS_FAILED, '发送失败'),
    )

    alert = models.ForeignKey(AlertEvent, on_delete=models.CASCADE, related_name='oncall_escalations')
    service = models.ForeignKey(ServiceCatalog, on_delete=models.PROTECT, related_name='alert_oncall_escalations')
    policy = models.ForeignKey(
        ServiceOnCallPolicy, null=True, blank=True, on_delete=models.SET_NULL,
        related_name='alert_escalations'
    )
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default=STATUS_ACTIVE)
    primary_notified_at = models.DateTimeField(null=True, blank=True)
    acknowledged_at = models.DateTimeField(null=True, blank=True)
    backup_claimed_at = models.DateTimeField(null=True, blank=True)
    backup_notified_at = models.DateTimeField(null=True, blank=True)
    cancelled_at = models.DateTimeField(null=True, blank=True)
    failure_category = models.CharField(max_length=30, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'devops_alert_oncall_escalation'
        ordering = ['-created_at', '-id']
        unique_together = ('alert', 'service')
        indexes = [
            models.Index(fields=['status', 'primary_notified_at'], name='devops_oncall_due_idx'),
        ]


class ComplianceBaseline(models.Model):
    TYPE_SERVICE_ACTIVE = 'service_active'
    TYPE_FILE_SHA256 = 'file_sha256'
    TYPE_CHOICES = (
        (TYPE_SERVICE_ACTIVE, '服务运行状态'),
        (TYPE_FILE_SHA256, '文件 SHA-256'),
    )

    name = models.CharField(max_length=100, unique=True)
    baseline_type = models.CharField(max_length=30, choices=TYPE_CHOICES)
    service_name = models.CharField(max_length=100, blank=True)
    file_path = models.CharField(max_length=500, blank=True)
    expected_sha256 = models.CharField(max_length=64, blank=True)
    hosts = models.ManyToManyField(NewLinux, blank=True)
    created_by = models.CharField(max_length=100, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'devops_compliance_baseline'
        ordering = ['name']

    def __str__(self):
        return self.name


class ComplianceResult(models.Model):
    STATE_COMPLIANT = 'compliant'
    STATE_DRIFT = 'drift'
    STATE_ERROR = 'error'
    STATE_CHOICES = (
        (STATE_COMPLIANT, '符合'),
        (STATE_DRIFT, '存在漂移'),
        (STATE_ERROR, '扫描失败'),
    )

    baseline = models.ForeignKey(ComplianceBaseline, on_delete=models.CASCADE, related_name='results')
    host = models.ForeignKey(NewLinux, on_delete=models.CASCADE)
    state = models.CharField(max_length=20, choices=STATE_CHOICES)
    actual_value = models.CharField(max_length=100, blank=True)
    checked_at = models.DateTimeField(auto_now=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'devops_compliance_result'
        unique_together = ('baseline', 'host')
        ordering = ['baseline__name', 'host__linux_name']


def devops_upload_path(instance, filename):
    now = timezone.now()
    return 'devops/%04d/%02d/%02d/%s' % (now.year, now.month, now.day, filename)


class FileDistribution(models.Model):
    STATUS_PENDING = 'pending'
    STATUS_RUNNING = 'running'
    STATUS_SUCCESS = 'success'
    STATUS_PARTIAL = 'partial'
    STATUS_FAILED = 'failed'
    STATUS_BLOCKED = 'blocked'

    STATUS_CHOICES = (
        (STATUS_PENDING, '等待分发'),
        (STATUS_RUNNING, '分发中'),
        (STATUS_SUCCESS, '全部成功'),
        (STATUS_PARTIAL, '部分成功'),
        (STATUS_FAILED, '全部失败'),
        (STATUS_BLOCKED, '已拦截'),
    )

    name = models.CharField(max_length=100)
    source_file = models.FileField(upload_to=devops_upload_path)
    remote_path = models.CharField(max_length=500)
    hosts = models.ManyToManyField(NewLinux, blank=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default=STATUS_PENDING)
    summary = models.CharField(max_length=300, blank=True)
    created_by = models.CharField(max_length=100, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    finished_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = "devops_file_distribution"
        ordering = ['-created_at']


class FileDistributionResult(models.Model):
    distribution = models.ForeignKey(FileDistribution, on_delete=models.CASCADE, related_name='results')
    host = models.ForeignKey(NewLinux, on_delete=models.CASCADE)
    status = models.CharField(max_length=20, choices=CommandExecution.STATUS_CHOICES, default=CommandExecution.STATUS_PENDING)
    message = models.TextField(blank=True)
    duration_ms = models.IntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "devops_file_distribution_result"
        ordering = ['id']


class DeploymentApp(models.Model):
    name = models.CharField(max_length=100, unique=True)
    repository = models.CharField(max_length=140, blank=True, null=True, unique=True)
    description = models.CharField(max_length=300, blank=True)
    created_by = models.CharField(max_length=100, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "devops_deployment_app"
        ordering = ['name']

    def __str__(self):
        return self.name


class DevOpsProject(models.Model):
    name = models.CharField(max_length=100, unique=True)
    owner = models.CharField(max_length=100, blank=True)
    description = models.CharField(max_length=300, blank=True)
    monitoring_enabled = models.BooleanField(default=True)
    monitor_cpu = models.CharField(max_length=20, default='80%')
    monitor_memory = models.CharField(max_length=20, default='80%')
    monitor_disk = models.CharField(max_length=20, default='80%')
    hosts = models.ManyToManyField(NewLinux, blank=True, related_name='devops_projects')
    groups = models.ManyToManyField(HostGroup, blank=True, related_name='devops_projects')
    tags = models.ManyToManyField(HostTag, blank=True, related_name='devops_projects')
    services = models.ManyToManyField(ServiceCatalog, blank=True, related_name='devops_projects')
    deployment_apps = models.ManyToManyField(DeploymentApp, blank=True, related_name='devops_projects')
    created_by = models.CharField(max_length=100, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'devops_project'
        ordering = ['name']

    def __str__(self):
        return self.name


class DeploymentRelease(models.Model):
    STATUS_PENDING = 'pending'
    STATUS_RUNNING = 'running'
    STATUS_SUCCESS = 'success'
    STATUS_PARTIAL = 'partial'
    STATUS_FAILED = 'failed'
    STATUS_BLOCKED = 'blocked'
    STATUS_ROLLED_BACK = 'rolled_back'

    STATUS_CHOICES = (
        (STATUS_PENDING, '等待发布'),
        (STATUS_RUNNING, '发布中'),
        (STATUS_SUCCESS, '发布成功'),
        (STATUS_PARTIAL, '部分成功'),
        (STATUS_FAILED, '发布失败'),
        (STATUS_BLOCKED, '已拦截'),
        (STATUS_ROLLED_BACK, '已回滚'),
    )

    app = models.ForeignKey(DeploymentApp, on_delete=models.CASCADE)
    version = models.CharField(max_length=100)
    description = models.CharField(max_length=300, blank=True)
    deploy_script = models.TextField()
    rollback_script = models.TextField(blank=True)
    hosts = models.ManyToManyField(NewLinux, blank=True)
    rollout_batch_size = models.PositiveSmallIntegerField(default=0)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default=STATUS_PENDING)
    summary = models.CharField(max_length=300, blank=True)
    created_by = models.CharField(max_length=100, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    finished_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = "devops_deployment_release"
        ordering = ['-created_at']

    def __str__(self):
        return '%s:%s' % (self.app.name, self.version)


class CIDelivery(models.Model):
    """Sanitized CI status delivery used for idempotency and quality gates."""
    PROVIDER_JENKINS = 'jenkins'
    PROVIDER_GITLAB = 'gitlab'
    PROVIDER_CHOICES = (
        (PROVIDER_JENKINS, 'Jenkins'),
        (PROVIDER_GITLAB, 'GitLab'),
    )

    provider = models.CharField(max_length=20, choices=PROVIDER_CHOICES)
    repository = models.CharField(max_length=200)
    delivery_id = models.CharField(max_length=128)
    fingerprint = models.CharField(max_length=64, unique=True)
    status = models.CharField(max_length=20)
    revision = models.CharField(max_length=64, blank=True)
    summary = models.CharField(max_length=200)
    release = models.ForeignKey(
        DeploymentRelease, null=True, blank=True, on_delete=models.SET_NULL,
        related_name='ci_deliveries',
    )
    received_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'devops_ci_delivery'
        ordering = ['-received_at', '-id']
        indexes = [
            models.Index(fields=['repository', 'revision'], name='devops_ci_repo_rev_idx'),
            models.Index(fields=['status', '-received_at'], name='devops_ci_status_time_idx'),
        ]


class DeploymentHealthEvaluation(models.Model):
    """A bounded post-release health summary with no raw operational data."""
    STATUS_HEALTHY = 'healthy'
    STATUS_UNHEALTHY = 'unhealthy'
    STATUS_CHOICES = (
        (STATUS_HEALTHY, '健康'),
        (STATUS_UNHEALTHY, '不健康'),
    )

    release = models.ForeignKey(
        DeploymentRelease, on_delete=models.CASCADE, related_name='health_evaluations',
    )
    batch_identity = models.CharField(max_length=200)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES)
    score = models.PositiveSmallIntegerField(default=100)
    summary = models.CharField(max_length=300)
    evaluated_at = models.DateTimeField()

    class Meta:
        db_table = 'devops_deployment_health_evaluation'
        ordering = ['-evaluated_at', '-id']
        indexes = [
            models.Index(fields=['release', '-evaluated_at'], name='devops_release_health_idx'),
        ]


class DeploymentResult(models.Model):
    ACTION_DEPLOY = 'deploy'
    ACTION_ROLLBACK = 'rollback'

    ACTION_CHOICES = (
        (ACTION_DEPLOY, '发布'),
        (ACTION_ROLLBACK, '回滚'),
    )

    release = models.ForeignKey(DeploymentRelease, on_delete=models.CASCADE, related_name='results')
    host = models.ForeignKey(NewLinux, on_delete=models.CASCADE)
    action = models.CharField(max_length=20, choices=ACTION_CHOICES, default=ACTION_DEPLOY)
    command_execution = models.ForeignKey(CommandExecution, null=True, blank=True, on_delete=models.SET_NULL)
    status = models.CharField(max_length=20, choices=CommandExecution.STATUS_CHOICES, default=CommandExecution.STATUS_PENDING)
    output = models.TextField(blank=True)
    error = models.TextField(blank=True)
    duration_ms = models.IntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "devops_deployment_result"
        ordering = ['id']


class BackgroundJob(models.Model):
    """A durable reference to a vetted DevOps operation.

    The queue deliberately stores neither callable paths nor operation input.  The
    target records already hold the encrypted/sensitive values needed by their
    existing execution services.
    """
    TYPE_COMMAND = 'command'
    TYPE_BATCH_TASK = 'batch_task'
    TYPE_FILE_DISTRIBUTION = 'file_distribution'
    TYPE_DEPLOYMENT = 'deployment'
    TYPE_ROLLBACK = 'rollback'

    TYPE_CHOICES = (
        (TYPE_COMMAND, '命令执行'),
        (TYPE_BATCH_TASK, '批量任务'),
        (TYPE_FILE_DISTRIBUTION, '文件分发'),
        (TYPE_DEPLOYMENT, '发布部署'),
        (TYPE_ROLLBACK, '发布回滚'),
    )

    STATUS_PENDING = 'pending'
    STATUS_RUNNING = 'running'
    STATUS_SUCCESS = 'success'
    STATUS_FAILED = 'failed'

    STATUS_CHOICES = (
        (STATUS_PENDING, '等待执行'),
        (STATUS_RUNNING, '执行中'),
        (STATUS_SUCCESS, '执行成功'),
        (STATUS_FAILED, '执行失败'),
    )

    job_type = models.CharField(max_length=30, choices=TYPE_CHOICES)
    target_id = models.PositiveIntegerField()
    role = models.CharField(max_length=20, blank=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default=STATUS_PENDING)
    attempts = models.PositiveIntegerField(default=0)
    error = models.CharField(max_length=500, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    started_at = models.DateTimeField(null=True, blank=True)
    finished_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = 'devops_background_job'
        ordering = ['id']
        indexes = [
            models.Index(fields=['status', 'id'], name='devops_back_status_4bee48_idx'),
        ]


class ScheduledTaskRun(models.Model):
    """The safe, durable state and lease for one built-in scheduler task."""
    STATUS_PENDING = 'pending'
    STATUS_RUNNING = 'running'
    STATUS_SUCCESS = 'success'
    STATUS_FAILED = 'failed'

    STATUS_CHOICES = (
        (STATUS_PENDING, '等待执行'),
        (STATUS_RUNNING, '执行中'),
        (STATUS_SUCCESS, '执行成功'),
        (STATUS_FAILED, '执行失败'),
    )

    task_name = models.CharField(max_length=80, unique=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default=STATUS_PENDING)
    last_summary = models.CharField(max_length=200, blank=True)
    last_started_at = models.DateTimeField(null=True, blank=True)
    last_finished_at = models.DateTimeField(null=True, blank=True)
    next_run_at = models.DateTimeField(null=True, blank=True)
    lease_expires_at = models.DateTimeField(null=True, blank=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'devops_scheduled_task_run'
        ordering = ['task_name']
        indexes = [
            models.Index(fields=['status', 'lease_expires_at'], name='devops_sched_lease_idx'),
            models.Index(fields=['next_run_at'], name='devops_sched_next_idx'),
        ]


class IntegrationHealthEvent(models.Model):
    """Append-only, non-sensitive outcomes for external integration health."""
    TYPE_PROMETHEUS = 'prometheus'
    TYPE_ALERTMANAGER = 'alertmanager'
    TYPE_GITHUB_INBOUND = 'github_inbound'
    TYPE_NOTIFICATION = 'notification'

    TYPE_CHOICES = (
        (TYPE_PROMETHEUS, 'Prometheus'),
        (TYPE_ALERTMANAGER, 'Alertmanager'),
        (TYPE_GITHUB_INBOUND, 'GitHub 入站'),
        (TYPE_NOTIFICATION, '通知渠道'),
    )

    SOURCE_GITHUB_INBOUND = 'github_inbound'

    STATUS_SUCCESS = 'success'
    STATUS_FAILED = 'failed'

    STATUS_CHOICES = (
        (STATUS_SUCCESS, '成功'),
        (STATUS_FAILED, '失败'),
    )

    CATEGORY_OK = 'ok'
    CATEGORY_HTTP_ERROR = 'http_error'
    CATEGORY_TIMEOUT = 'timeout'
    CATEGORY_REQUEST_ERROR = 'request_error'
    CATEGORY_CONFIGURATION = 'configuration'
    CATEGORY_VALIDATION_ERROR = 'validation_error'
    CATEGORY_REJECTED = 'rejected'
    CATEGORY_DUPLICATE = 'duplicate'
    CATEGORY_UNAVAILABLE = 'unavailable'
    CATEGORY_INTERNAL_ERROR = 'internal_error'

    CATEGORY_CHOICES = (
        (CATEGORY_OK, '正常'),
        (CATEGORY_HTTP_ERROR, 'HTTP 错误'),
        (CATEGORY_TIMEOUT, '超时'),
        (CATEGORY_REQUEST_ERROR, '请求异常'),
        (CATEGORY_CONFIGURATION, '配置异常'),
        (CATEGORY_VALIDATION_ERROR, '校验失败'),
        (CATEGORY_REJECTED, '已拒绝'),
        (CATEGORY_DUPLICATE, '重复投递'),
        (CATEGORY_UNAVAILABLE, '服务不可用'),
        (CATEGORY_INTERNAL_ERROR, '内部异常'),
    )

    integration_type = models.CharField(max_length=30, choices=TYPE_CHOICES)
    source_id = models.PositiveIntegerField(null=True, blank=True)
    source_name = models.CharField(max_length=100, blank=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES)
    category = models.CharField(max_length=30, choices=CATEGORY_CHOICES)
    summary = models.CharField(max_length=200)
    occurred_at = models.DateTimeField(default=timezone.now)

    class Meta:
        db_table = 'devops_integration_health_event'
        ordering = ['-occurred_at', '-id']
        indexes = [
            models.Index(fields=['integration_type', 'source_id', '-occurred_at'], name='devops_ihe_type_ref_5b36b3_idx'),
        ]


class VulnerabilityFinding(models.Model):
    SEVERITY_CHOICES = (('low', '低'), ('medium', '中'), ('high', '高'), ('critical', '严重'))
    STATUS_OPEN = 'open'
    STATUS_RESOLVED = 'resolved'
    STATUS_CHOICES = ((STATUS_OPEN, '待处理'), (STATUS_RESOLVED, '已处理'))
    host = models.ForeignKey(NewLinux, on_delete=models.CASCADE, related_name='vulnerability_findings')
    package_name = models.CharField(max_length=128)
    advisory_id = models.CharField(max_length=80)
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default=STATUS_OPEN)
    first_seen_at = models.DateTimeField(auto_now_add=True)
    last_seen_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'devops_vulnerability_finding'
        unique_together = ('host', 'package_name', 'advisory_id')
        indexes = [models.Index(fields=['status', 'severity'])]


class GitOpsDriftFinding(models.Model):
    STATUS_DRIFTED = 'drifted'
    STATUS_IN_SYNC = 'in_sync'
    STATUS_CHOICES = ((STATUS_DRIFTED, '存在漂移'), (STATUS_IN_SYNC, '已同步'))
    cluster = models.ForeignKey(K8sCluster, on_delete=models.PROTECT, related_name='gitops_drift_findings')
    namespace = models.CharField(max_length=63)
    resource_name = models.CharField(max_length=253)
    resource_kind = models.CharField(max_length=40)
    desired_digest = models.CharField(max_length=64)
    observed_digest = models.CharField(max_length=64)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default=STATUS_DRIFTED)
    first_seen_at = models.DateTimeField(auto_now_add=True)
    last_seen_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'devops_gitops_drift_finding'
        unique_together = ('cluster', 'namespace', 'resource_name', 'resource_kind')
        indexes = [models.Index(fields=['cluster', 'status'])]


CONTROLLED_INTEGRATION_STATUS_CHOICES = (
    ('pending', '等待执行'),
    ('running', '执行中'),
    ('success', '执行成功'),
    ('failed', '执行失败'),
    ('blocked', '已拦截'),
)


class IntegrationConnector(models.Model):
    TYPE_GITOPS = 'gitops'
    TYPE_VULNERABILITY = 'vulnerability'
    TYPE_CHOICES = (
        (TYPE_GITOPS, 'GitOps'),
        (TYPE_VULNERABILITY, '漏洞导入'),
    )

    name = models.CharField(max_length=100, unique=True)
    connector_type = models.CharField(max_length=30, choices=TYPE_CHOICES)
    enabled = models.BooleanField(default=False)
    read_only = models.BooleanField(default=True)
    schedule = models.CharField(max_length=100, blank=True)
    config_encrypted = models.TextField(blank=True)
    last_status = models.CharField(max_length=20, choices=CONTROLLED_INTEGRATION_STATUS_CHOICES, default='blocked')
    last_outcome_category = models.CharField(max_length=40, blank=True)
    last_run_at = models.DateTimeField(null=True, blank=True)
    created_by = models.CharField(max_length=100, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __init__(self, *args, **kwargs):
        config = kwargs.pop('config', None)
        super().__init__(*args, **kwargs)
        if config is not None:
            self.set_config(config)

    def set_config(self, value):
        if not isinstance(value, dict):
            raise ValueError('连接器配置必须是对象')
        self.config_encrypted = encrypt_text(json.dumps(value, sort_keys=True, separators=(',', ':')))

    def get_config(self):
        if not self.config_encrypted:
            return {}
        try:
            value = json.loads(decrypt_text(self.config_encrypted))
        except (TypeError, ValueError):
            return {}
        return value if isinstance(value, dict) else {}

    @property
    def config(self):
        return self.get_config()

    @config.setter
    def config(self, value):
        self.set_config(value)

    def safe_summary(self):
        return {
            'id': self.id,
            'name': self.name,
            'connector_type': self.connector_type,
            'enabled': self.enabled,
            'read_only': self.read_only,
            'status': self.last_status,
        }

    class Meta:
        db_table = 'devops_integration_connector'
        ordering = ['name', 'id']


class GitOpsCollectionRun(models.Model):
    STATUS_PENDING = 'pending'
    STATUS_RUNNING = 'running'
    STATUS_SUCCESS = 'success'
    STATUS_FAILED = 'failed'
    STATUS_BLOCKED = 'blocked'

    connector = models.ForeignKey(IntegrationConnector, on_delete=models.PROTECT, related_name='gitops_runs')
    status = models.CharField(max_length=20, choices=CONTROLLED_INTEGRATION_STATUS_CHOICES, default='pending')
    outcome_category = models.CharField(max_length=40, blank=True)
    finding_count = models.PositiveIntegerField(default=0)
    triggered_by = models.CharField(max_length=100, blank=True)
    started_at = models.DateTimeField(default=timezone.now)
    finished_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'devops_gitops_collection_run'
        ordering = ['-created_at', '-id']
        indexes = [models.Index(fields=['connector', '-created_at'], name='devops_gcr_connector_time_idx')]


class VulnerabilityImportRun(models.Model):
    STATUS_PENDING = 'pending'
    STATUS_RUNNING = 'running'
    STATUS_SUCCESS = 'success'
    STATUS_FAILED = 'failed'
    STATUS_BLOCKED = 'blocked'

    connector = models.ForeignKey(IntegrationConnector, on_delete=models.PROTECT, related_name='vulnerability_runs')
    status = models.CharField(max_length=20, choices=CONTROLLED_INTEGRATION_STATUS_CHOICES, default='pending')
    outcome_category = models.CharField(max_length=40, blank=True)
    finding_count = models.PositiveIntegerField(default=0)
    triggered_by = models.CharField(max_length=100, blank=True)
    started_at = models.DateTimeField(default=timezone.now)
    finished_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'devops_vulnerability_import_run'
        ordering = ['-created_at', '-id']
        indexes = [models.Index(fields=['connector', '-created_at'], name='devops_vir_connector_time_idx')]


class InfrastructureBlueprint(models.Model):
    name = models.CharField(max_length=100, unique=True)
    provider_type = models.CharField(max_length=30)
    enabled = models.BooleanField(default=False)
    read_only = models.BooleanField(default=True)
    definition_digest = models.CharField(max_length=64, blank=True)
    summary = models.CharField(max_length=200, blank=True)
    created_by = models.CharField(max_length=100, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __init__(self, *args, **kwargs):
        definition = kwargs.pop('definition', None)
        super().__init__(*args, **kwargs)
        if definition is not None:
            self.set_definition(definition)

    def set_definition(self, value):
        if not isinstance(value, (dict, list)):
            raise ValueError('蓝图定义必须是对象或列表')
        serialized = json.dumps(value, sort_keys=True, separators=(',', ':'))
        self.definition_digest = hashlib.sha256(serialized.encode('utf-8')).hexdigest()

    def safe_summary(self):
        return {
            'id': self.id,
            'name': self.name,
            'provider_type': self.provider_type,
            'enabled': self.enabled,
            'read_only': self.read_only,
            'definition_digest': self.definition_digest,
            'summary': self.summary,
        }

    class Meta:
        db_table = 'devops_infrastructure_blueprint'
        ordering = ['name', 'id']


class InfrastructurePlan(models.Model):
    STATUS_PENDING = 'pending'
    STATUS_RUNNING = 'running'
    STATUS_SUCCESS = 'success'
    STATUS_FAILED = 'failed'
    STATUS_BLOCKED = 'blocked'

    blueprint = models.ForeignKey(InfrastructureBlueprint, on_delete=models.PROTECT, related_name='plans')
    status = models.CharField(max_length=20, choices=CONTROLLED_INTEGRATION_STATUS_CHOICES, default='pending')
    outcome_category = models.CharField(max_length=40, blank=True)
    definition_digest = models.CharField(max_length=64, blank=True)
    resource_count = models.PositiveIntegerField(default=0)
    summary = models.CharField(max_length=200, blank=True)
    requested_by = models.CharField(max_length=100, blank=True)
    started_at = models.DateTimeField(default=timezone.now)
    finished_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def safe_summary(self):
        return {
            'id': self.id,
            'blueprint_id': self.blueprint_id,
            'status': self.status,
            'outcome_category': self.outcome_category,
            'definition_digest': self.definition_digest,
            'resource_count': self.resource_count,
            'summary': self.summary,
            'created_at': self.created_at,
        }

    class Meta:
        db_table = 'devops_infrastructure_plan'
        ordering = ['-created_at', '-id']
        indexes = [models.Index(fields=['blueprint', '-created_at'], name='devops_ip_blueprint_time_idx')]


class ApprovalRequest(models.Model):
    TYPE_COMMAND = 'command'
    TYPE_DEPLOYMENT = 'deployment'
    TYPE_ROLLBACK = 'rollback'

    TYPE_CHOICES = (
        (TYPE_COMMAND, '命令执行'),
        (TYPE_DEPLOYMENT, '发布部署'),
        (TYPE_ROLLBACK, '发布回滚'),
    )

    STATUS_PENDING = 'pending'
    STATUS_APPROVED = 'approved'
    STATUS_REJECTED = 'rejected'
    STATUS_EXECUTED = 'executed'
    STATUS_FAILED = 'failed'

    STATUS_CHOICES = (
        (STATUS_PENDING, '待审批'),
        (STATUS_APPROVED, '已批准'),
        (STATUS_REJECTED, '已拒绝'),
        (STATUS_EXECUTED, '已执行'),
        (STATUS_FAILED, '执行失败'),
    )

    request_type = models.CharField(max_length=30, choices=TYPE_CHOICES)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default=STATUS_PENDING)
    title = models.CharField(max_length=150)
    reason = models.CharField(max_length=500, blank=True)
    requester = models.CharField(max_length=100, blank=True)
    approver = models.CharField(max_length=100, blank=True)
    comment = models.CharField(max_length=500, blank=True)
    host = models.ForeignKey(NewLinux, null=True, blank=True, on_delete=models.SET_NULL)
    command = models.TextField(blank=True)
    deployment_release = models.ForeignKey(DeploymentRelease, null=True, blank=True, on_delete=models.SET_NULL)
    command_execution = models.ForeignKey(CommandExecution, null=True, blank=True, on_delete=models.SET_NULL)
    created_at = models.DateTimeField(auto_now_add=True)
    decided_at = models.DateTimeField(null=True, blank=True)
    executed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = "devops_approval_request"
        ordering = ['-created_at']
