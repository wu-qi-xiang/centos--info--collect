from django.db import models
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

    user = models.ForeignKey(User, on_delete=models.CASCADE)
    module = models.CharField(max_length=30, choices=MODULE_CHOICES)
    role = models.CharField(max_length=20, choices=DevOpsRole.ROLE_CHOICES, default=DevOpsRole.ROLE_VIEWER)
    created_by = models.CharField(max_length=100, blank=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "devops_module_permission"
        unique_together = ('user', 'module')
        ordering = ['user__user', 'module']

    def __str__(self):
        return '%s:%s:%s' % (self.user.user, self.module, self.role)


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

    EVENT_CHOICES = (
        (EVENT_ALERT, '告警'),
        (EVENT_APPROVAL, '审批'),
        (EVENT_DEPLOYMENT, '发布'),
        (EVENT_TEST, '测试'),
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
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "devops_notification_log"
        ordering = ['-created_at']


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
    description = models.CharField(max_length=300, blank=True)
    created_by = models.CharField(max_length=100, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "devops_deployment_app"
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
