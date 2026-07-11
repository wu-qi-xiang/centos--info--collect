from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('devops', '0011_host_scope_tags'),
    ]

    operations = [
        migrations.CreateModel(
            name='K8sCluster',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=100, unique=True)),
                ('api_server', models.CharField(blank=True, max_length=300)),
                ('default_namespace', models.CharField(default='default', max_length=100)),
                ('kubeconfig', models.TextField()),
                ('status', models.CharField(choices=[('unknown', '未检测'), ('online', '在线'), ('offline', '离线')], default='unknown', max_length=20)),
                ('last_error', models.CharField(blank=True, max_length=300)),
                ('created_by', models.CharField(blank=True, max_length=100)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('last_checked_at', models.DateTimeField(blank=True, null=True)),
            ],
            options={
                'db_table': 'devops_k8s_cluster',
                'ordering': ['name'],
            },
        ),
        migrations.AlterField(
            model_name='devopsmodulepermission',
            name='module',
            field=models.CharField(choices=[('command', '命令执行'), ('task', '批量任务'), ('service', '服务管理'), ('file', '文件分发'), ('deployment', '发布部署'), ('approval', '审批流'), ('alert', '告警治理'), ('metric', '监控历史'), ('security', '安全策略'), ('audit', '审计日志'), ('cluster', 'K8s集群')], max_length=30),
        ),
    ]
