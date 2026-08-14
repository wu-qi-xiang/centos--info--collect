from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ('devops', '0046_integration_health_escalation'),
    ]

    operations = [
        migrations.AlterField(
            model_name='notificationlog',
            name='event_type',
            field=models.CharField(
                choices=[
                    ('alert', '告警'), ('approval', '审批'), ('deployment', '发布'),
                    ('test', '测试'), ('integration_health', '集成健康'),
                ], max_length=30,
            ),
        ),
    ]
