from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    dependencies = [
        ('devops', '0045_alert_quality_governance_review'),
    ]

    operations = [
        migrations.CreateModel(
            name='IntegrationHealthEscalationPolicy',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('enabled', models.BooleanField(default=False)),
                ('consecutive_failures', models.PositiveSmallIntegerField(default=3)),
                ('cooldown_minutes', models.PositiveIntegerField(default=60)),
                ('notify_recovery', models.BooleanField(default=True)),
                ('updated_by', models.CharField(blank=True, max_length=100)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('channel', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='integration_health_policies', to='devops.notificationchannel')),
            ],
            options={'db_table': 'devops_integration_health_escalation'},
        ),
    ]
