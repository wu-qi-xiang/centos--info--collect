from django.db import migrations, models
import django.db.models.deletion

class Migration(migrations.Migration):
    dependencies = [('aiops', '0005_aiopsinvestigation')]
    operations = [migrations.CreateModel(name='AiopsInvestigationFeedback', fields=[
        ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
        ('classification', models.CharField(choices=[('effective', '有效'), ('partial', '部分有效'), ('ineffective', '无效')], max_length=20)),
        ('note', models.CharField(blank=True, max_length=300)), ('created_by', models.CharField(blank=True, max_length=100)),
        ('created_at', models.DateTimeField(auto_now_add=True)),
        ('investigation', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='feedback', to='aiops.aiopsinvestigation')),
    ], options={'db_table': 'aiops_investigation_feedback', 'ordering': ['-created_at', '-id']})]
