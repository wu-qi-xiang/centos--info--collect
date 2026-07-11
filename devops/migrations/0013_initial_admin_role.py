from django.db import migrations


def create_initial_admin_role(apps, schema_editor):
    User = apps.get_model('RemoteLinux', 'User')
    DevOpsRole = apps.get_model('devops', 'DevOpsRole')
    try:
        admin = User.objects.get(user='admin')
    except User.DoesNotExist:
        return
    DevOpsRole.objects.update_or_create(
        user=admin,
        defaults={'role': 'admin'},
    )


class Migration(migrations.Migration):

    dependencies = [
        ('RemoteLinux', '0008_initial_admin'),
        ('devops', '0012_k8s_cluster'),
    ]

    operations = [
        migrations.RunPython(create_initial_admin_role, migrations.RunPython.noop),
    ]
