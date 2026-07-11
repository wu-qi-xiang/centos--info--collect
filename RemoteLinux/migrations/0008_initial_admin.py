from django.contrib.auth.hashers import check_password, make_password
from django.db import migrations


def create_initial_admin(apps, schema_editor):
	User = apps.get_model('RemoteLinux', 'User')
	user, created = User.objects.get_or_create(
		user='admin',
		defaults={
			'email': 'admin@example.com',
			'password': '',
			'confirm_pwd': '',
		},
	)
	if created or not check_password('Wx@123456', user.password):
		password = make_password('Wx@123456')
		user.password = password
		user.confirm_pwd = password
		user.save(update_fields=['password', 'confirm_pwd'])


class Migration(migrations.Migration):

	dependencies = [
		('RemoteLinux', '0007_expand_user_password_hashes'),
	]

	operations = [
		migrations.RunPython(create_initial_admin, migrations.RunPython.noop),
	]
