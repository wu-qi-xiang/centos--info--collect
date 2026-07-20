"""Create a database backup using the configured Django database backend."""
from __future__ import print_function

import json
import os
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError


SQLITE_ENGINE = 'django.db.backends.sqlite3'
MYSQL_ENGINES = ('django.db.backends.mysql', 'django.db.backends.mysql.base')
POSTGRES_ENGINES = ('django.db.backends.postgresql', 'django.db.backends.postgresql_psycopg2')


def safe_output_path(value):
    """Resolve a deliberately supplied output path without following symlinks."""
    supplied = Path(value).expanduser()
    if not value or '..' in supplied.parts:
        raise CommandError('Backup output must be an explicit path without parent traversal.')
    output = supplied.absolute()
    current = Path(output.anchor)
    for component in output.parts[1:]:
        current /= component
        if current.is_symlink():
            raise CommandError('Backup output must not traverse a symbolic link.')
    if not output.parent.is_dir() or output.parent.is_symlink():
        raise CommandError('Backup output parent must be an existing regular directory.')
    if output.exists() and (not output.is_file() or output.is_symlink()):
        raise CommandError('Backup output must be a regular file path.')
    return output


def database_config():
    config = dict(getattr(settings, 'DATABASES', {}).get('default', {}) or {})
    if not config.get('ENGINE'):
        raise CommandError('The default Django database engine is not configured.')
    return config


def dump_environment(config, backend):
    environment = os.environ.copy()
    password = str(config.get('PASSWORD', '') or '')
    if password:
        environment['MYSQL_PWD' if backend == 'mysql' else 'PGPASSWORD'] = password
    return environment


def mysql_dump_command(config, output):
    command = ['mysqldump', '--single-transaction', '--routines', '--events']
    host = str(config.get('HOST', '') or '')
    port = str(config.get('PORT', '') or '')
    user = str(config.get('USER', '') or '')
    if host:
        command.extend(['--host', host])
    if port:
        command.extend(['--port', port])
    if user:
        command.extend(['--user', user])
    command.extend(['--result-file', str(output), '--databases', str(config.get('NAME', '') or '')])
    if not config.get('NAME'):
        raise CommandError('MySQL backup requires a configured database name.')
    return command


def postgres_dump_command(config, output):
    command = ['pg_dump', '--format=custom', '--file', str(output)]
    host = str(config.get('HOST', '') or '')
    port = str(config.get('PORT', '') or '')
    user = str(config.get('USER', '') or '')
    if host:
        command.extend(['--host', host])
    if port:
        command.extend(['--port', port])
    if user:
        command.extend(['--username', user])
    name = str(config.get('NAME', '') or '')
    if not name:
        raise CommandError('PostgreSQL backup requires a configured database name.')
    command.extend(['--dbname', name])
    return command


def encrypt_archive(source, destination):
    """Load the existing backup crypto helper without making scripts a Django app."""
    scripts_directory = str(Path(settings.BASE_DIR) / 'scripts')
    if scripts_directory not in sys.path:
        sys.path.insert(0, scripts_directory)
    from backup_crypto import encrypt_file
    encrypt_file(source, destination, secret=getattr(settings, 'DATA_ENCRYPTION_KEY', ''))


class Command(BaseCommand):
    help = 'Create an encrypted SQLite archive or a controlled MySQL/PostgreSQL database dump.'

    def add_arguments(self, parser):
        parser.add_argument('--output', required=True, help='New explicit local backup output path.')
        parser.add_argument('--upload-s3', action='store_true', help='Upload an encrypted archive using BACKUP_S3_* settings.')
        parser.add_argument('--dry-run', action='store_true', help='Validate the selected backup plan without writing or contacting S3.')
        parser.add_argument('--force', action='store_true', help='Allow replacing an existing regular output file.')

    def _run(self, command, environment=None):
        try:
            subprocess.run(command, check=True, env=environment)
        except (OSError, subprocess.CalledProcessError):
            raise CommandError('Backup command failed; inspect protected server logs for the underlying process error.')

    def _sqlite_plan(self, config, output, upload_s3):
        database = safe_output_path(str(config.get('NAME', '') or ''))
        if not database.is_file() or database.is_symlink():
            raise CommandError('SQLite backup requires an existing regular database file.')
        if not str(output).endswith('.tar.gz.enc'):
            raise CommandError('SQLite backup output must end with .tar.gz.enc.')
        if not getattr(settings, 'DATA_ENCRYPTION_KEY', ''):
            raise CommandError('SQLite encrypted backup requires DATA_ENCRYPTION_KEY.')
        uploads = Path(getattr(settings, 'MEDIA_ROOT', '')).absolute()
        if not uploads.is_dir() or uploads.is_symlink():
            raise CommandError('SQLite backup requires MEDIA_ROOT to be an existing regular directory.')
        root = Path(settings.BASE_DIR)
        local_command = [
            sys.executable, str(root / 'scripts' / 'backup_local.py'),
            '--database', str(database), '--uploads', str(uploads), '--output', str(output),
            '--encrypt',
        ]
        return local_command, self._s3_command(output) if upload_s3 else None

    def _s3_command(self, output):
        config_s3 = getattr(settings, 'BACKUP_S3_CONFIG', {}) or {}
        if not config_s3.get('enabled'):
            raise CommandError('S3 upload requires configured BACKUP_S3_BUCKET settings.')
        root = Path(settings.BASE_DIR)
        command = [
            sys.executable, str(root / 'scripts' / 'backup_s3.py'),
            '--archive', str(output), '--bucket', str(config_s3['bucket']),
            '--prefix', str(config_s3['prefix']),
            '--retention-days', str(getattr(settings, 'BACKUP_RETENTION_DAYS', 30)),
        ]
        if config_s3.get('endpoint_url'):
            command.extend(['--endpoint-url', str(config_s3['endpoint_url'])])
        if config_s3.get('region_name'):
            command.extend(['--region', str(config_s3['region_name'])])
        return command

    def _create_encrypted_dump_archive(self, dump_command, environment, output, backend):
        """Dump into a private temporary directory, then encrypt the final archive."""
        with tempfile.TemporaryDirectory(prefix='pylinux-dump-', dir=str(output.parent)) as temporary:
            temporary_path = Path(temporary)
            database_name = 'database.sql' if backend == 'mysql' else 'database.dump'
            dump_path = temporary_path / database_name
            command = list(dump_command)
            if backend == 'mysql':
                command[command.index('--result-file') + 1] = str(dump_path)
            else:
                command[command.index('--file') + 1] = str(dump_path)
            self._run(command, environment)
            if not dump_path.is_file() or dump_path.is_symlink():
                raise CommandError('Database dump command did not create a regular backup file.')
            manifest_path = temporary_path / 'manifest.json'
            manifest_path.write_text(json.dumps({
                'format_version': 2,
                'database_backend': backend,
                'database_member': database_name,
                'encrypted': True,
            }, sort_keys=True) + '\n', encoding='utf-8')
            archive_path = temporary_path / 'backup.tar.gz'
            with tarfile.open(str(archive_path), 'w:gz', format=tarfile.PAX_FORMAT) as archive:
                archive.add(str(manifest_path), arcname='manifest.json', recursive=False)
                archive.add(str(dump_path), arcname=database_name, recursive=False)
            encrypt_archive(archive_path, output)

    def handle(self, *args, **options):
        output = safe_output_path(options['output'])
        if output.exists() and not options['force']:
            raise CommandError('Backup output already exists; use --force to replace it.')
        config = database_config()
        engine = config['ENGINE']
        dry_run = options['dry_run']

        if engine == SQLITE_ENGINE:
            local_command, s3_command = self._sqlite_plan(config, output, options['upload_s3'])
            if dry_run:
                self.stdout.write('Validated encrypted SQLite backup plan; no local or remote changes were made.')
                return
            if output.exists() and options['force']:
                output.unlink()
            self._run(local_command)
            if s3_command:
                self._run(s3_command)
            self.stdout.write('Encrypted SQLite backup completed.')
            return

        if engine in MYSQL_ENGINES:
            if not getattr(settings, 'DATA_ENCRYPTION_KEY', ''):
                raise CommandError('MySQL encrypted backup requires DATA_ENCRYPTION_KEY.')
            if not str(output).endswith('.tar.gz.enc'):
                raise CommandError('MySQL backup output must end with .tar.gz.enc.')
            command = mysql_dump_command(config, output)
            backend = 'mysql'
        elif engine in POSTGRES_ENGINES:
            if not getattr(settings, 'DATA_ENCRYPTION_KEY', ''):
                raise CommandError('PostgreSQL encrypted backup requires DATA_ENCRYPTION_KEY.')
            if not str(output).endswith('.tar.gz.enc'):
                raise CommandError('PostgreSQL backup output must end with .tar.gz.enc.')
            command = postgres_dump_command(config, output)
            backend = 'postgresql'
        else:
            raise CommandError('Unsupported database engine for managed backup: %s' % engine)
        s3_command = self._s3_command(output) if options['upload_s3'] else None
        if dry_run:
            self.stdout.write('Validated controlled %s dump plan; no local changes were made.' % backend)
            return
        if output.exists() and options['force']:
            output.unlink()
        self._create_encrypted_dump_archive(command, dump_environment(config, backend), output, backend)
        if s3_command:
            self._run(s3_command)
        self.stdout.write('Encrypted %s database backup completed.' % backend)
