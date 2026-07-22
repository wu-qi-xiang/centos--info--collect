"""Verify and restore a local runtime archive into an isolated directory."""
from __future__ import print_function

import importlib.util
import json
import sqlite3
import sys
import tarfile
from pathlib import Path
from types import SimpleNamespace

from cryptography.exceptions import InvalidTag
from django.conf import settings
from django.core.management.base import BaseCommand, CommandError


def load_restore_preflight():
    """Load the existing validated restore helper from the repository scripts path."""
    scripts_directory = Path(settings.BASE_DIR) / 'scripts'
    preflight_path = scripts_directory / 'restore_preflight.py'
    if not preflight_path.is_file():
        raise CommandError('Restore verification helper is unavailable.')
    scripts_directory_text = str(scripts_directory)
    if scripts_directory_text not in sys.path:
        sys.path.insert(0, scripts_directory_text)
    specification = importlib.util.spec_from_file_location('pylinux_restore_preflight', str(preflight_path))
    if specification is None or specification.loader is None:
        raise CommandError('Restore verification helper is unavailable.')
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


class Command(BaseCommand):
    help = 'Verify and restore a local encrypted backup archive only into an empty isolated directory.'

    def add_arguments(self, parser):
        parser.add_argument('--archive', required=True, help='Explicit local encrypted .tar.gz.enc archive.')
        parser.add_argument('--target-dir', required=True, help='Existing empty isolated restore directory.')

    def handle(self, *args, **options):
        if not str(options['archive']).endswith('.tar.gz.enc'):
            raise CommandError('Restore archive must be an encrypted .tar.gz.enc file.')
        try:
            load_restore_preflight().preflight(SimpleNamespace(
                archive=options['archive'], target_dir=options['target_dir'],
            ))
        except (OSError, sqlite3.Error, ValueError, InvalidTag, tarfile.TarError, json.JSONDecodeError) as error:
            raise CommandError('Restore verification failed: %s' % error)
