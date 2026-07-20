#!/usr/bin/env python3
"""Create a self-contained, local SQLite and uploads backup archive."""
from __future__ import print_function

import argparse
import datetime
import hashlib
import json
import os
import sqlite3
import stat
import sys
import tarfile
import tempfile
from pathlib import Path

from backup_crypto import encrypt_file


ARCHIVE_SUFFIX = '.tar.gz'
ENCRYPTED_ARCHIVE_SUFFIX = '.tar.gz.enc'
SENSITIVE_UPLOAD_NAMES = {'.env', 'id_rsa', 'id_dsa', 'id_ecdsa', 'id_ed25519'}
SENSITIVE_UPLOAD_SUFFIXES = ('.pem', '.key', '.p12', '.pfx')


def fail(message):
    raise ValueError(message)


def explicit_path(value, label):
    supplied = Path(value).expanduser()
    if '..' in supplied.parts:
        fail('%s must not contain parent-directory traversal' % label)
    path = supplied.absolute()
    current = Path(path.anchor)
    for component in path.parts[1:]:
        current /= component
        if current.is_symlink():
            fail('%s must not traverse a symbolic link' % label)
    return path


def regular_file(path, label):
    if not path.exists() or not path.is_file() or path.is_symlink():
        fail('%s must be an existing regular file' % label)


def existing_directory(path, label):
    if not path.exists() or not path.is_dir() or path.is_symlink():
        fail('%s must be an existing directory' % label)


def validate_output_path(path, uploads_dir, force):
    if path.name in ('', '.', '..') or str(path) == os.path.sep:
        fail('output must be a specific archive file')
    if not (str(path).endswith(ARCHIVE_SUFFIX) or str(path).endswith(ENCRYPTED_ARCHIVE_SUFFIX)):
        fail('output archive must end with %s or %s' % (ARCHIVE_SUFFIX, ENCRYPTED_ARCHIVE_SUFFIX))
    existing_directory(path.parent, 'output parent')
    if path.exists() and (not path.is_file() or path.is_symlink()):
        fail('output must be a regular file path')
    if path.exists() and not force:
        fail('output already exists; use --force to replace that archive')
    try:
        path.relative_to(uploads_dir)
    except ValueError:
        return
    fail('output archive must not be inside the uploads directory')


def upload_entries(uploads_dir):
    entries = []
    for root, directories, filenames in os.walk(str(uploads_dir), followlinks=False):
        root_path = Path(root)
        for directory in directories:
            directory_path = root_path / directory
            if directory_path.is_symlink():
                fail('uploads contains a symbolic link: %s' % directory_path)
        for filename in filenames:
            source = root_path / filename
            relative = source.relative_to(uploads_dir)
            lower_name = filename.lower()
            if (lower_name in SENSITIVE_UPLOAD_NAMES or lower_name.startswith('.env.') or
                    lower_name.endswith(SENSITIVE_UPLOAD_SUFFIXES)):
                fail('uploads contains a sensitive runtime file: %s' % relative)
            if source.is_symlink() or not stat.S_ISREG(source.stat().st_mode):
                fail('uploads contains a non-regular file: %s' % relative)
            entries.append((source, relative))
    return sorted(entries, key=lambda item: item[1].as_posix())


def sha256_path(path):
    digest = hashlib.sha256()
    with path.open('rb') as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def sqlite_backup(source, destination):
    source_connection = sqlite3.connect(str(source))
    try:
        destination_connection = sqlite3.connect(str(destination))
        try:
            source_connection.backup(destination_connection)
        finally:
            destination_connection.close()
    finally:
        source_connection.close()


def add_file(archive, source, member_name):
    info = archive.gettarinfo(str(source), arcname=member_name)
    info.uid = 0
    info.gid = 0
    info.uname = ''
    info.gname = ''
    info.mtime = 0
    with source.open('rb') as handle:
        archive.addfile(info, handle)


def create_backup(args):
    database = explicit_path(args.database, 'database')
    uploads = explicit_path(args.uploads, 'uploads')
    output = explicit_path(args.output, 'output')
    regular_file(database, 'database')
    existing_directory(uploads, 'uploads')
    validate_output_path(output, uploads, args.force)
    if args.encrypt and not str(output).endswith(ENCRYPTED_ARCHIVE_SUFFIX):
        fail('encrypted output archive must end with %s' % ENCRYPTED_ARCHIVE_SUFFIX)
    if not args.encrypt and str(output).endswith(ENCRYPTED_ARCHIVE_SUFFIX):
        fail('--encrypt is required for an encrypted output archive')
    entries = upload_entries(uploads)

    with tempfile.TemporaryDirectory(prefix='pylinux-backup-', dir=str(output.parent)) as temporary:
        temporary_path = Path(temporary)
        copied_database = temporary_path / 'database.sqlite3'
        sqlite_backup(database, copied_database)
        checksum_lines = ['%s  database.sqlite3' % sha256_path(copied_database)]
        uploads_bytes = 0
        for source, relative in entries:
            checksum_lines.append('%s  uploads/%s' % (sha256_path(source), relative.as_posix()))
            uploads_bytes += source.stat().st_size
        manifest = {
            'format_version': 1,
            'created_at_utc': datetime.datetime.utcnow().replace(microsecond=0).isoformat() + 'Z',
            'database_member': 'database.sqlite3',
            'uploads_prefix': 'uploads/',
            'uploads_file_count': len(entries),
            'uploads_bytes': uploads_bytes,
            'checksum_algorithm': 'sha256',
        }
        manifest_path = temporary_path / 'manifest.json'
        checksum_path = temporary_path / 'checksums.sha256'
        manifest_path.write_text(json.dumps(manifest, sort_keys=True, indent=2) + '\n', encoding='utf-8')
        checksum_path.write_text('\n'.join(checksum_lines) + '\n', encoding='utf-8')
        staged_output = temporary_path / 'backup.tar.gz'
        with tarfile.open(str(staged_output), 'w:gz', format=tarfile.PAX_FORMAT) as archive:
            add_file(archive, manifest_path, 'manifest.json')
            add_file(archive, checksum_path, 'checksums.sha256')
            add_file(archive, copied_database, 'database.sqlite3')
            for source, relative in entries:
                add_file(archive, source, 'uploads/%s' % relative.as_posix())
        if args.encrypt:
            staged_encrypted_output = temporary_path / 'backup.tar.gz.enc'
            encrypt_file(staged_output, staged_encrypted_output)
            os.replace(str(staged_encrypted_output), str(output))
        else:
            os.replace(str(staged_output), str(output))

    print('Backup created: %s' % output)
    print('Encrypted: %s' % ('yes' if args.encrypt else 'no'))
    print('Uploads files: %d' % len(entries))


def parse_args(argv):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--database', required=True, help='explicit SQLite database file')
    parser.add_argument('--uploads', required=True, help='explicit uploads directory')
    parser.add_argument('--output', required=True, help='new .tar.gz or .tar.gz.enc backup archive path')
    parser.add_argument('--force', action='store_true', help='replace an existing output archive')
    parser.add_argument('--encrypt', action='store_true', help='encrypt with DATA_ENCRYPTION_KEY using AES-GCM')
    return parser.parse_args(argv)


def main(argv=None):
    try:
        create_backup(parse_args(argv))
    except (OSError, sqlite3.Error, ValueError, tarfile.TarError) as error:
        print('Backup failed: %s' % error, file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
