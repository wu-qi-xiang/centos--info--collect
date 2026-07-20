#!/usr/bin/env python3
"""Verify and restore a backup archive only into an explicitly empty directory."""
from __future__ import print_function

import argparse
import hashlib
import json
import os
import sqlite3
import sys
import tarfile
import tempfile
from pathlib import Path, PurePosixPath
from urllib.parse import quote

from backup_crypto import decrypt_file
from cryptography.exceptions import InvalidTag


ARCHIVE_SUFFIX = '.tar.gz'
ENCRYPTED_ARCHIVE_SUFFIX = '.tar.gz.enc'
REQUIRED_MEMBERS = {'manifest.json', 'checksums.sha256', 'database.sqlite3'}


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


def safe_member_name(name):
    path = PurePosixPath(name)
    if not name or path.is_absolute() or '..' in path.parts or name.startswith('/'):
        fail('archive contains an unsafe member path: %r' % name)
    return path


def validate_target(target, archive):
    if str(target) == target.anchor or target.name in ('', '.', '..'):
        fail('target directory must be a specific existing directory')
    if not target.exists() or not target.is_dir() or target.is_symlink():
        fail('target directory must be an existing non-symbolic-link directory')
    if any(target.iterdir()):
        fail('target directory must be empty')
    try:
        archive.relative_to(target)
    except ValueError:
        return
    fail('target directory must not contain the backup archive')


def member_digest(archive, member):
    digest = hashlib.sha256()
    handle = archive.extractfile(member)
    if handle is None:
        fail('cannot read archive member: %s' % member.name)
    with handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def parse_checksums(raw, allowed_names):
    result = {}
    for line in raw.decode('utf-8').splitlines():
        if not line:
            continue
        try:
            digest, name = line.split('  ', 1)
        except ValueError:
            fail('invalid checksum line')
        if len(digest) != 64 or any(character not in '0123456789abcdef' for character in digest):
            fail('invalid SHA-256 digest')
        safe_member_name(name)
        if name not in allowed_names or name in result:
            fail('checksum list does not match archive content')
        result[name] = digest
    if set(result) != allowed_names:
        fail('checksum list is incomplete')
    return result


def validate_archive(archive):
    members = archive.getmembers()
    names = set()
    regular_members = {}
    for member in members:
        safe_member_name(member.name)
        if member.name in names:
            fail('archive contains duplicate member: %s' % member.name)
        names.add(member.name)
        if member.isdir():
            continue
        if not member.isreg() or member.issym() or member.islnk():
            fail('archive contains a non-regular member: %s' % member.name)
        regular_members[member.name] = member
    if not REQUIRED_MEMBERS.issubset(regular_members):
        fail('archive is missing required backup members')
    allowed = set(regular_members) - {'manifest.json', 'checksums.sha256'}
    if 'database.sqlite3' not in allowed or any(not name.startswith('uploads/') and name != 'database.sqlite3' for name in allowed):
        fail('archive contains unexpected backup data')
    manifest_handle = archive.extractfile(regular_members['manifest.json'])
    checksum_handle = archive.extractfile(regular_members['checksums.sha256'])
    if manifest_handle is None or checksum_handle is None:
        fail('archive metadata cannot be read')
    with manifest_handle:
        manifest = json.loads(manifest_handle.read().decode('utf-8'))
    with checksum_handle:
        checksums = parse_checksums(checksum_handle.read(), allowed)
    if manifest.get('format_version') != 1 or manifest.get('database_member') != 'database.sqlite3':
        fail('archive manifest format is not supported')
    for name, expected_digest in checksums.items():
        if member_digest(archive, regular_members[name]) != expected_digest:
            fail('checksum mismatch for archive member: %s' % name)
    return regular_members, manifest


def extract_members(archive, members, target):
    for name in sorted(members):
        if name in ('manifest.json', 'checksums.sha256'):
            continue
        destination = target.joinpath(*PurePosixPath(name).parts)
        destination.parent.mkdir(parents=True, exist_ok=True)
        source = archive.extractfile(members[name])
        if source is None:
            fail('cannot extract archive member: %s' % name)
        with source, destination.open('wb') as output:
            while True:
                chunk = source.read(1024 * 1024)
                if not chunk:
                    break
                output.write(chunk)


def sqlite_integrity_check(database):
    uri = 'file:%s?mode=ro' % quote(str(database))
    connection = sqlite3.connect(uri, uri=True)
    try:
        rows = [row[0] for row in connection.execute('PRAGMA integrity_check')]
    finally:
        connection.close()
    if rows != ['ok']:
        fail('SQLite integrity check failed: %s' % ', '.join(rows))


def preflight(args):
    archive_path = explicit_path(args.archive, 'archive')
    target = explicit_path(args.target_dir, 'target directory')
    if not archive_path.is_file() or archive_path.is_symlink() or not (
            str(archive_path).endswith(ARCHIVE_SUFFIX) or str(archive_path).endswith(ENCRYPTED_ARCHIVE_SUFFIX)):
        fail('archive must be an existing regular .tar.gz or .tar.gz.enc file')
    validate_target(target, archive_path)
    with tempfile.TemporaryDirectory(prefix='pylinux-restore-', dir=str(target.parent)) as temporary:
        decrypted_path = Path(temporary) / 'backup.tar.gz'
        if str(archive_path).endswith(ENCRYPTED_ARCHIVE_SUFFIX):
            decrypt_file(archive_path, decrypted_path)
            archive_for_validation = decrypted_path
        else:
            archive_for_validation = archive_path
        with tarfile.open(str(archive_for_validation), 'r:gz') as archive:
            members, manifest = validate_archive(archive)
            extract_members(archive, members, target)
    sqlite_integrity_check(target / 'database.sqlite3')
    report = {
        'ok': True,
        'format_version': manifest['format_version'],
        'uploads_file_count': manifest.get('uploads_file_count', 0),
        'restored_database': str(target / 'database.sqlite3'),
        'restored_uploads': str(target / 'uploads'),
    }
    print(json.dumps(report, sort_keys=True))


def parse_args(argv):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', required=True, help='explicit backup .tar.gz or .tar.gz.enc archive')
    parser.add_argument('--target-dir', required=True, help='existing empty isolated restore directory')
    return parser.parse_args(argv)


def main(argv=None):
    try:
        preflight(parse_args(argv))
    except (OSError, sqlite3.Error, ValueError, InvalidTag, tarfile.TarError, json.JSONDecodeError) as error:
        print('Restore preflight failed: %s' % error, file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
