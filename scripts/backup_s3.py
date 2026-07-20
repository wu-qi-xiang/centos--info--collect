#!/usr/bin/env python3
"""Upload an encrypted backup to an S3-compatible store and prune old backups."""
from __future__ import print_function

import argparse
import datetime
import os
import sys
from pathlib import Path


ENCRYPTED_ARCHIVE_SUFFIX = '.tar.gz.enc'


def fail(message):
    raise ValueError(message)


def explicit_path(value):
    supplied = Path(value).expanduser()
    if '..' in supplied.parts:
        fail('archive must not contain parent-directory traversal')
    path = supplied.absolute()
    current = Path(path.anchor)
    for component in path.parts[1:]:
        current /= component
        if current.is_symlink():
            fail('archive must not traverse a symbolic link')
    return path


def validate_bucket(bucket):
    if not bucket or len(bucket) > 63:
        fail('S3 bucket name is invalid')
    allowed = set('abcdefghijklmnopqrstuvwxyz0123456789.-')
    if set(bucket) - allowed or bucket[0] in '.-' or bucket[-1] in '.-':
        fail('S3 bucket name is invalid')


def normalize_prefix(prefix):
    prefix = (prefix or '').strip('/')
    if not prefix or '..' in prefix.split('/') or '\\' in prefix:
        fail('S3 prefix must be specific and must not contain path traversal')
    return prefix + '/'


def s3_client(endpoint_url, region):
    try:
        import boto3
    except ImportError:
        fail('boto3 is required for S3 backup upload; install the optional S3 dependency')
    options = {}
    if endpoint_url:
        options['endpoint_url'] = endpoint_url
    if region:
        options['region_name'] = region
    return boto3.client('s3', **options)


def encrypted_archive(args):
    archive = explicit_path(args.archive)
    if not archive.is_file() or archive.is_symlink() or not str(archive).endswith(ENCRYPTED_ARCHIVE_SUFFIX):
        fail('archive must be an existing encrypted .tar.gz.enc regular file')
    return archive


def prune_old_backups(client, bucket, prefix, retention_days, now=None):
    if retention_days < 1:
        fail('retention days must be at least 1')
    now = now or datetime.datetime.now(datetime.timezone.utc)
    cutoff = now - datetime.timedelta(days=retention_days)
    paginator = client.get_paginator('list_objects_v2')
    delete_batch = []
    deleted = 0
    for page in paginator.paginate(Bucket=bucket, Prefix=prefix):
        for item in page.get('Contents', []):
            key = item.get('Key', '')
            modified = item.get('LastModified')
            if not key.startswith(prefix) or not key.endswith(ENCRYPTED_ARCHIVE_SUFFIX) or not modified:
                continue
            if modified <= cutoff:
                delete_batch.append({'Key': key})
                if len(delete_batch) == 1000:
                    client.delete_objects(Bucket=bucket, Delete={'Objects': delete_batch, 'Quiet': True})
                    deleted += len(delete_batch)
                    delete_batch = []
    if delete_batch:
        client.delete_objects(Bucket=bucket, Delete={'Objects': delete_batch, 'Quiet': True})
        deleted += len(delete_batch)
    return deleted


def upload_backup(args, client_factory=s3_client):
    archive = encrypted_archive(args)
    validate_bucket(args.bucket)
    prefix = normalize_prefix(args.prefix)
    retention_days = int(args.retention_days)
    if retention_days < 1:
        fail('retention days must be at least 1')
    object_key = prefix + archive.name
    if args.dry_run:
        print('S3 upload plan validated; no remote changes were made')
        return
    try:
        client = client_factory(args.endpoint_url, args.region)
        client.upload_file(str(archive), args.bucket, object_key, ExtraArgs={'ServerSideEncryption': 'AES256'})
        deleted = prune_old_backups(client, args.bucket, prefix, retention_days)
    except Exception:
        # SDK exceptions can include endpoint, bucket, or object details.
        fail('S3 upload or retention request failed')
    print('Encrypted backup uploaded; expired encrypted backups removed: %d' % deleted)


def parse_args(argv):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', required=True, help='explicit encrypted .tar.gz.enc archive')
    parser.add_argument('--bucket', required=True, help='S3-compatible bucket name')
    parser.add_argument('--prefix', default='pylinux-backups', help='S3 prefix, default: pylinux-backups')
    parser.add_argument('--endpoint-url', default=os.environ.get('BACKUP_S3_ENDPOINT_URL', ''), help='S3 endpoint URL')
    parser.add_argument('--region', default=os.environ.get('BACKUP_S3_REGION', ''), help='optional S3 region')
    parser.add_argument('--retention-days', default=os.environ.get('BACKUP_RETENTION_DAYS', '30'), help='minimum 1')
    parser.add_argument('--dry-run', action='store_true', help='validate inputs without contacting S3')
    return parser.parse_args(argv)


def main(argv=None):
    try:
        upload_backup(parse_args(argv))
    except (OSError, ValueError) as error:
        print('S3 backup upload failed: %s' % error, file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
