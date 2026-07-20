#!/usr/bin/env python3
"""Streaming encryption helpers for PyLinux backup archives."""
from __future__ import print_function

import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


MAGIC = b'PYLINUX-BACKUP-ENC-1\x00'
NONCE_BYTES = 12
CHUNK_SIZE = 1024 * 1024
KEY_SALT = b'pylinux-backup-encryption-v1'
KEY_INFO = b'pylinux-backup-archive'


def fail(message):
    raise ValueError(message)


def encryption_key(secret=None):
    if secret is None:
        secret = os.environ.get('DATA_ENCRYPTION_KEY', '')
    if not secret:
        fail('DATA_ENCRYPTION_KEY must be configured to encrypt or decrypt a backup')
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=KEY_SALT,
        info=KEY_INFO,
        backend=default_backend(),
    ).derive(secret.encode('utf-8'))


def encrypt_file(source, destination, secret=None):
    """Encrypt source to destination without retaining the archive in memory."""
    nonce = os.urandom(NONCE_BYTES)
    cipher = Cipher(algorithms.AES(encryption_key(secret)), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    encryptor.authenticate_additional_data(MAGIC)
    with source.open('rb') as input_handle, destination.open('xb') as output_handle:
        output_handle.write(MAGIC)
        output_handle.write(nonce)
        while True:
            chunk = input_handle.read(CHUNK_SIZE)
            if not chunk:
                break
            output_handle.write(encryptor.update(chunk))
        output_handle.write(encryptor.finalize())
        output_handle.write(encryptor.tag)


def decrypt_file(source, destination, secret=None):
    """Decrypt source to destination and authenticate it before returning."""
    minimum_size = len(MAGIC) + NONCE_BYTES + 16
    if source.stat().st_size < minimum_size:
        fail('encrypted backup is truncated')
    with source.open('rb') as input_handle:
        if input_handle.read(len(MAGIC)) != MAGIC:
            fail('encrypted backup format is not supported')
        nonce = input_handle.read(NONCE_BYTES)
        input_handle.seek(-16, os.SEEK_END)
        tag = input_handle.read(16)
        cipher = Cipher(algorithms.AES(encryption_key(secret)), modes.GCM(nonce, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        decryptor.authenticate_additional_data(MAGIC)
        input_handle.seek(len(MAGIC) + NONCE_BYTES)
        remaining = source.stat().st_size - len(MAGIC) - NONCE_BYTES - 16
        with destination.open('xb') as output_handle:
            while remaining:
                chunk = input_handle.read(min(CHUNK_SIZE, remaining))
                if not chunk:
                    fail('encrypted backup is truncated')
                remaining -= len(chunk)
                output_handle.write(decryptor.update(chunk))
            output_handle.write(decryptor.finalize())
