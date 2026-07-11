import base64
import hashlib

from cryptography.fernet import Fernet, InvalidToken
from django.conf import settings


PREFIX = 'enc:'


def _fernet():
    secret = getattr(settings, 'DATA_ENCRYPTION_KEY', '') or settings.SECRET_KEY
    digest = hashlib.sha256(secret.encode('utf-8')).digest()
    key = base64.urlsafe_b64encode(digest)
    return Fernet(key)


def encrypt_text(value):
    if value in (None, ''):
        return value
    value = str(value)
    if value.startswith(PREFIX):
        return value
    token = _fernet().encrypt(value.encode('utf-8')).decode('utf-8')
    return PREFIX + token


def decrypt_text(value):
    if value in (None, ''):
        return value
    value = str(value)
    if not value.startswith(PREFIX):
        return value
    token = value[len(PREFIX):]
    try:
        return _fernet().decrypt(token.encode('utf-8')).decode('utf-8')
    except InvalidToken:
        return ''
