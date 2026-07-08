import paramiko
import socket
from io import StringIO

from PyLinux.crypto import decrypt_text


class SSHCommandError(Exception):
    pass


class SSHCredentialError(Exception):
    pass


class SSHConnectionError(Exception):
    pass


def describe_ssh_error(exc):
    if isinstance(exc, SSHCredentialError):
        return str(exc)
    if isinstance(exc, paramiko.AuthenticationException):
        return 'SSH认证失败，请检查用户名、密码或私钥'
    if isinstance(exc, paramiko.SSHException):
        return 'SSH协议错误：%s' % exc
    if isinstance(exc, socket.timeout):
        return 'SSH连接超时，请检查网络、端口或防火墙'
    if isinstance(exc, socket.gaierror):
        return 'SSH主机解析失败，请检查IP或域名'
    if isinstance(exc, (socket.error, OSError)):
        return 'SSH网络连接失败：%s' % exc
    return 'SSH连接失败：%s' % exc


def load_private_key(private_key, passphrase=''):
    if not private_key:
        raise SSHCredentialError('未配置SSH私钥')

    key_stream = StringIO(private_key)
    last_error = None
    key_classes = (
        paramiko.RSAKey,
        paramiko.ECDSAKey,
        paramiko.Ed25519Key,
        paramiko.DSSKey,
    )
    for key_class in key_classes:
        key_stream.seek(0)
        try:
            return key_class.from_private_key(key_stream, password=passphrase or None)
        except Exception as exc:
            last_error = exc
    raise SSHCredentialError('SSH私钥解析失败：%s' % last_error)


def create_ssh_client(host, port, username, password='', timeout=8, private_key=None, passphrase=''):
    client = paramiko.SSHClient()
    client.load_system_host_keys()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    connect_kwargs = {
        'hostname': host,
        'port': int(port),
        'username': username,
        'compress': True,
        'timeout': timeout,
    }
    if private_key:
        connect_kwargs['pkey'] = load_private_key(private_key, passphrase)
        if password:
            connect_kwargs['password'] = password
    else:
        connect_kwargs['password'] = password
    try:
        client.connect(**connect_kwargs)
        return client
    except Exception:
        client.close()
        raise


def create_host_ssh_client(host, timeout=8):
    auth_type = getattr(host, 'linux_auth_type', 'password')
    password = decrypt_text(getattr(host, 'linux_passwd', ''))
    if auth_type == 'key':
        return create_ssh_client(
            host.linux_ip,
            host.linux_port,
            host.linux_user,
            password=password,
            private_key=decrypt_text(getattr(host, 'linux_private_key', '')),
            passphrase=decrypt_text(getattr(host, 'linux_private_key_passphrase', '')),
            timeout=timeout,
        )
    return create_ssh_client(
        host.linux_ip,
        host.linux_port,
        host.linux_user,
        password=password,
        timeout=timeout,
    )


def run_command(client, command, default=''):
    stdin, stdout, stderr = client.exec_command(command)
    output = stdout.read().decode().strip()
    error = stderr.read().decode().strip()
    if error and not output:
        return default
    return output or default


def first_line(value, default=''):
    if not value:
        return default
    lines = str(value).splitlines()
    return lines[0].strip() if lines else default
