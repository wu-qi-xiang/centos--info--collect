"""Validation and storage boundary for outbound Host Agent heartbeats.

Agents authenticate as ``Authorization: Bearer <registration_id>.<credential>``.
The credential is returned only by ``create_host_agent`` and only its Django
password hash is persisted.  This module deliberately has no SSH, command, or
file-upload capability.
"""
import re
import secrets
from dataclasses import dataclass

from django.contrib.auth.hashers import check_password, make_password
from django.utils import timezone

from .models import HostAgent


MAX_HEARTBEAT_BYTES = 4096
MAX_COLLECTION_DELAY_SECONDS = 7 * 24 * 60 * 60
SAFE_SUMMARY_FIELDS = {
    'os_family': ('string', 40),
    'os_version': ('string', 120),
    'cpu_count': ('integer', 4096),
    'memory_total_mb': ('integer', 134217728),
    'disk_total_gb': ('integer', 1048576),
}
HEARTBEAT_FIELDS = frozenset(('agent_version', 'collection_delay_seconds', 'system_summary'))
SAFE_TEXT = re.compile(r'^[A-Za-z0-9 ._+:/-]+$')


@dataclass(frozen=True)
class HeartbeatResult:
    ok: bool
    code: str
    agent: HostAgent = None


def create_host_agent(host):
    """Create or rotate an opaque registration credential for one host."""
    registration_id = secrets.token_hex(24)
    credential = secrets.token_urlsafe(32)
    defaults = {
        'credential_hash': make_password(credential),
        'is_revoked': False,
        'agent_version': '',
        'collection_delay_seconds': 0,
        'system_summary': {},
        'last_heartbeat_at': None,
        'revoked_at': None,
    }
    agent, created = HostAgent.objects.get_or_create(
        host=host,
        defaults=dict(defaults, registration_id=registration_id),
    )
    if not created:
        agent.registration_id = registration_id
        for field, value in defaults.items():
            setattr(agent, field, value)
        agent.save()
    return agent, credential


def revoke_host_agent(agent):
    if not agent.is_revoked:
        agent.revoke()
    return agent


def _parse_bearer(authorization):
    if not isinstance(authorization, str) or not authorization.startswith('Bearer '):
        return None, None
    value = authorization[7:].strip()
    if value.count('.') != 1:
        return None, None
    registration_id, credential = value.split('.', 1)
    if not re.fullmatch(r'[0-9a-f]{48}', registration_id) or not credential or len(credential) > 128:
        return None, None
    return registration_id, credential


def _validate_summary(summary):
    if not isinstance(summary, dict) or set(summary) - set(SAFE_SUMMARY_FIELDS):
        return None
    cleaned = {}
    for key, value in summary.items():
        value_type, maximum = SAFE_SUMMARY_FIELDS[key]
        if value_type == 'string':
            if not isinstance(value, str) or not value or len(value) > maximum or not SAFE_TEXT.fullmatch(value):
                return None
        elif isinstance(value, bool) or not isinstance(value, int) or value < 0 or value > maximum:
            return None
        cleaned[key] = value
    return cleaned


def _validate_payload(payload):
    if not isinstance(payload, dict) or set(payload) != HEARTBEAT_FIELDS:
        return None
    version = payload.get('agent_version')
    delay = payload.get('collection_delay_seconds')
    summary = _validate_summary(payload.get('system_summary'))
    if (not isinstance(version, str) or not version or len(version) > 64 or
            not SAFE_TEXT.fullmatch(version) or isinstance(delay, bool) or
            not isinstance(delay, int) or delay < 0 or delay > MAX_COLLECTION_DELAY_SECONDS or summary is None):
        return None
    return version, delay, summary


def ingest_heartbeat(authorization, payload):
    """Authenticate and persist an allowlisted heartbeat without logging input."""
    registration_id, credential = _parse_bearer(authorization)
    if not registration_id:
        return HeartbeatResult(False, 'unauthorized')
    try:
        agent = HostAgent.objects.get(registration_id=registration_id)
    except HostAgent.DoesNotExist:
        return HeartbeatResult(False, 'unauthorized')
    if agent.is_revoked or not check_password(credential, agent.credential_hash):
        return HeartbeatResult(False, 'unauthorized')
    valid = _validate_payload(payload)
    if valid is None:
        return HeartbeatResult(False, 'invalid_payload')
    version, delay, summary = valid
    agent.agent_version = version
    agent.collection_delay_seconds = delay
    agent.system_summary = summary
    agent.last_heartbeat_at = timezone.now()
    agent.save(update_fields=[
        'agent_version', 'collection_delay_seconds', 'system_summary',
        'last_heartbeat_at', 'updated_at',
    ])
    return HeartbeatResult(True, 'accepted', agent)
