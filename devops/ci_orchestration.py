"""Pure validation helpers for sanitized Jenkins and GitLab CI status intake.

This module deliberately does not authenticate webhooks, access the database,
or trigger deployments. Request adapters can authenticate a delivery first and
then persist only the dictionary returned by :func:`parse_ci_delivery`.
"""

import hashlib
import re


SUPPORTED_PROVIDERS = frozenset(('jenkins', 'gitlab'))
ALLOWED_STATUSES = frozenset((
    'pending', 'running', 'success', 'failed', 'canceled', 'skipped',
))
_REPOSITORY_RE = re.compile(r'^[a-z0-9][a-z0-9._-]*/[a-z0-9][a-z0-9._-]*$')
_DELIVERY_ID_RE = re.compile(r'^[A-Za-z0-9._:-]{1,128}$')
_REVISION_RE = re.compile(r'^[0-9a-f]{7,64}$')
_UNSAFE_KEY_PARTS = ('token', 'url', 'log', 'command')


class CIValidationError(ValueError):
    """A validation error with a stable, safe error code."""

    def __init__(self, code):
        self.code = code
        super().__init__(code)


def _normalized_provider(provider):
    if not isinstance(provider, str):
        raise CIValidationError('unsupported_provider')
    normalized = provider.strip().lower()
    if normalized not in SUPPORTED_PROVIDERS:
        raise CIValidationError('unsupported_provider')
    return normalized


def _normalized_repository(repository):
    if not isinstance(repository, str):
        raise CIValidationError('invalid_repository')
    normalized = repository.strip().lower()
    if len(normalized) > 200 or not _REPOSITORY_RE.match(normalized):
        raise CIValidationError('invalid_repository')
    return normalized


def _normalized_delivery_id(delivery_id):
    if not isinstance(delivery_id, str):
        raise CIValidationError('invalid_delivery')
    normalized = delivery_id.strip()
    if not _DELIVERY_ID_RE.match(normalized):
        raise CIValidationError('invalid_delivery')
    return normalized


def _normalized_status(status):
    if not isinstance(status, str):
        raise CIValidationError('invalid_status')
    normalized = status.strip().lower()
    if normalized not in ALLOWED_STATUSES:
        raise CIValidationError('invalid_status')
    return normalized


def _normalized_revision(revision):
    if revision in (None, ''):
        return ''
    if not isinstance(revision, str):
        raise CIValidationError('invalid_revision')
    normalized = revision.strip().lower()
    if not _REVISION_RE.match(normalized):
        raise CIValidationError('invalid_revision')
    return normalized


def _contains_unsafe_key(value):
    if isinstance(value, dict):
        for key, nested in value.items():
            if not isinstance(key, str):
                return True
            normalized_key = key.lower()
            if any(part in normalized_key for part in _UNSAFE_KEY_PARTS):
                return True
            if _contains_unsafe_key(nested):
                return True
    elif isinstance(value, (list, tuple)):
        return any(_contains_unsafe_key(item) for item in value)
    return False


def delivery_fingerprint(provider, repository, delivery_id):
    """Return a stable, provider-scoped digest for idempotency storage."""
    normalized = '|'.join((
        _normalized_provider(provider),
        _normalized_repository(repository),
        _normalized_delivery_id(delivery_id),
    ))
    return hashlib.sha256(normalized.encode('utf-8')).hexdigest()


def parse_ci_delivery(provider, payload):
    """Validate a CI status payload and return a safe, fixed-field summary.

    Payload values other than the whitelisted identity/status fields are never
    returned. Sensitive or executable-looking keys cause a full rejection so a
    future adapter cannot accidentally persist them.
    """
    normalized_provider = _normalized_provider(provider)
    if not isinstance(payload, dict) or _contains_unsafe_key(payload):
        raise CIValidationError('unsafe_payload')

    repository = _normalized_repository(payload.get('repository'))
    status = _normalized_status(payload.get('status'))
    delivery_id = _normalized_delivery_id(payload.get('delivery_id'))
    revision = _normalized_revision(payload.get('revision'))
    provider_label = 'Jenkins' if normalized_provider == 'jenkins' else 'GitLab'

    return {
        'provider': normalized_provider,
        'repository': repository,
        'status': status,
        'delivery_id': delivery_id,
        'revision': revision,
        'fingerprint': delivery_fingerprint(
            normalized_provider, repository, delivery_id,
        ),
        'summary': '%s CI status %s for %s.' % (
            provider_label, status, repository,
        ),
    }
