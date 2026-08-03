"""Safe, local-only integration normalization and collection contracts."""

from django.db import transaction
from django.utils import timezone

from .gitops import ALLOWED_KINDS, record_gitops_drift
from .models import (
    GitOpsCollectionRun,
    InfrastructurePlan,
    K8sCluster,
    IntegrationConnector,
    InfrastructureBlueprint,
    VulnerabilityImportRun,
)
from .vulnerability import ADVISORY_RE, PACKAGE_RE, record_vulnerability_finding
from RemoteLinux.models import NewLinux


OUTCOME_CONNECTOR_DISABLED = 'connector_disabled'
OUTCOME_PROVIDER_UNCONFIGURED = 'provider_unconfigured'
OUTCOME_COMPLETED = 'completed'
OUTCOME_INVALID_INPUT = 'invalid_input'
OUTCOME_ADAPTER_ERROR = 'adapter_error'
OUTCOME_BLUEPRINT_DISABLED = 'blueprint_disabled'


class DisabledGitOpsAdapter:
    """Intentional no-network default; callers must inject a vetted adapter."""
    is_disabled_adapter = True

    def collect(self, config):
        return ()


class DisabledVulnerabilityAdapter:
    """Intentional no-network default; callers must inject a vetted adapter."""
    is_disabled_adapter = True

    def collect(self, config):
        return ()


def _require_exact_keys(row, allowed_keys):
    if not isinstance(row, dict) or set(row) != set(allowed_keys):
        raise ValueError('集成记录字段无效')


def normalize_gitops_finding(row):
    _require_exact_keys(row, (
        'cluster', 'namespace', 'resource_name', 'resource_kind', 'desired_manifest', 'observed_manifest',
    ))
    cluster = row['cluster']
    if not isinstance(cluster, K8sCluster) or not cluster.pk or not K8sCluster.objects.filter(pk=cluster.pk).exists():
        raise ValueError('GitOps 集群无效')
    if not isinstance(row['resource_kind'], str) or row['resource_kind'] not in ALLOWED_KINDS:
        raise ValueError('GitOps 资源类型无效')
    if not isinstance(row['namespace'], str) or not isinstance(row['resource_name'], str):
        raise ValueError('GitOps 资源标识无效')
    if not isinstance(row['desired_manifest'], dict) or not isinstance(row['observed_manifest'], dict):
        raise ValueError('GitOps 清单无效')
    return row


def normalize_vulnerability_finding(row):
    _require_exact_keys(row, ('host', 'package_name', 'advisory_id', 'severity'))
    host = row['host']
    if not isinstance(host, NewLinux) or not host.pk or not NewLinux.objects.filter(pk=host.pk).exists():
        raise ValueError('漏洞主机无效')
    if not all(isinstance(row[field], str) for field in ('package_name', 'advisory_id', 'severity')):
        raise ValueError('漏洞标识无效')
    if not PACKAGE_RE.match(row['package_name'] or '') or not ADVISORY_RE.match(row['advisory_id'] or ''):
        raise ValueError('漏洞标识无效')
    if row['severity'] not in ('low', 'medium', 'high', 'critical'):
        raise ValueError('漏洞严重度无效')
    return row


def _finish_run(run, status, outcome_category, finding_count=0):
    run.status = status
    run.outcome_category = outcome_category
    run.finding_count = finding_count
    run.finished_at = timezone.now()
    run.save(update_fields=['status', 'outcome_category', 'finding_count', 'finished_at'])
    IntegrationConnector.objects.filter(pk=run.connector_id).update(
        last_status=status,
        last_outcome_category=outcome_category,
        last_run_at=run.finished_at,
    )
    return run


def _collect(connector, adapter, expected_type, run_model, normalizer, recorder, triggered_by=''):
    if connector.connector_type != expected_type:
        raise ValueError('连接器类型无效')
    run = run_model.objects.create(connector=connector, status='pending', triggered_by=triggered_by)
    if not connector.enabled or not connector.read_only:
        return _finish_run(run, 'blocked', OUTCOME_CONNECTOR_DISABLED)
    if adapter is None or getattr(adapter, 'is_disabled_adapter', False) is True:
        return _finish_run(run, 'blocked', OUTCOME_PROVIDER_UNCONFIGURED)

    run.status = 'running'
    run.save(update_fields=['status'])
    try:
        rows = list(adapter.collect(connector.get_config()))
        normalized_rows = [normalizer(row) for row in rows]
        with transaction.atomic():
            for row in normalized_rows:
                recorder(**row)
    except ValueError:
        return _finish_run(run, 'failed', OUTCOME_INVALID_INPUT)
    except Exception:
        return _finish_run(run, 'failed', OUTCOME_ADAPTER_ERROR)
    return _finish_run(run, 'success', OUTCOME_COMPLETED, finding_count=len(normalized_rows))


def collect_gitops_connector(connector, adapter=None, triggered_by=''):
    return _collect(
        connector, adapter, IntegrationConnector.TYPE_GITOPS, GitOpsCollectionRun,
        normalize_gitops_finding, record_gitops_drift, triggered_by,
    )


def collect_vulnerability_connector(connector, adapter=None, triggered_by=''):
    return _collect(
        connector, adapter, IntegrationConnector.TYPE_VULNERABILITY, VulnerabilityImportRun,
        normalize_vulnerability_finding, record_vulnerability_finding, triggered_by,
    )


def request_infrastructure_plan(blueprint, requested_by=''):
    """Persist a local planning request only; no provider operation is performed."""
    if not isinstance(blueprint, InfrastructureBlueprint) or not blueprint.pk:
        raise ValueError('基础设施蓝图无效')
    outcome_category = '' if blueprint.enabled and blueprint.read_only else OUTCOME_BLUEPRINT_DISABLED
    return InfrastructurePlan.objects.create(
        blueprint=blueprint,
        status='pending' if not outcome_category else 'blocked',
        outcome_category=outcome_category,
        definition_digest=blueprint.definition_digest,
        summary=blueprint.summary,
        requested_by=requested_by,
        finished_at=timezone.now() if outcome_category else None,
    )
