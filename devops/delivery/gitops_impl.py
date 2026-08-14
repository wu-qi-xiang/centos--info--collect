import hashlib
import json

from ..models import GitOpsDriftFinding

ALLOWED_KINDS = ('Deployment', 'StatefulSet', 'DaemonSet', 'ConfigMap', 'PrometheusRule')


def manifest_digest(manifest):
    if not isinstance(manifest, dict):
        raise ValueError('清单必须是对象')
    return hashlib.sha256(json.dumps(manifest, sort_keys=True, separators=(',', ':')).encode('utf-8')).hexdigest()


def record_gitops_drift(cluster, namespace, resource_name, resource_kind, desired_manifest, observed_manifest):
    if not cluster or resource_kind not in ALLOWED_KINDS or not namespace or not resource_name:
        raise ValueError('GitOps 资源标识无效')
    desired_digest = manifest_digest(desired_manifest)
    observed_digest = manifest_digest(observed_manifest)
    finding, _ = GitOpsDriftFinding.objects.update_or_create(
        cluster=cluster, namespace=namespace, resource_name=resource_name, resource_kind=resource_kind,
        defaults={
            'desired_digest': desired_digest, 'observed_digest': observed_digest,
            'status': GitOpsDriftFinding.STATUS_DRIFTED if desired_digest != observed_digest else GitOpsDriftFinding.STATUS_IN_SYNC,
        },
    )
    return finding
