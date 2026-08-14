"""Bounded, read-only Kubernetes health analysis."""
import re
import sys

from devops.services import load_cached_k8s_cluster_detail

NAMESPACE_RE = re.compile(r'^[a-z0-9]([-a-z0-9]*[a-z0-9])?$')
MAX_FINDINGS = 80
MAX_RESOURCES = 200


def safe_namespace(value, default='default'):
    value = (value or default).strip().lower()
    return value if len(value) <= 63 and NAMESPACE_RE.match(value) else None


def _finding(kind, row, status, reason):
    return {'kind': kind, 'name': str(row.get('name') or '-')[:253],
            'namespace': str(row.get('namespace') or '-')[:63], 'status': status,
            'replicas': row.get('replicas', '-'), 'detail': str(row.get('detail') or '')[:300],
            'reason': reason}


def analyze_k8s_detail(cluster, namespace, mappings=(), refresh=False):
    # Keep the historical ``aiops.k8s_analyzer.load_cached_k8s_cluster_detail``
    # patch point working for callers that still use the legacy module path.
    legacy = sys.modules.get('aiops.k8s_analyzer')
    loader = getattr(legacy, 'load_cached_k8s_cluster_detail', load_cached_k8s_cluster_detail)
    detail = loader(cluster.id, cluster.decrypted_kubeconfig,
                                             namespace, refresh=refresh)
    overview = detail.get('overview') or {}
    resources = overview.get('resources') or {}
    allowed = {(m.namespace, m.workload_kind.lower(), m.workload_name) for m in mappings}
    findings = []
    for key in ('deployments', 'statefulsets', 'daemonsets'):
        for row in (resources.get(key) or [])[:MAX_RESOURCES]:
            kind = key[:-1].lower()
            if (str(row.get('namespace') or namespace), kind, str(row.get('name') or '')) not in allowed:
                continue
            replicas = row.get('replicas')
            status = str(row.get('status') or '').lower()
            if status not in ('healthy', 'running', 'available', 'ready', '运行中', '健康', '就绪'):
                findings.append(_finding(key[:-1], row, status or 'unknown', 'workload 状态异常'))
            elif isinstance(replicas, str) and '/' in replicas and replicas.split('/', 1)[0] != replicas.split('/', 1)[1]:
                findings.append(_finding(key[:-1], row, status, 'workload 副本未就绪'))
    errors = []
    if not overview.get('ok'):
        errors.append({'source': 'kubernetes', 'code': 'source_unavailable'})
    for source, message in (overview.get('resource_errors') or {}).items():
        errors.append({'source': str(source)[:40], 'code': 'source_unavailable'})
    return {
        'cluster': {'id': cluster.id, 'name': cluster.name, 'status': cluster.status},
        'scope': {'namespace': namespace},
        'resource_counts': {key: sum(1 for row in (resources.get(key) or []) if
                            (str(row.get('namespace') or namespace), key[:-1].lower(), str(row.get('name') or '')) in allowed)
                            for key in ('deployments', 'statefulsets', 'daemonsets')},
        'findings': findings[:MAX_FINDINGS], 'partial': bool(errors),
        'errors': errors[:20],
    }
