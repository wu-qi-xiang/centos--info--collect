"""兼容入口：请从 :mod:`aiops.investigation.k8s_analyzer` 导入。"""

from .investigation import k8s_analyzer as _implementation

safe_namespace = _implementation.safe_namespace
_finding = _implementation._finding
load_cached_k8s_cluster_detail = _implementation.load_cached_k8s_cluster_detail


def analyze_k8s_detail(*args, **kwargs):
    """Delegate while preserving the legacy loader patch point."""
    _implementation.load_cached_k8s_cluster_detail = load_cached_k8s_cluster_detail
    return _implementation.analyze_k8s_detail(*args, **kwargs)

__all__ = ['analyze_k8s_detail', 'safe_namespace']
