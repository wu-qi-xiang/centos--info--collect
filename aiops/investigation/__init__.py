"""AIOps 事件调查实现包。

顶层 ``aiops`` 模块保留为兼容入口；调查逻辑在本包内按职责维护。
"""

from .evidence_pack import build_evidence_pack
from .investigation_timeline import build_investigation_timelines
from .investigations import build_investigation_result
from .k8s_analyzer import analyze_k8s_detail
from .operator_mode import build_operator_scan

__all__ = [
    'build_evidence_pack',
    'build_investigation_timelines',
    'build_investigation_result',
    'analyze_k8s_detail',
    'build_operator_scan',
]
