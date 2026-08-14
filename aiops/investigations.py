"""兼容入口：请从 :mod:`aiops.investigation.investigations` 导入。"""

from .investigation import investigations as _implementation

_ids = _implementation._ids
_stamp = _implementation._stamp
_row = _implementation._row
_collect_alerts = _implementation._collect_alerts
_collect_metrics = _implementation._collect_metrics
_collect_incidents = _implementation._collect_incidents
_collect_releases = _implementation._collect_releases
_collect_slos = _implementation._collect_slos
_collect_dependencies = _implementation._collect_dependencies


build_investigation_result = _implementation.build_investigation_result

__all__ = ['build_investigation_result']
