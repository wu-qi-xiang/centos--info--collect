"""兼容入口：请从 :mod:`aiops.analysis.alert_quality` 导入。"""

from .analysis.alert_quality import *  # noqa: F401,F403
from .analysis.alert_quality import __dict__ as _source

__all__ = [name for name in _source if not name.startswith('_')]
