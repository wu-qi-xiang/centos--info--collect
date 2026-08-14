"""兼容入口：请从 :mod:`aiops.investigation.runbook_recommendations` 导入。"""

from .investigation.runbook_recommendations import *  # noqa: F401,F403
from .investigation.runbook_recommendations import __dict__ as _source

__all__ = [name for name in _source if not name.startswith('_')]
