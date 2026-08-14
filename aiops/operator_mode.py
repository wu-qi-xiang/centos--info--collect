"""兼容入口：请从 :mod:`aiops.investigation.operator_mode` 导入。"""

from .investigation.operator_mode import *  # noqa: F401,F403
from .investigation.operator_mode import __dict__ as _source

__all__ = [name for name in _source if not name.startswith('_')]
