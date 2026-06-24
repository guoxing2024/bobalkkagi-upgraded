"""
Engine Package — P2: 执行引擎工厂
===================================
提供统一的执行引擎创建接口。
"""

from ..core.backend import (
    IExecutionBackend, BackendType, ExecutionStage,
    ExecutionResult, BackendExecutionError, BackendNotAvailableError
)
from .unicorn_backend import UnicornBackend
from .debugger_backend import DebuggerBackend
from .hybrid_backend import HybridBackend

__all__ = [
    'IExecutionBackend', 'BackendType', 'ExecutionStage',
    'ExecutionResult', 'BackendExecutionError', 'BackendNotAvailableError',
    'UnicornBackend', 'DebuggerBackend', 'HybridBackend',
    'create_backend',
]


def create_backend(backend_type: str, **kwargs) -> IExecutionBackend:
    """
    执行引擎工厂。

    Args:
        backend_type: "unicorn" | "debugger" | "hybrid"
        **kwargs: 传递给具体后端的参数
          - unicorn: crc_mode, emu_mode, verbose
          - debugger: hide_debugger, timeout_seconds

    Returns:
        IExecutionBackend 实例

    Raises:
        ValueError: 未知后端类型
        BackendNotAvailableError: 后端在当前环境下不可用
    """
    bt = backend_type.lower().strip()

    if bt == "unicorn":
        return UnicornBackend(
            crc_mode=kwargs.get('crc_mode', 'safe'),
            emu_mode=kwargs.get('emu_mode', 'f'),
            verbose=kwargs.get('verbose', False),
        )

    elif bt == "debugger":
        backend = DebuggerBackend(
            hide_debugger=kwargs.get('hide_debugger', True),
            timeout_seconds=kwargs.get('debugger_timeout', 60),
        )
        ok, msg = backend.validate_environment()
        if not ok:
            raise BackendNotAvailableError(msg)
        return backend

    elif bt == "hybrid":
        return HybridBackend(
            crc_mode=kwargs.get('crc_mode', 'safe'),
            emu_mode=kwargs.get('emu_mode', 'f'),
            debugger_timeout=kwargs.get('debugger_timeout', 60),
            hide_debugger=kwargs.get('hide_debugger', True),
        )

    else:
        raise ValueError(
            f"Unknown backend type: '{backend_type}'. "
            f"Valid options: unicorn, debugger"
        )
