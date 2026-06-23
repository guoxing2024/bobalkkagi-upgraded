"""
Core Layer — Bobalkkagi v2.0 架构基础
========================================
提供:
  - UnpackContext: 中心状态容器（替代GLOBAL_VAR）
  - Event System: 不可变事件类型（ApiEvent, MemoryEvent, CallEvent等）
  - EventBus: 发布/订阅事件总线
  - Plugin Interface: Detector/Rebuilder抽象基类
  - OEPDetectorBase: OEP检测器基类（综合评分算法）
"""

from .context import UnpackContext, ModuleInfo, RegionInfo, TLSInfo
from .events import (
    BaseEvent, EventType,
    ApiEvent, MemoryEvent, CallEvent,
    ExceptionEvent, OEPEvent, ModuleLoadEvent,
)
from .plugin import (
    EventBus, DetectorPlugin, RebuilderPlugin, OEPDetectorBase,
)

__all__ = [
    'UnpackContext', 'ModuleInfo', 'RegionInfo', 'TLSInfo',
    'BaseEvent', 'EventType',
    'ApiEvent', 'MemoryEvent', 'CallEvent',
    'ExceptionEvent', 'OEPEvent', 'ModuleLoadEvent',
    'EventBus', 'DetectorPlugin', 'RebuilderPlugin', 'OEPDetectorBase',
]
