"""
Core Event Types
=================
Bobalkkagi v2.0 — 事件驱动架构的事件类定义

所有Tracker产生事件，所有Detector消费事件。

设计原则：
  - 不可变事件：事件创建后不修改
  - 可序列化：所有事件可转为dict/JSON
  - 带时间戳：方便事后排序分析
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional


class EventType(Enum):
    API_CALL = "api_call"
    MEMORY_WRITE = "memory_write"
    MEMORY_PROTECT = "memory_protect"
    CODE_EXECUTE = "code_execute"
    CALL_TRACE = "call_trace"
    RET_TRACE = "ret_trace"
    EXCEPTION = "exception"
    OEP_DETECTED = "oep_detected"
    VM_DISPATCH = "vm_dispatch"
    MODULE_LOAD = "module_load"


@dataclass
class BaseEvent:
    """所有事件的基类"""
    timestamp: datetime = field(default_factory=datetime.now)
    event_type: EventType = EventType.API_CALL
    
    def to_dict(self) -> dict:
        """转换为字典（用于JSON序列化）"""
        d = {}
        for name, value in self.__dict__.items():
            if isinstance(value, datetime):
                d[name] = value.isoformat()
            elif isinstance(value, Enum):
                d[name] = value.value
            elif isinstance(value, bytes):
                d[name] = value.hex()
            else:
                d[name] = value
        return d


@dataclass
class ApiEvent(BaseEvent):
    """API调用事件
    
    字段: timestamp, dll, api, args, ret_value, thread_id
    """
    event_type: EventType = field(default=EventType.API_CALL, init=False)
    dll: str = ""
    api: str = ""
    args: dict = field(default_factory=dict)
    ret_value: int = 0
    thread_id: int = 0
    call_address: int = 0
    
    def __repr__(self):
        return f"ApiEvent({self.dll}.{self.api} args={self.args} ret=0x{self.ret_value:x})"


@dataclass
class MemoryEvent(BaseEvent):
    """内存操作事件
    
    type: 'write' | 'exec' | 'protect'
    """
    event_type: EventType = field(default=EventType.MEMORY_WRITE, init=False)
    operation: str = "write"  # write, exec, protect
    address: int = 0
    size: int = 0
    value: int = 0             # 写入值（write时）
    old_protect: int = 0       # 旧保护（protect时）
    new_protect: int = 0       # 新保护（protect时）
    
    def __repr__(self):
        if self.operation == "protect":
            return (f"MemoryEvent({self.operation} @ 0x{self.address:x} "
                    f"0x{self.old_protect:x}→0x{self.new_protect:x})")
        return f"MemoryEvent({self.operation} @ 0x{self.address:x} size={self.size})"


@dataclass
class CallEvent(BaseEvent):
    """CALL/RET事件
    
    用于调用图分析和RET链分析
    """
    event_type: EventType = field(default=EventType.CALL_TRACE, init=False)
    is_call: bool = True       # True=CALL, False=RET
    caller: int = 0            # 调用者地址
    callee: int = 0            # 被调用者地址 (CALL时)
    return_addr: int = 0       # 返回地址
    
    def __repr__(self):
        if self.is_call:
            return f"CallEvent(CALL 0x{self.caller:x}→0x{self.callee:x} ret=0x{self.return_addr:x})"
        return f"CallEvent(RET to 0x{self.return_addr:x})"


@dataclass
class ExceptionEvent(BaseEvent):
    """异常事件"""
    event_type: EventType = field(default=EventType.EXCEPTION, init=False)
    exception_code: int = 0
    exception_address: int = 0
    handled: bool = False
    info: str = ""
    
    def __repr__(self):
        h = " [HANDLED]" if self.handled else ""
        return f"ExceptionEvent(0x{self.exception_code:08x} @ 0x{self.exception_address:x}{h})"


@dataclass
class OEPEvent(BaseEvent):
    """OEP检测事件"""
    event_type: EventType = field(default=EventType.OEP_DETECTED, init=False)
    oep: int = 0
    score: float = 0.0
    signals: list = field(default_factory=list)  # 触发信号列表
    
    def __repr__(self):
        return f"OEPEvent(0x{self.oep:x} score={self.score:.1f} signals={self.signals})"


@dataclass
class ModuleLoadEvent(BaseEvent):
    """DLL加载事件"""
    event_type: EventType = field(default=EventType.MODULE_LOAD, init=False)
    dll_name: str = ""
    base_address: int = 0
    size: int = 0
    
    def __repr__(self):
        return f"ModuleLoadEvent({self.dll_name} @ 0x{self.base_address:x})"
