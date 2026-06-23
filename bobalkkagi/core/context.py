"""
UnpackContext — 中心状态容器
=============================
Bobalkkagi v2.0 — 替代 GLOBAL_VAR 的上下文对象

架构原则：
  - 所有状态进入 Context
  - 任何模块通过 ctx 访问数据
  - 禁止共享全局状态
  - 支持多实例（未来可并行处理多样本）
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, Dict, List
from pathlib import Path

from .events import (
    ApiEvent, MemoryEvent, CallEvent, ExceptionEvent,
    OEPEvent, ModuleLoadEvent, EventType
)


@dataclass
class ModuleInfo:
    """加载的模块信息"""
    name: str = ""
    base: int = 0
    size: int = 0
    path: str = ""
    is_dll: bool = False


@dataclass
class RegionInfo:
    """内存区域信息（用于内存分析引擎）"""
    start: int = 0
    end: int = 0
    protect: int = 0
    write_count: int = 0
    execute_count: int = 0
    classification: str = ""  # encrypted, decrypted, vm, code, data
    entropy: float = 0.0


@dataclass
class TLSInfo:
    """TLS目录信息"""
    start_of_raw_data: int = 0
    end_of_raw_data: int = 0
    address_of_index: int = 0
    address_of_callbacks: int = 0
    callback_count: int = 0
    callbacks: List[int] = field(default_factory=list)


class UnpackContext:
    """
    解包上下文——整个脱壳流程的中心状态容器。
    
    包含：
      - 样本信息和PE元数据
      - 模块/内存镜像
      - 事件日志（API调用、内存操作、异常等）
      - OEP候选
      - TLS/SEH信息
      - 追踪器状态
    """
    
    def __init__(self, sample_path: str):
        # === 样本信息 ===
        self.sample_path = sample_path
        self.sample_name = Path(sample_path).name
        self.metadata = {
            'created': datetime.now().isoformat(),
            'architecture': 'x64',
            'packer': 'unknown',
            'packer_version': '',
        }
        
        # === PE信息 ===
        self.pe = None                     # pefile.PE 对象
        self.image_base: int = 0x140000000
        self.image_end: int = 0
        self.entry_point: int = 0
        self.section_count: int = 0
        
        # === 模块 ===
        self.modules: Dict[str, ModuleInfo] = {}
        self.module_order: List[str] = []  # 加载顺序
        
        # === 内存镜像 ===
        self.memory_image: Optional[bytearray] = None
        self.regions: List[RegionInfo] = []
        
        # === OEP ===
        self.oep: int = 0
        self.oep_candidates: list = []     # [(address, score, signals), ...]
        self._oep_state = "START"          # START, UNPACKING, DECRYPTING, STABILIZING, OEP_FOUND
        
        # === TLS ===
        self.tls: Optional[TLSInfo] = None
        
        # === 事件日志 ===
        self.api_events: List[ApiEvent] = []
        self.memory_events: List[MemoryEvent] = []
        self.call_events: List[CallEvent] = []
        self.exception_events: List[ExceptionEvent] = []
        self.oep_events: List[OEPEvent] = []
        
        # === 导入/导出 ===
        self.imports: Dict[str, List[str]] = {}  # {dll: [func, ...]}
        self.exports: Dict[int, str] = {}        # {address: name}
        
        # === 运行时记录 ===
        self.runtime_api_calls: set = set()      # {(dll, func), ...}
        
        # === 追踪器状态 ===
        self._api_call_count = 0
        self._memory_write_count = 0
        self._exec_count = 0
        self._ret_stack: List[int] = []          # 调用栈(RET链分析用)
        
        # === 输出 ===
        self.dump_path = ""
        self.output_path = ""
        self.status = ""
    
    # ===== Event recording =====
    
    def record_api(self, dll: str, api: str, args: dict = None, ret: int = 0, addr: int = 0):
        """记录API调用事件"""
        event = ApiEvent(dll=dll, api=api, args=args or {}, ret_value=ret, call_address=addr)
        self.api_events.append(event)
        self.runtime_api_calls.add((dll.lower(), api))
        self._api_call_count += 1
    
    def record_memory_write(self, address: int, size: int, value: int = 0):
        """记录内存写入事件"""
        event = MemoryEvent(operation="write", address=address, size=size, value=value)
        self.memory_events.append(event)
        self._memory_write_count += 1
    
    def record_memory_protect(self, address: int, old_prot: int, new_prot: int):
        """记录保护变更事件"""
        event = MemoryEvent(operation="protect", address=address, 
                           old_protect=old_prot, new_protect=new_prot)
        self.memory_events.append(event)
    
    def record_call(self, caller: int, callee: int, return_addr: int):
        """记录CALL事件"""
        event = CallEvent(is_call=True, caller=caller, callee=callee, return_addr=return_addr)
        self.call_events.append(event)
        self._ret_stack.append(return_addr)
    
    def record_ret(self, return_addr: int):
        """记录RET事件"""
        event = CallEvent(is_call=False, return_addr=return_addr)
        self.call_events.append(event)
        if self._ret_stack and self._ret_stack[-1] == return_addr:
            self._ret_stack.pop()
    
    def record_exception(self, code: int, address: int, handled: bool = False, info: str = ""):
        """记录异常事件"""
        event = ExceptionEvent(exception_code=code, exception_address=address,
                              handled=handled, info=info)
        self.exception_events.append(event)
    
    def record_oep(self, address: int, score: float, signals: list):
        """记录OEP检测事件"""
        event = OEPEvent(oep=address, score=score, signals=signals)
        self.oep_events.append(event)
        self.oep = address
        self._oep_state = "OEP_FOUND"
    
    def record_module(self, name: str, base: int, size: int, is_dll: bool = False):
        """记录模块加载"""
        self.modules[name.lower()] = ModuleInfo(name=name, base=base, size=size, is_dll=is_dll)
        self.module_order.append(name)
    
    # ===== OEP State Machine =====
    
    @property
    def oep_state(self):
        return self._oep_state
    
    def transition_oep_state(self, new_state: str):
        """OEP状态机转换"""
        valid_transitions = {
            "START": ["UNPACKING"],
            "UNPACKING": ["DECRYPTING"],
            "DECRYPTING": ["STABILIZING"],
            "STABILIZING": ["OEP_FOUND"],
        }
        if new_state in valid_transitions.get(self._oep_state, []):
            self._oep_state = new_state
    
    # ===== Accessors =====
    
    def get_module(self, name: str) -> Optional[ModuleInfo]:
        return self.modules.get(name.lower())
    
    def get_runtime_imports(self) -> Dict[str, List[str]]:
        """获取运行时记录的API调用，按DLL分组"""
        result = {}
        for dll, func in sorted(self.runtime_api_calls):
            if dll not in result:
                result[dll] = []
            result[dll].append(func)
        return result
    
    def summary(self) -> str:
        """生成摘要"""
        return (
            f"UnpackContext({self.sample_name})\n"
            f"  OEP: 0x{self.oep:x}  state: {self._oep_state}\n"
            f"  Modules: {len(self.modules)}\n"
            f"  API calls: {len(self.api_events)}\n"
            f"  Memory events: {len(self.memory_events)}\n"
            f"  Exceptions: {len(self.exception_events)}\n"
            f"  Runtime APIs: {len(self.runtime_api_calls)}\n"
            f"  OEP candidates: {len(self.oep_events)}"
        )
