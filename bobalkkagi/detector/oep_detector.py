"""
OEP Detector — 事件驱动的OEP检测器
====================================
Bobalkkagi v2.0 — P1: 综合评分OEP检测

工作原理:
  1. 订阅 EventBus 的 MemoryEvent + ApiEvent
  2. 维护 OEP 状态机: START → UNPACKING → DECRYPTING → STABILIZING → OEP_FOUND
  3. 综合四重信号评分:
     - return_to_main_module    × 30
     - rw_to_rx_transition     × 25
     - call_stack_collapse     × 25
     - api_sequence_match      × 20

输出: OEPEvent (发送回 EventBus)
"""

from datetime import datetime
from typing import Optional, List

from ..core.events import (
    MemoryEvent, ApiEvent, OEPEvent, EventType, BaseEvent
)
from ..core.plugin import OEPDetectorBase


class OEPDetector(OEPDetectorBase):
    """
    事件驱动的OEP检测器。
    
    通过订阅MemoryEvent和ApiEvent,
    自动追踪OEP状态并输出候选评分。
    """
    
    name = "oep_detector_v2"
    
    def __init__(self, threshold=50.0):
        super().__init__(threshold=threshold)
        self.ctx = None
        self._candidates = []
        self._state = "START"
        
        # 信号计数器
        self._rw_rx_count = 0         # RW→RX转换次数
        self._return_to_main = 0      # 返回主模块次数
        self._stack_collapse = 0      # RET链坍缩次数
        self._api_decrypt_done = 0    # 解密完成API序列
        self._last_exec_in_main = 0   # 最近主模块执行地址
        
        # API行为模型 — 解密完成信号序列
        self._api_sequence = []       # 最近调用的API名列表
        self._DECRYPT_APIS = {
            'VirtualProtect', 'VirtualAlloc',  # 内存操作
            'NtProtectVirtualMemory',          # 直接NT调用
        }
    
    def initialize(self, ctx) -> bool:
        self.ctx = ctx
        GLOBAL_VAR.transition_oep_state("START")
        return True
    
    def process(self, event: BaseEvent, ctx) -> Optional[BaseEvent]:
        """处理一个事件，可能返回OEPEvent"""
        
        # MemoryEvent: 检测RW→RX转换
        if isinstance(event, MemoryEvent) and event.operation == "protect":
            return self._on_memory_protect(event, ctx)
        
        # MemoryEvent: 记录主模块执行
        if isinstance(event, MemoryEvent) and event.operation == "exec":
            return self._on_exec(event, ctx)
        
        # ApiEvent: 追踪API序列
        if isinstance(event, ApiEvent):
            return self._on_api(event, ctx)
        
        return None
    
    def _on_memory_protect(self, event: MemoryEvent, ctx) -> Optional[OEPEvent]:
        """检测RW→RX转换"""
        old_has_w = event.old_protect & 0x20  # write flag
        new_has_x = event.new_protect & 0x10  # exec flag
        
        if old_has_w and new_has_x:
            self._rw_rx_count += 1
            GLOBAL_VAR.transition_oep_state("DECRYPTING")
        
        return None
    
    def _on_exec(self, event: MemoryEvent, ctx) -> Optional[OEPEvent]:
        """记录主模块执行"""
        if GLOBAL_VAR.image_base <= event.address < GLOBAL_VAR.image_end:
            self._last_exec_in_main = event.address
            self._return_to_main += 1
            GLOBAL_VAR.transition_oep_state("UNPACKING")
        return None
    
    def _on_api(self, event: ApiEvent, ctx) -> Optional[OEPEvent]:
        """追踪API调用序列"""
        self._api_sequence.append(event.api)
        if len(self._api_sequence) > 10:
            self._api_sequence.pop(0)
        
        # 检测解密完成信号: VirtualProtect(RW→RX)是最后一个解密API
        if event.api in self._DECRYPT_APIS:
            self._api_decrypt_done += 1
            
            # 如果之后出现非解密API，准备OEP检测
            if self._rw_rx_count >= 3 and self._return_to_main >= 5:
                GLOBAL_VAR.transition_oep_state("STABILIZING")
                
                # 综合评分
                score = self._score_candidate(
                    self._last_exec_in_main,
                    [self._return_to_main, self._rw_rx_count,
                     self._stack_collapse, self._api_decrypt_done]
                )
                
                if score >= self.threshold:
                    GLOBAL_VAR.transition_oep_state("OEP_FOUND")
                    oep_event = OEPEvent(
                        oep=self._last_exec_in_main,
                        score=score,
                        signals=[
                            f"ret_to_main={self._return_to_main}",
                            f"rw_rx={self._rw_rx_count}",
                            f"stack={self._stack_collapse}",
                            f"api={self._api_decrypt_done}",
                        ]
                    )
                    GLOBAL_VAR.record_oep(self._last_exec_in_main, score, oep_event.signals)
                    return oep_event
        
        return None
    
    def finalize(self, ctx) -> list:
        """返回最终OEP候选列表"""
        if GLOBAL_VAR.oep:
            return [{'address': GLOBAL_VAR.oep, 'score': 100, 'state': GLOBAL_VAR.oep_state}]
        return [{'address': self._last_exec_in_main, 'score': self._score_candidate(
            self._last_exec_in_main,
            [self._return_to_main, self._rw_rx_count, self._stack_collapse, self._api_decrypt_done]
        ), 'state': GLOBAL_VAR.oep_state}]
