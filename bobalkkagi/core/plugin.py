"""
Plugin System + Event Bus
==========================
Bobalkkagi v2.0 — 插件系统和事件总线

设计原则：
  - 所有模块解耦
  - 通过事件总线通信
  - 插件可动态注册/注销
  - 支持自定义Detector和Rebuilder
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, List, Dict, Callable
from collections import defaultdict

from .events import BaseEvent, EventType


class DetectorPlugin(ABC):
    """OEP/VM检测器插件接口"""
    
    name: str = "base_detector"
    version: str = "1.0"
    
    @abstractmethod
    def initialize(self, ctx) -> bool:
        """初始化，返回True表示成功"""
        pass
    
    @abstractmethod
    def process(self, event: BaseEvent, ctx) -> Optional[BaseEvent]:
        """
        处理一个事件。
        返回: 如果检测到OEP/VM，返回对应事件；否则None
        """
        pass
    
    @abstractmethod
    def finalize(self, ctx) -> list:
        """完成分析，返回检测结果列表"""
        pass


class RebuilderPlugin(ABC):
    """PE/IAT/TLS重建器插件接口"""
    
    name: str = "base_rebuilder"
    version: str = "1.0"
    
    @abstractmethod
    def rebuild(self, ctx) -> bool:
        """重建，返回True表示成功"""
        pass


class EventBus:
    """
    事件总线。
    
    Trackers emit events → EventBus dispatches → Detectors process
    """
    
    def __init__(self):
        self._subscribers: Dict[EventType, List[Callable]] = defaultdict(list)
        self._all_subscribers: List[Callable] = []  # 接收所有事件的订阅者
        self.event_count = 0
    
    def subscribe(self, event_type: EventType, handler: Callable):
        """订阅特定类型事件"""
        self._subscribers[event_type].append(handler)
    
    def subscribe_all(self, handler: Callable):
        """订阅所有事件"""
        self._all_subscribers.append(handler)
    
    def emit(self, event: BaseEvent):
        """发布事件到所有订阅者"""
        self.event_count += 1
        
        # 分发给特定类型订阅者
        for handler in self._subscribers.get(event.event_type, []):
            try:
                handler(event)
            except Exception as e:
                pass  # 一个订阅者失败不影响其他
        
        # 分发给全局订阅者
        for handler in self._all_subscribers:
            try:
                handler(event)
            except Exception as e:
                pass
    
    def clear(self):
        """清空订阅者"""
        self._subscribers.clear()
        self._all_subscribers.clear()
        self.event_count = 0


class OEPDetectorBase(DetectorPlugin):
    """
    OEP检测器基类。
    
    子类实现具体的检测算法。
    综合评分公式:
      score = return_to_main_module * 30
            + rw_to_rx_transition * 25
            + call_stack_collapse * 25
            + api_sequence_match * 20
    """
    
    name = "oep_detector"
    
    # 评分权重
    WEIGHT_RETURN_MAIN = 30
    WEIGHT_RW_RX = 25
    WEIGHT_STACK_COLLAPSE = 25
    WEIGHT_API_SEQUENCE = 20
    
    def __init__(self, threshold=50.0):
        self.threshold = threshold
        self._candidates = []
    
    def _score_candidate(self, address: int, signals: list, 
                         weights: list = None) -> float:
        """综合评分"""
        if weights is None:
            weights = [self.WEIGHT_RETURN_MAIN, self.WEIGHT_RW_RX,
                      self.WEIGHT_STACK_COLLAPSE, self.WEIGHT_API_SEQUENCE]
        
        return sum(s * w / 100.0 for s, w in zip(signals, weights))
    
    def find_best(self, candidates: List[dict]) -> Optional[dict]:
        """从候选列表中找最佳OEP"""
        if not candidates:
            return None
        scored = []
        for c in candidates:
            score = self._score_candidate(
                c['address'],
                [c.get('r2m', 0), c.get('rwrw', 0),
                 c.get('stack', 0), c.get('api', 0)]
            )
            scored.append((score, c))
        
        scored.sort(key=lambda x: -x[0])
        best = scored[0]
        
        if best[0] >= self.threshold:
            return best[1]
        return None
