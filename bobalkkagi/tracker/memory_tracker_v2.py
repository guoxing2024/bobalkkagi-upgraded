
class MemoryTrackerV2(MemoryTracker):
    """
    MemoryTracker v2.0 — 集成事件总线
    
    与 v1 的区别：
      - 自动将内存操作发布到EventBus
      - 其他Detector可订阅事件总线获取信号
      - 支持多Detector协同
    """
    
    def __init__(self, event_bus: EventBus = None):
        super().__init__()
        self.event_bus = event_bus
    
    def _on_write(self, uc, access, address, size, value, user_data):
        ret = super()._on_write(uc, access, address, size, value, user_data)
        if self.event_bus:
            event = MemoryEvent(operation="write", address=address, 
                               size=size, value=value)
            self.event_bus.emit(event)
        return ret
    
    def _on_prot_change(self, uc, access, address, size, prot, user_data):
        old_prot = UC_PROT_NONE
        page = self.pages.get(address & ~0xFFF)
        if page:
            old_prot = page.current_prot
        ret = super()._on_prot_change(uc, access, address, size, prot, user_data)
        if self.event_bus:
            event = MemoryEvent(operation="protect", address=address,
                               old_protect=old_prot, new_protect=prot)
            self.event_bus.emit(event)
        return ret
    
    def _on_exec(self, uc, address, size, user_data):
        ret = super()._on_exec(uc, address, size, user_data)
        if self.event_bus:
            event = MemoryEvent(operation="exec", address=address, size=size)
            self.event_bus.emit(event)
        return ret
