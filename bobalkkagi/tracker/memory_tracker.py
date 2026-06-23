"""
Memory Tracker — 内存页保护状态追踪
======================================
Bobalkkagi v2.0 — 追踪Unicorn模拟期间的内存页保护状态变化

支持事件总线模式：
  MemoryTrackerV2 自动将写入/保护变更/执行事件发送到EventBus
"""

from collections import defaultdict
from datetime import datetime
from unicorn import *
from unicorn.x86_const import *

# v2.0 EventBus 集成
from ..core.events import MemoryEvent, EventType
from ..core.plugin import EventBus

# 保护标志映射
PROTECT_NAMES = {
    UC_PROT_NONE: "---",
    UC_PROT_READ: "R--",
    UC_PROT_WRITE: "-W-",
    UC_PROT_EXEC: "--X",
    UC_PROT_READ | UC_PROT_WRITE: "RW-",
    UC_PROT_READ | UC_PROT_EXEC: "R-X",
    UC_PROT_WRITE | UC_PROT_EXEC: "-WX",
    UC_PROT_ALL: "RWX",
}

PROTECT_BITS = [
    ("read", UC_PROT_READ),
    ("write", UC_PROT_WRITE),
    ("exec", UC_PROT_EXEC),
]


class PageRecord:
    """单个内存页的记录"""
    __slots__ = ('address', 'size', 'initial_prot', 'current_prot',
                 'write_count', 'execute_count', 'prot_changes', 'first_write',
                 'last_write', 'first_exec', 'last_exec')
    
    def __init__(self, address, size, prot):
        self.address = address
        self.size = size
        self.initial_prot = prot
        self.current_prot = prot
        self.write_count = 0
        self.execute_count = 0
        self.prot_changes = []  # [(old_prot, new_prot, timestamp), ...]
        self.first_write = None
        self.last_write = None
        self.first_exec = None
        self.last_exec = None
    
    def record_write(self):
        now = datetime.now()
        self.write_count += 1
        if self.first_write is None:
            self.first_write = now
        self.last_write = now
    
    def record_exec(self):
        now = datetime.now()
        self.execute_count += 1
        if self.first_exec is None:
            self.first_exec = now
        self.last_exec = now
    
    def record_prot_change(self, old_prot, new_prot):
        self.prot_changes.append((old_prot, new_prot, datetime.now()))
        self.current_prot = new_prot
    
    @property
    def had_rw_to_rx(self):
        """是否经历过RW→RX转换（极可能是解密完成信号）"""
        old_has_w = any(p & UC_PROT_WRITE for p, _, _ in self.prot_changes)
        new_has_x = self.current_prot & UC_PROT_EXEC
        return old_has_w and new_has_x
    
    @property
    def is_hot_region(self):
        """高价值区域：频繁写入后执行"""
        return self.write_count > 10 and self.execute_count > 0
    
    def prot_str(self, prot):
        return PROTECT_NAMES.get(prot, f"0x{prot:x}")
    
    def summary(self):
        w = self.prot_str(self.initial_prot)
        c = self.prot_str(self.current_prot)
        rw_rx = " [RW→RX!]" if self.had_rw_to_rx else ""
        hot = " [HOT]" if self.is_hot_region else ""
        return (f"  0x{self.address:08x}: {w}→{c} "
                f"W={self.write_count} X={self.execute_count}"
                f"{rw_rx}{hot}")


class MemoryTracker:
    """Unicorn内存保护状态追踪器"""
    
    def __init__(self):
        self.pages = {}  # {page_aligned_addr: PageRecord}
        self._hook_write = None
        self._hook_prot = None
        self._hook_exec = None
        self.uc = None
        self.image_base = 0
        self.image_end = 0
        self.running = False
    
    def install(self, uc, image_base=0x140000000, image_end=0):
        """
        在Unicorn实例上安装追踪hook。
        必须在uc.emu_start()之前调用。
        """
        self.uc = uc
        self.image_base = image_base
        self.image_end = image_end
        self.running = True
        
        # Hook内存写入
        self._hook_write = uc.hook_add(UC_HOOK_MEM_WRITE, self._on_write)
        
        # Hook内存保护变更
        self._hook_prot = uc.hook_add(UC_HOOK_MEM_PROT, self._on_prot_change)
        
        # Hook代码执行（只在主模块范围内）
        if image_end > image_base:
            self._hook_exec = uc.hook_add(UC_HOOK_CODE, self._on_exec,
                                           None, image_base, image_end)
    
    def uninstall(self):
        """卸载所有hook"""
        if self.uc and self.running:
            try:
                if self._hook_write:
                    self.uc.hook_del(self._hook_write)
                if self._hook_prot:
                    self.uc.hook_del(self._hook_prot)
                if self._hook_exec:
                    self.uc.hook_del(self._hook_exec)
            except:
                pass
        self.running = False
    
    def _get_page(self, address):
        """获取或创建页记录（页对齐）"""
        page_addr = address & ~0xFFF
        if page_addr not in self.pages:
            try:
                prot = self.uc.mem_protect(page_addr, 0x1000)
            except:
                prot = UC_PROT_NONE
            self.pages[page_addr] = PageRecord(page_addr, 0x1000, prot)
        return self.pages[page_addr]
    
    def _on_write(self, uc, access, address, size, value, user_data):
        """内存写入回调"""
        if address < self.image_base:
            return True
        page = self._get_page(address)
        page.record_write()
        return True
    
    def _on_prot_change(self, uc, access, address, size, prot, user_data):
        """内存保护变更回调"""
        old_prot = UC_PROT_NONE
        page = self._get_page(address)
        old_prot = page.current_prot
        page.record_prot_change(old_prot, prot)
        return True
    
    def _on_exec(self, uc, address, size, user_data):
        """代码执行回调（只在主模块范围内）"""
        page = self._get_page(address)
        page.record_exec()
        return True
    
    def find_oep_candidates(self, top_n=3):
        """
        基于四重信号寻找OEP候选：
        1. RW→RX转换（解密完成标志）
        2. 高写入+高执行区域
        3. 最后执行地址
        4. 靠近模块入口的区域
        """
        candidates = []
        
        # 信号1: RW→RX转换的页
        for page in self.pages.values():
            if page.had_rw_to_rx:
                candidates.append({
                    'address': page.address,
                    'score': 4,
                    'signal': 'RW→RX',
                    'write_count': page.write_count,
                    'exec_count': page.execute_count,
                })
        
        # 信号2: 高价值区域（热区域）
        for page in self.pages.values():
            if page.is_hot_region and page.address not in {c['address'] for c in candidates}:
                candidates.append({
                    'address': page.address,
                    'score': 3,
                    'signal': 'HOT',
                    'write_count': page.write_count,
                    'exec_count': page.execute_count,
                })
        
        # 信号3: 最后执行地址附近
        last_exec_pages = [p for p in self.pages.values() if p.last_exec is not None]
        if last_exec_pages:
            last_exec_pages.sort(key=lambda p: p.last_exec, reverse=True)
            for p in last_exec_pages[:3]:
                if p.address not in {c['address'] for c in candidates}:
                    candidates.append({
                        'address': p.address,
                        'score': 2,
                        'signal': 'LAST_EXEC',
                        'write_count': p.write_count,
                        'exec_count': p.execute_count,
                    })
        
        candidates.sort(key=lambda c: (c['score'], c['write_count'] + c['exec_count']), reverse=True)
        return candidates[:top_n]
    
    def get_report(self):
        """生成完整追踪报告"""
        lines = ["\n=== Memory Tracker Report ==="]
        
        # RW→RX转换
        rw_rx = [p for p in self.pages.values() if p.had_rw_to_rx]
        if rw_rx:
            lines.append(f"\n[RW→RX Transitions] ({len(rw_rx)} pages):")
            for p in sorted(rw_rx, key=lambda x: x.address):
                lines.append(p.summary())
        
        # 热区域
        hot = [p for p in self.pages.values() if p.is_hot_region]
        if hot:
            lines.append(f"\n[Hot Regions] ({len(hot)} pages):")
            for p in sorted(hot, key=lambda x: -x.write_count)[:10]:
                lines.append(p.summary())
        
        # OEP候选
        oep_candidates = self.find_oep_candidates()
        if oep_candidates:
            lines.append(f"\n[OEP Candidates]:")
            for c in oep_candidates:
                lines.append(f"  0x{c['address']:08x}: score={c['score']} "
                            f"signal={c['signal']} W={c['write_count']} X={c['exec_count']}")
        
        # 统计
        lines.append(f"\nTotal pages tracked: {len(self.pages)}")
        total_writes = sum(p.write_count for p in self.pages.values())
        total_execs = sum(p.execute_count for p in self.pages.values())
        lines.append(f"Total writes: {total_writes}")
        lines.append(f"Total executes: {total_execs}")
        
        return '\n'.join(lines)
