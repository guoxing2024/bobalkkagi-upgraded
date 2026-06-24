"""
V7 Memory Transition Analyzer — 全内存页迁移监控
=====================================================
Bobalkkagi V7.0 — Expert Review Phase 1

监控目标:
  1. 哪些页被写入 (解密/初始化)
  2. 哪些页被执行 (VM vs Native 代码)
  3. 哪些页从 RW→RX (解密完成信号)
  4. VirtualAlloc/VirtualProtect 调用时间线

输出:
  Top Executed Regions (执行最频繁的区域)
  Top Written Regions (写入最频繁的区域)  
  RW→RX Timeline (解密时间线)
"""

import struct
from collections import defaultdict
from typing import Dict, List, Set, Tuple


class MemoryTransitionAnalyzer:
    """V7: 全内存页迁移分析器"""

    PAGE_SIZE = 0x1000

    def __init__(self, uc, verbose=False):
        self.uc = uc
        self.verbose = verbose

        # 统计
        self._page_writes: Dict[int, int] = defaultdict(int)     # {page: write_count}
        self._page_execs: Dict[int, int] = defaultdict(int)      # {page: exec_count}
        self._page_protects: List[dict] = []                      # {addr, size, old, new, time}
        self._page_allocs: List[dict] = []                        # {addr, size, prot, time}

        # 当前页权限快照
        self._page_protections: Dict[int, int] = {}  # {page: protection}

        self._exec_count = 0
        self._write_count = 0
        self._sample_interval = 1000  # sample RIP every N instructions

        # 段分类
        self._regions = {
            'boot':    (0x140885000, 0x140C5E000),
            'themida': (0x140213000, 0x140885000),
            'text':    (0x140001000, 0x140001000 + 0x1a4000),
            'dll':     (0x7FF000000000, 0x800000000000),
        }

    def install(self):
        """安装监控 hooks"""
        from unicorn import (UC_HOOK_MEM_WRITE, UC_HOOK_CODE,
                           UC_HOOK_MEM_READ_UNMAPPED, UC_HOOK_MEM_WRITE_UNMAPPED)

        # 1. 内存写入监控 (所有页)
        self.uc.hook_add(UC_HOOK_MEM_WRITE, self._on_mem_write)

        # 2. 执行采样 (仅 0x140000000 范围)
        self.uc.hook_add(UC_HOOK_CODE, self._on_code,
                         None, 0x140000000, 0x141000000)

        # 3. 未映射内存自动处理
        def on_unmapped(uc, acc, addr, sz, val, ud):
            page = addr & ~0xFFF
            try:
                uc.mem_map(page, 0x1000, 0x7)  # RWX
                self._page_allocs.append({
                    'addr': page, 'size': 0x1000, 'prot': 0x7, 'reason': 'unmapped'
                })
            except:
                pass
            return True
        self.uc.hook_add(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED, on_unmapped)

    def _on_mem_write(self, uc, access, address, size, value, user_data):
        """记录内存写入"""
        page = address & ~self.PAGE_SIZE
        self._page_writes[page] += 1
        self._write_count += 1

    def _on_code(self, uc, address, size, user_data):
        """采样执行地址"""
        self._exec_count += 1
        if self._exec_count % self._sample_interval == 0:
            page = address & ~self.PAGE_SIZE
            self._page_execs[page] += self._sample_interval

    def classify(self, addr: int) -> str:
        """分类地址所属区域"""
        for name, (start, end) in self._regions.items():
            if start <= addr < end:
                return name
        return 'other'

    def track_virtual_protect(self, addr: int, size: int, old_prot: int, new_prot: int):
        """记录 VirtualProtect 调用"""
        page = addr & ~self.PAGE_SIZE
        pages = range(page, (addr + size + 0xFFF) & ~self.PAGE_SIZE, self.PAGE_SIZE)
        for p in pages:
            self._page_protections[p] = new_prot

        self._page_protects.append({
            'addr': addr, 'size': size, 'old': old_prot, 'new': new_prot,
            'class': self.classify(addr)
        })

    def track_virtual_alloc(self, addr: int, size: int, prot: int, alloc_type: int):
        """记录 VirtualAlloc 调用"""
        self._page_allocs.append({
            'addr': addr, 'size': size, 'prot': prot, 'type': alloc_type
        })

    def report(self) -> str:
        """生成分析报告"""
        lines = []
        lines.append("=" * 60)
        lines.append("V7 Memory Transition Report")
        lines.append("=" * 60)

        # Summary
        lines.append(f"\nTotal writes: {self._write_count}")
        lines.append(f"Total exec samples: {self._exec_count}")
        lines.append(f"Pages written: {len(self._page_writes)}")
        lines.append(f"Pages executed: {len(self._page_execs)}")
        lines.append(f"VirtualProtect calls: {len(self._page_protects)}")
        lines.append(f"VirtualAlloc calls: {len(self._page_allocs)}")

        # Top Executed Pages
        if self._page_execs:
            lines.append(f"\n--- Top 10 Executed Pages ---")
            top_ex = sorted(self._page_execs.items(), key=lambda x: -x[1])[:10]
            for page, count in top_ex:
                cls = self.classify(page)
                lines.append(f"  0x{page:012x} [{cls}] : {count} samples")

        # Top Written Pages
        if self._page_writes:
            lines.append(f"\n--- Top 10 Written Pages ---")
            top_wr = sorted(self._page_writes.items(), key=lambda x: -x[1])[:10]
            for page, count in top_wr:
                cls = self.classify(page)
                lines.append(f"  0x{page:012x} [{cls}] : {count} writes")

        # RW→RX Transitions
        rx_transitions = [p for p in self._page_protects
                         if (p['old'] & 0xF0) == 0 and (p['new'] & 0xF0) != 0]
        if rx_transitions:
            lines.append(f"\n--- RW→RX Transitions ({len(rx_transitions)}) ---")
            for p in rx_transitions:
                lines.append(f"  0x{p['addr']:x} sz=0x{p['size']:x} "
                           f"[{p['class']}] old=0x{p['old']:x} new=0x{p['new']:x}")

        # Allocs
        if self._page_allocs:
            lines.append(f"\n--- VirtualAlloc calls ---")
            for a in self._page_allocs:
                lines.append(f"  0x{a['addr']:x} sz=0x{a['size']:x} "
                           f"prot=0x{a['prot']:x} [{a.get('reason','explicit')}]")

        # Region summary
        lines.append(f"\n--- Region Execution Summary ---")
        region_exec = defaultdict(int)
        for page, count in self._page_execs.items():
            region_exec[self.classify(page)] += count
        for cls, count in sorted(region_exec.items(), key=lambda x: -x[1]):
            pct = (count / max(self._exec_count, 1)) * 100
            lines.append(f"  {cls}: {count} samples ({pct:.1f}%)")

        return "\n".join(lines)

    def print_report(self):
        print(self.report())
