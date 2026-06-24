"""
V7 Alloc Monitor — VirtualAlloc 追踪器
=========================================
Themida 3.x 不修改 .text，而是通过 VirtualAlloc(MEM_COMMIT) 分配新页。
追踪所有 VirtualAlloc/VirtualAllocEx 调用，尤其是 PAGE_EXECUTE_READWRITE 的页。
"""

import struct
from collections import defaultdict
from typing import Dict, List, Optional, Tuple


class AllocMonitor:
    """监控所有 VirtualAlloc 调用，追踪新执行页"""

    def __init__(self, uc, verbose=False):
        self.uc = uc
        self.verbose = verbose
        self._allocs: List[dict] = []
        self._exec_pages: Dict[int, int] = defaultdict(int)  # {page: exec_count}
        self._alloc_count = 0
        self._known_pages: set = set()  # known .text/.boot pages to exclude
        self._new_exec_pages: list = []  # newly allocated execute pages

    def set_known_pages(self):
        """记录已知段页面 (排除)"""
        for addr in range(0x140001000, 0x140C5E000 + 0x1000, 0x1000):
            self._known_pages.add(addr)

    def on_virtual_alloc(self, addr: int, size: int, alloc_type: int, protect: int) -> Optional[int]:
        """记录 VirtualAlloc 调用

        Returns: 返回值 (由 hook 函数设置), None if tracking only
        """
        entry = {
            'addr': addr, 'size': size,
            'alloc_type': alloc_type,  # MEM_COMMIT=0x1000, MEM_RESERVE=0x2000
            'protect': protect,
        }
        self._allocs.append(entry)
        self._alloc_count += 1

        # Check for execute permission
        if protect & 0x10 or protect & 0x20 or protect & 0x40:  # PAGE_EXECUTE*
            self._new_exec_pages.append(entry)
            if self.verbose:
                tp = 'RESERVE' if alloc_type & 0x2000 else 'COMMIT' if alloc_type & 0x1000 else 'BOTH'
                print(f"  [Alloc] EXEC {tp} 0x{addr:x} sz=0x{size:x} prot=0x{protect:x}")

        if self.verbose and self._alloc_count <= 10:
            tp = 'RESERVE' if alloc_type & 0x2000 else 'COMMIT' if alloc_type & 0x1000 else 'BOTH'
            print(f"  [Alloc] {tp} 0x{addr:x} sz=0x{size:x} prot=0x{protect:x}")

        return None  # hook continues normally

    def on_exec(self, address: int):
        """记录执行在新分配页面上的情况"""
        page = address & ~0xFFF
        if page not in self._known_pages:
            self._exec_pages[page] += 1

    def report(self) -> str:
        lines = []
        lines.append(f"\n--- VirtualAlloc Report ({self._alloc_count} calls) ---")

        if self._new_exec_pages:
            lines.append(f"  Execute pages allocated: {len(self._new_exec_pages)}")
            for e in self._new_exec_pages:
                lines.append(f"    0x{e['addr']:x} sz=0x{e['size']:x} "
                           f"prot=0x{e['protect']:x}")

        if self._exec_pages:
            lines.append(f"  Execution on non-known pages:")
            top = sorted(self._exec_pages.items(), key=lambda x: -x[1])[:10]
            for page, count in top:
                lines.append(f"    0x{page:x}: {count} hits")

        return "\n".join(lines)
