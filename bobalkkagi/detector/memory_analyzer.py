"""
Memory Analyzer — 内存区域分类器
==================================
Bobalkkagi v2.0 — P1: 自动区域分类

对 MemoryTracker 采集的页记录进行分类:
  - Encrypted: 写入后未执行
  - Decrypted: RW→RX 转换完成
  - VM: 频繁执行的小循环 (Themida dispatcher)
  - Code: 只执行不写入
  - Data: 只读写不执行
"""

from datetime import datetime
from typing import List
import math


class RegionClassifier:
    """
    内存区域分类器。
    
    基于页记录的写/执行统计进行分类。
    """
    
    ENTROPY_HIGH = 7.0       # 高熵阈值 (加密数据)
    ENTROPY_LOW = 4.0        # 低熵阈值 (明文代码)
    VM_LOOP_THRESHOLD = 50   # VM dispatcher最小执行次数
    
    def __init__(self, pages: dict):
        """
        Args:
            pages: {address: PageRecord} from MemoryTracker
        """
        self.pages = pages
        self.classified = {}  # {address: classification}
    
    def classify(self) -> dict:
        """对所有页进行分类，返回 {address: category}"""
        for addr, page in self.pages.items():
            cat = self._classify_page(page)
            self.classified[addr] = cat
        return self.classified
    
    def _classify_page(self, page) -> str:
        """分类单个页"""
        w = page.write_count
        x = page.execute_count
        had_rw_rx = page.had_rw_to_rx
        
        # Encrypted: 大量写入，从未执行
        if w > 10 and x == 0:
            return "encrypted"
        
        # Decrypted: RW→RX 转换完成
        if had_rw_rx and x > 0:
            return "decrypted"
        
        # VM dispatcher: 极高执行频率的小循环
        if x > self.VM_LOOP_THRESHOLD and w < 5:
            return "vm"
        
        # Code: 执行，少写入
        if x > 0:
            if w == 0:
                return "code"
            return "mixed"
        
        # Data: 只读写
        if w > 0:
            return "data"
        
        return "unknown"
    
    def get_summary(self) -> str:
        """获取分类摘要"""
        if not self.classified:
            return "No pages classified"
        
        counts = {}
        for cat in self.classified.values():
            counts[cat] = counts.get(cat, 0) + 1
        
        total = len(self.classified)
        lines = ["\n=== Memory Region Classification ==="]
        for cat in ["encrypted", "decrypted", "vm", "code", "data", "mixed", "unknown"]:
            c = counts.get(cat, 0)
            if c > 0:
                pct = c / total * 100
                lines.append(f"  {cat:12s}: {c:4d} pages ({pct:5.1f}%)")
        
        return '\n'.join(lines)
    
    def get_high_value_regions(self) -> list:
        """获取高价值区域（解密后的代码区）"""
        return [
            (addr, page) for addr, page in self.pages.items()
            if self.classified.get(addr) in ("decrypted", "code", "vm")
            and page.execute_count > 0
        ]
    
    def get_possible_oep_regions(self) -> list:
        """获取可能的OEP候选区域"""
        candidates = []
        for addr, page in self.pages.items():
            cat = self.classified.get(addr, "")
            if cat in ("decrypted", "code") and page.execute_count > 5:
                score = page.execute_count * 0.5 + page.write_count * 0.3
                candidates.append((addr, score, cat))
        
        candidates.sort(key=lambda x: -x[1])
        return candidates[:10]
