"""
VM Analyzer — P3: VM 入口检测 + Handler 提取 + 字节码分析
===========================================================
Bobalkkagi v4.0 — Themida/VMProtect 虚拟机分析框架。

模块:
  - VMEntryDetector: 基于特征的 VM 解释器入口点识别
  - HandlerExtractor: 执行轨迹中的高频跳转目标 → Handler 表
  - BytecodeReader: 从 VM 上下文读取字节码流

支持引擎:
  - "themida": Themida 3.x VM (VMP 3.0 engine)
  - "vmprotect": VMProtect 3.x native engine
  - "auto": 自动检测
"""

from typing import List, Optional, Dict, Tuple, Set
from dataclasses import dataclass, field
import struct

from ..vtil.ir import HandlerInfo
from ..vtil.lift_engine import VTILLiftEngine

try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64
    HAS_CAPSTONE = True
except ImportError:
    HAS_CAPSTONE = False


# ============================================================
# VM Engine 类型
# ============================================================

VM_ENGINE_THEMIDA = "themida"
VM_ENGINE_VMPROTECT = "vmprotect"
VM_ENGINE_AUTO = "auto"


# ============================================================
# Themida VM Entry 特征
# ============================================================

@dataclass
class VMEntrySignature:
    """VM 入口签名"""
    engine: str                       # "themida" / "vmprotect"
    name: str                         # 签名名称
    # 入口指令序列 (助记符列表)
    prologue_mnemonics: List[str] = field(default_factory=list)
    # 入口结构偏移
    handler_table_offset: int = 0     # Handler 表在入口附近偏移
    bytecode_ptr_offset: int = 0      # 字节码指针在上下文中的偏移
    vsp_offset: int = 0              # 虚拟栈指针偏移


# Themida 3.x VM 入口特征
THEMIDA_VM_SIGNATURES = [
    VMEntrySignature(
        engine=VM_ENGINE_THEMIDA,
        name="themida_vmp3_entry",
        prologue_mnemonics=['push', 'push', 'mov', 'mov', 'mov', 'jmp'],
        handler_table_offset=0x20,
        bytecode_ptr_offset=0x48,
        vsp_offset=0x50,
    ),
    VMEntrySignature(
        engine=VM_ENGINE_THEMIDA,
        name="themida_vmp3_entry_alt",
        prologue_mnemonics=['push', 'sub', 'mov', 'mov', 'lea', 'jmp'],
        handler_table_offset=0x28,
        bytecode_ptr_offset=0x48,
        vsp_offset=0x50,
    ),
]

# VMProtect 3.x VM 入口特征
VMPROTECT_VM_SIGNATURES = [
    VMEntrySignature(
        engine=VM_ENGINE_VMPROTECT,
        name="vmprotect3_entry",
        prologue_mnemonics=['push', 'push', 'push', 'push', 'push', 'mov', 'mov', 'jmp'],
        handler_table_offset=0x30,
        bytecode_ptr_offset=0x40,
        vsp_offset=0x48,
    ),
]


# ============================================================
# VMAnalyzer
# ============================================================

class VMAnalyzer:
    """
    VM 分析器。

    工作流程:
      1. detect_vm_entry() → 扫描 dump 中的 VM 入口
      2. extract_handlers() → 基于执行轨迹提取 Handler 表
      3. read_bytecode() → 从 VM 上下文读取字节码
    """

    def __init__(self, ctx, lift_engine: Optional[VTILLiftEngine] = None):
        self.ctx = ctx
        self.lift_engine = lift_engine or VTILLiftEngine()
        self._capstone = None
        if HAS_CAPSTONE:
            self._capstone = Cs(CS_ARCH_X86, CS_MODE_64)
        self._detected_engine = VM_ENGINE_AUTO
        self._entries: List[int] = []
        self._handlers: Dict[int, HandlerInfo] = {}
        # 执行轨迹 (地址 → 次数)
        self._execution_trace: Dict[int, int] = {}

    # ===== VM Entry Detection =====

    def detect_vm_entry(self, memory_image: Optional[bytes] = None,
                        image_base: int = 0x140000000) -> List[int]:
        """
        扫描内存图像，识别 VM 解释器入口点。

        Returns:
            疑似 VM 入口点列表 (VA)
        """
        data = memory_image or self.ctx.memory_image
        if not data or not self._capstone:
            return []

        entries = []
        base = image_base or self.ctx.image_base

        # 扫描 .themida 段 (通常在 dump 后半部分)
        themida_section = getattr(self.ctx, 'themida_section', None)
        scan_ranges = []

        if themida_section and len(themida_section) >= 3:
            va = themida_section[1]
            size = min(themida_section[2], 0x10000)  # 前64KB
            scan_ranges.append((va, size))
        else:
            # 扫描整个 dump 的可执行区域
            scan_ranges.append((base, min(len(data), 0x200000)))

        for va, size in scan_ranges:
            offset = va - base
            if offset < 0 or offset + size > len(data):
                continue

            chunk = data[offset:offset + size]

            # 尝试匹配 Themida 签名
            for sig in THEMIDA_VM_SIGNATURES:
                results = self._match_signature(chunk, va, sig)
                entries.extend(results)

            # 尝试匹配 VMProtect 签名
            for sig in VMPROTECT_VM_SIGNATURES:
                results = self._match_signature(chunk, va, sig)
                entries.extend(results)

        self._entries = entries
        if entries:
            self._detected_engine = VM_ENGINE_THEMIDA  # 默认，可通过后续分析调整

        return entries

    def _match_signature(self, data: bytes, base_va: int,
                         sig: VMEntrySignature) -> List[int]:
        """匹配 VM 入口签名"""
        if not self._capstone:
            return []

        results = []
        window_size = min(len(sig.prologue_mnemonics) + 5, 16)

        for insn in self._capstone.disasm(data[:0x10000], base_va):
            # 检查接下来 N 条指令的助记符是否匹配签名
            if insn.mnemonic.lower() != sig.prologue_mnemonics[0]:
                continue

            # 从当前位置取 window_size 条指令
            chunk_start = insn.address - base_va
            if chunk_start < 0:
                continue
            chunk = data[chunk_start:chunk_start + 0x100]
            mnemonics = []
            count = 0
            for i in self._capstone.disasm(chunk, insn.address):
                mnemonics.append(i.mnemonic.lower())
                count += 1
                if count >= window_size:
                    break

            # 前缀匹配
            match_len = 0
            for a, b in zip(mnemonics, sig.prologue_mnemonics):
                if a == b:
                    match_len += 1
                else:
                    break

            if match_len >= len(sig.prologue_mnemonics):
                results.append(insn.address)
                print(f"  [VMAnalyzer] VM entry detected: 0x{insn.address:x} ({sig.name})")

        return results

    # ===== Handler Extraction =====

    def record_execution(self, address: int):
        """记录执行地址"""
        self._execution_trace[address] = self._execution_trace.get(address, 0) + 1

    def extract_handlers(self, min_visits: int = 5) -> List[HandlerInfo]:
        """
        从执行轨迹中提取高频跳转目标 → Handler 表。

        Args:
            min_visits: 最少访问次数阈值

        Returns:
            Handler 列表
        """
        if not self._execution_trace:
            return []

        # 按访问次数排序
        sorted_addrs = sorted(self._execution_trace.items(),
                             key=lambda x: -x[1])

        handlers = []
        handler_idx = 1
        for addr, count in sorted_addrs:
            if count < min_visits:
                break
            info = HandlerInfo(
                address=addr,
                name=f"handler_{handler_idx}",
                visit_count=count,
            )
            handlers.append(info)
            self._handlers[addr] = info
            handler_idx += 1

        # 尝试为 handlers 做 VTIL 提升
        if self.lift_engine and self.lift_engine.available:
            memory = self.ctx.memory_image
            if memory:
                for handler in handlers[:50]:  # 限制 50 个
                    offset = handler.address - self.ctx.image_base
                    if 0 <= offset < len(memory):
                        try:
                            routine = self.lift_engine.lift_stub(
                                memory[offset:offset + 256],
                                handler.address, 256
                            )
                            if routine.blocks:
                                handler.lifted_block = list(routine.blocks.values())[0]
                        except:
                            pass

        print(f"  [VMAnalyzer] Extracted {len(handlers)} handlers "
              f"(from {len(self._execution_trace)} traced addresses)")

        return handlers

    # ===== Bytecode Reading =====

    def read_bytecode(self, handler: HandlerInfo = None,
                      vpc_addr: int = 0, size: int = 64) -> Optional[bytes]:
        """
        从 VM 上下文结构中读取字节码。

        Args:
            handler: Handler 信息（获取字节码范围）
            vpc_addr: 虚拟 PC 地址（覆盖上下文中的地址）
            size: 读取大小

        Returns:
            字节码 bytes
        """
        memory = self.ctx.memory_image
        if not memory:
            return None

        # 尝试从 Handler 的 bytecode_range 读取
        if handler and handler.bytecode_range != (0, 0):
            start, end = handler.bytecode_range
            offset = start - self.ctx.image_base
            if 0 <= offset < len(memory):
                return bytes(memory[offset:offset + min(end - start, size)])

        # 尝试从 VM 上下文结构读取 (vPC 位置在 [rbp+0x48] for Themida)
        if vpc_addr:
            offset = vpc_addr - self.ctx.image_base
            if 0 <= offset < len(memory):
                return bytes(memory[offset:offset + size])

        # 从 .themida 段读取
        themida = getattr(self.ctx, 'themida_section', None)
        if themida and len(themida) >= 2:
            va = themida[1]
            offset = va - self.ctx.image_base
            if 0 <= offset < len(memory):
                return bytes(memory[offset:offset + min(0x1000, size)])

        return None

    # ===== 综合分析 =====

    def analyze(self, memory_image: bytes = None,
                image_base: int = 0) -> dict:
        """
        执行完整 VM 分析流水线。

        Returns:
            {
              "detected": bool,
              "engine": str,
              "entry_points": [...],
              "handler_count": int,
              "bytecode_size": int,
              "vtil_summary": {...}
            }
        """
        data = memory_image or self.ctx.memory_image
        base = image_base or self.ctx.image_base

        result = {
            "detected": False,
            "engine": VM_ENGINE_AUTO,
            "entry_points": [],
            "handler_count": 0,
            "bytecode_size": 0,
            "bytecode_sample": "",
            "vtil_summary": {
                "lifted_handlers": 0,
                "simplified_handlers": 0,
                "api_calls_in_vm": [],
            }
        }

        # Step 1: 检测 VM 入口
        entries = self.detect_vm_entry(data, base)
        if entries:
            result["detected"] = True
            result["engine"] = self._detected_engine
            result["entry_points"] = [f"0x{e:x}" for e in entries[:10]]

        # Step 2: 提取 Handlers
        handlers = self.extract_handlers(min_visits=3)
        result["handler_count"] = len(handlers)

        # Step 3: 读取字节码
        bytecode = self.read_bytecode(size=1024)
        if bytecode:
            result["bytecode_size"] = len(bytecode)
            result["bytecode_sample"] = bytecode[:32].hex()

        # Step 4: VTIL 摘要
        if self.lift_engine and self.lift_engine.available:
            lifted = sum(1 for h in self._handlers.values() if h.lifted_block)
            result["vtil_summary"]["lifted_handlers"] = lifted
            result["vtil_summary"]["simplified_handlers"] = lifted  # 未实际简化

        return result

    def reset(self):
        """重置分析状态"""
        self._entries.clear()
        self._handlers.clear()
        self._execution_trace.clear()
        self._detected_engine = VM_ENGINE_AUTO
