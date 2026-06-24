"""
Runtime IAT Scanner — P3: VM 注入导入 stub 识别
=================================================
Bobalkkagi v4.0 — 借鉴 VMPDump 的 stub 识别策略。

扫描所有可执行段，识别 Themida/VMProtect 注入的导入 stub。
利用 VTILLiftEngine 提升 stub 并分析其 API 调用模式。

参考:
  - VMPDump: scan_executable_sections + identify_stubs
  - VMPDump VTIL x64 lifter stub analysis
"""

import struct
from typing import List, Optional, Dict, Tuple, Set

from ..vtil.ir import StubInfo
from ..vtil.lift_engine import VTILLiftEngine

try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64
    HAS_CAPSTONE = True
except ImportError:
    HAS_CAPSTONE = False


# ============================================================
# stub 模式
# ============================================================

# Themida 3.x API stub 特征:
#   1. jmp [rip+disp]  →  跳转表 (最常见的 Themida stub)
#   2. mov rax, addr; jmp rax  →  间接跳转
#   3. call [rip+disp]  →  直接调用
#   4. push ret_value; mov rax, 0x...; jmp [handler]  →  VM stub 封装

THEMIDA_STUB_PATTERNS = [
    # jmp [rip+X]
    {"bytes": b'\xff\x25', "mask": b'\xff\xff', "name": "jmp_rip_disp"},
    # call [rip+X]
    {"bytes": b'\xff\x15', "mask": b'\xff\xff', "name": "call_rip_disp"},
    # push imm; ret  (common in some Themida versions)
    {"bytes": b'h\x00\x00\x00\x00\xc3', "mask": b'\xff\x00\x00\x00\x00\xff',
     "name": "push_imm_ret"},
]

# VMProtect 3.x stub 特征:
#   push reg; push reg; ...; mov reg, imm; jmp handler  →  VM 导出调用
#   call [disp]; jmp [addr]  →  双跳转模式

VMPROTECT_STUB_PATTERNS = [
    # call [rel32]; jmp [rel32]  (VMP 双跳转)
    {"bytes": b'\xe8', "mask": b'\xff', "name": "call_rel32", "follow_jmp": True},
    # push ... ; jmp  (VMP 封装)
    {"bytes": b'PH\xb8', "mask": b'\xff\xff', "name": "push_mov_jmp", "check_len": 16},
]


class RuntimeIATScanner:
    """
    运行时 IAT Stub 扫描器。

    扫描 dump 中的可执行段，识别 VM 注入的导入 stub。
    """

    def __init__(self, lift_engine: Optional[VTILLiftEngine] = None):
        self.lift_engine = lift_engine or VTILLiftEngine()
        self._capstone = None
        if HAS_CAPSTONE:
            self._capstone = Cs(CS_ARCH_X86, CS_MODE_64)

    def scan_stubs(self, ctx,
                   target: str = "auto") -> List[StubInfo]:
        """
        扫描所有可执行段，识别导入 stub。

        Args:
            ctx: UnpackContext
            target: "auto" | "themida" | "vmprotect"

        Returns:
            StubInfo 列表
        """
        memory = ctx.memory_image
        if not memory:
            return []

        # 选择 stub 模式
        if target == "themida":
            patterns = THEMIDA_STUB_PATTERNS
        elif target == "vmprotect":
            patterns = VMPROTECT_STUB_PATTERNS
        else:
            patterns = THEMIDA_STUB_PATTERNS + VMPROTECT_STUB_PATTERNS

        stubs = []
        image_base = ctx.image_base or 0x140000000

        # 扫描可执行段 (.text, .themida, .boot 等)
        sections_to_scan = self._get_executable_sections(ctx)

        for sec_name, sec_va, sec_size in sections_to_scan:
            offset = sec_va - image_base
            if offset < 0 or offset + sec_size > len(memory):
                continue

            sec_data = bytes(memory[offset:offset + sec_size])

            for pattern in patterns:
                found = self._scan_pattern(sec_data, sec_va, pattern)
                stubs.extend(found)

        # 去重 (同地址)
        seen = set()
        unique_stubs = []
        for stub in stubs:
            if stub.address not in seen:
                seen.add(stub.address)
                unique_stubs.append(stub)

        print(f"  [IATScanner] Found {len(unique_stubs)} stubs in {len(sections_to_scan)} sections")

        return unique_stubs

    def _get_executable_sections(self, ctx) -> List[Tuple[str, int, int]]:
        """获取所有可执行段"""
        sections = []
        image_base = ctx.image_base or 0x140000000

        # 从 section_info 获取
        section_info = getattr(ctx, 'section_info', [])
        for sec in section_info:
            if len(sec) >= 4:
                name = sec[0]
                va = sec[1]
                size = sec[2]
                flags = sec[3] if len(sec) > 3 else 0
                if flags & 0x20000000:  # IMAGE_SCN_MEM_EXECUTE
                    sections.append((name, va, size))

        # 添加 themida / boot 段
        for attr in ['themida_section', 'boot_section']:
            sec = getattr(ctx, attr, None)
            if sec and len(sec) >= 3:
                sections.append((attr, sec[1], sec[2]))

        return sections

    def _scan_pattern(self, data: bytes, base_va: int,
                      pattern: dict) -> List[StubInfo]:
        """在数据中搜索 stub 模式"""
        stubs = []
        pat_bytes = pattern["bytes"]
        pat_mask = pattern["mask"]
        pat_name = pattern["name"]
        check_len = pattern.get("check_len", 8)
        follow_jmp = pattern.get("follow_jmp", False)

        i = 0
        while i < len(data) - len(pat_bytes):
            match = True
            for j in range(len(pat_bytes)):
                if (data[i + j] & pat_mask[j]) != (pat_bytes[j] & pat_mask[j]):
                    match = False
                    break

            if match:
                addr = base_va + i

                # 尝试提升 stub 到 VTIL 分析
                confidence = 0.5  # 基础置信度
                dll, func = "", ""

                if self.lift_engine and self.lift_engine.available:
                    try:
                        stub_data = data[i:i + check_len]
                        routine = self.lift_engine.lift_stub(stub_data, addr, check_len)
                        summary = self.lift_engine.get_summary(routine)
                        if summary["api_patterns"] > 0:
                            confidence = 0.8
                    except:
                        pass

                stub = StubInfo(
                    address=addr,
                    size=check_len,
                    call_type="direct" if "call" in pat_name else "indirect",
                    confidence=confidence,
                )
                stubs.append(stub)
                i += check_len  # 跳过已扫描
            else:
                i += 1

        return stubs

    def analyze_stub(self, ctx, stub: StubInfo) -> Optional[dict]:
        """
        利用 VTIL 深度分析单个 stub。

        Returns:
            { "dll": str, "func": str, "confidence": float, "vtil_summary": dict }
            或 None (无法确定)
        """
        memory = ctx.memory_image
        if not memory or not self.lift_engine.available:
            return None

        offset = stub.address - ctx.image_base
        if offset < 0 or offset + stub.size > len(memory):
            return None

        stub_data = bytes(memory[offset:offset + stub.size])
        routine = self.lift_engine.lift_stub(stub_data, stub.address, stub.size)
        summary = self.lift_engine.get_summary(routine)

        # 从 VTIL 分析中提取信息
        result = {
            "dll": "",
            "func": "",
            "confidence": stub.confidence,
            "vtil_summary": summary,
        }

        # 检查 API_CALL 指令
        for block in routine.blocks.values():
            for insn in block:
                if insn.opcode.value == "api_call":
                    result["confidence"] = max(result["confidence"], 0.7)

        return result
