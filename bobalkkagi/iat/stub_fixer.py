"""
Stub Fixer — P3: VM stub → 直接调用修复
=========================================
Bobalkkagi v4.0 — 基于 VTIL 分析的 stub 修复器。

将 VM 注入的导入 stub 替换为直接 thunk 调用。
支持节区扩展和跳转注入（当原位置空间不足时）。

修复策略:
  1. strict: 仅修复确定性高的 stub (置信度 >= 0.8)
  2. normal: 修复所有识别到的 stub (默认)
  3. aggressive: 尝试修复 + 节区扩展 + 跳转注入

参考:
  - VMPDump: fix_iat + section_expansion + jump_injection
"""

import struct
from typing import List, Dict, Optional, Tuple

from ..vtil.ir import StubInfo


# x64 direct call: FF 15 [rip+disp]  (6 bytes)
X64_CALL_THUNK = b'\xff\x15'
# x64 indirect jmp: FF 25 [rip+disp]  (6 bytes)
X64_JMP_THUNK = b'\xff\x25'
# x64 NOP sled
X64_NOP = b'\x90'


class StubFixer:
    """
    Stub 修复器。

    将 VM stub 替换为直接 thunk 调用。
    """

    def __init__(self, strategy: str = "normal"):
        self.strategy = strategy
        self._fixed_count = 0
        self._failed_stubs: List[StubInfo] = []

    def fix_stubs(self, ctx, stubs: List[StubInfo],
                  memory_image: bytearray = None) -> Tuple[int, List[StubInfo]]:
        """
        修复导入 stub。

        Args:
            ctx: UnpackContext
            stubs: 识别到的 stub 列表
            memory_image: 可写的内存镜像 (默认从 ctx 获取)

        Returns:
            (fixed_count, failed_stubs)
        """
        self._fixed_count = 0
        self._failed_stubs = []

        data = memory_image or ctx.memory_image
        if not data or not isinstance(data, bytearray):
            if isinstance(data, bytes):
                data = bytearray(data)
            else:
                return 0, stubs

        image_base = ctx.image_base or 0x140000000

        for stub in stubs:
            if self.strategy == "strict" and stub.confidence < 0.8:
                self._failed_stubs.append(stub)
                continue

            offset = stub.address - image_base
            if offset < 0 or offset > len(data):
                self._failed_stubs.append(stub)
                continue

            # 检查是否有足够空间
            if stub.size < 6:
                # 空间不足，尝试节区扩展
                if self.strategy == "aggressive":
                    new_addr = self._allocate_stub_space(ctx, 6)
                    if new_addr == 0:
                        self._failed_stubs.append(stub)
                        continue
                    # 写入 jmp → 新地址
                    self._write_thunk_jump(data, offset, new_addr)
                    offset = new_addr - image_base

            # 写入 thunk
            self._write_direct_thunk(data, offset, stub)
            self._fixed_count += 1

        print(f"  [StubFixer] Fixed {self._fixed_count}/{len(stubs)} stubs "
              f"(strategy={self.strategy}, failed={len(self._failed_stubs)})")

        return self._fixed_count, self._failed_stubs

    def _write_direct_thunk(self, data: bytearray, offset: int, stub: StubInfo):
        """
        写入直接 thunk 调用。

        格式: FF 15 [32-bit displacement to IAT entry]
        这 6 个字节调用 IAT 中的 thunk，由 Windows loader 自动解析。
        """
        # 简化: 写入 NOP sled + CALL thunk
        # 实际生产环境需计算真实 IAT 地址
        size = min(stub.size, 6)
        for i in range(size):
            data[offset + i] = 0x90  # NOP

        if size >= 6:
            # 写入 FF 15 xx xx xx xx (call [rip+disp])
            data[offset:offset + 2] = X64_CALL_THUNK
            # disp = 0 占位 (后续由 IATRebuilder 填充)
            struct.pack_into('<I', data, offset + 2, 0)

    def _write_thunk_jump(self, data: bytearray, from_offset: int, to_addr: int):
        """写入跳转指令 (jmp to_addr)"""
        # E9 [disp32]
        data[from_offset] = 0xE9
        disp = to_addr - (from_offset + 5 + ctx.image_base if hasattr(self.ctx, 'image_base') else 0)
        struct.pack_into('<i', data, from_offset + 1, disp)

    def _allocate_stub_space(self, ctx, size: int) -> int:
        """在 PE 中分配新的 stub 空间 (节区扩展)"""
        # 策略: 使用 .reloc 段末尾的空白空间
        memory = ctx.memory_image
        image_base = ctx.image_base or 0x140000000

        if not memory:
            return 0

        # 查找 .reloc 段
        section_info = getattr(ctx, 'section_info', [])
        for sec in section_info:
            if len(sec) >= 4 and sec[0] == '.reloc':
                reloc_va = sec[1]
                reloc_size = sec[2]
                # 在末尾留出空间
                new_va = reloc_va + reloc_size - 0x100
                return new_va

        return 0

    def get_report(self) -> dict:
        return {
            "fixed": self._fixed_count,
            "failed": len(self._failed_stubs),
            "strategy": self.strategy,
        }
