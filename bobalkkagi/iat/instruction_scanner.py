"""
Instruction-Based IAT Scanner — V5: Capstone代码扫描 + api_recorder合并
=========================================================================
Bobalkkagi V5.0 Phase 2 — 扫描 OEP 附近的 .text 段，识别 call/jmp [rip+disp]
并解析为 DLL 导入函数。

与 P3 RuntimeIATScanner 的区别:
  - P3 版本依赖运行时 api_recorder (9 个调用)
  - V5 版本扫描 DUMP 中的静态代码 (更多函数)
  - 双重验证: code_scan ∪ api_recorder 取并集
  - 处理 proxy stub: 识别 FF 25 → FF 15 中间跳转层
"""

import struct
from typing import Dict, List, Optional, Set, Tuple

try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64
    HAS_CAPSTONE = True
except ImportError:
    HAS_CAPSTONE = False


class InstructionBasedIATScanner:
    """V5: 指令级 IAT 扫描器"""

    def __init__(self, dump_data: bytes, image_base: int = 0x140000000):
        self.dump = dump_data
        self.image_base = image_base
        self._cs = Cs(CS_ARCH_X86, CS_MODE_64) if HAS_CAPSTONE else None
        # Known DLL exports (runtime-resolved)
        self._dll_exports: Dict[int, Tuple[str, str]] = {}
        # Scan results
        self._found_imports: Dict[str, Set[str]] = {}  # dll_name -> {func_names}
        self._proxy_stubs: List[Tuple[int, int]] = []  # [(stub_addr, target_addr)]

    def load_dll_exports(self, dll_exports: Dict[int, Tuple[str, str]]):
        """加载 DLL 导出表: {address: (dll_name, func_name)}"""
        self._dll_exports = dll_exports

    def scan_code_section(self, section_va: int, section_size: int) -> int:
        """扫描指定的代码段，返回发现的 IAT 条目数

        Args:
            section_va: section 的虚拟地址 (RVA)
            section_size: section 大小
        """
        if not self._cs:
            print("  [IATScanner] Capstone not available")
            return 0

        rva = section_va - self.image_base
        if rva < 0 or rva + section_size > len(self.dump):
            return 0

        code = self.dump[rva:rva + min(section_size, 0x200000)]  # max 2MB
        count = 0

        for insn in self._cs.disasm(code, section_va):
            if not self._is_call_jmp_mem(insn):
                continue

            # Extract target IAT slot address from [rip+disp]
            slot_addr = self._get_mem_operand(insn)
            if not slot_addr:
                continue

            # Read the resolved API address from the dump
            api_addr = self._read_ptr(slot_addr)
            if not api_addr:
                continue

            # Lookup in DLL exports
            export = self._dll_exports.get(api_addr)
            if export:
                dll, func = export
                if dll not in self._found_imports:
                    self._found_imports[dll] = set()
                self._found_imports[dll].add(func)
                count += 1

            # Check for proxy stubs (FF 25 that points to another FF 25)
            elif self._is_proxy_stub(api_addr):
                target = self._read_ptr(api_addr + 6)  # skip FF 25 00 00 00 00
                if target:
                    self._proxy_stubs.append((slot_addr, target))
                    # Recheck the real target
                    real = self._dll_exports.get(target)
                    if real:
                        dll, func = real
                        if dll not in self._found_imports:
                            self._found_imports[dll] = set()
                        self._found_imports[dll].add(func)
                        count += 1

        return count

    def merge_with_runtime(self, runtime_calls: Dict[str, Set[str]]) -> Dict[str, Set[str]]:
        """合并代码扫描结果与 api_recorder 运行时记录 (双重验证)"""
        merged = {}
        for dll in set(list(self._found_imports.keys()) +
                       list(runtime_calls.keys())):
            merged[dll] = (self._found_imports.get(dll, set()) |
                          runtime_calls.get(dll, set()))
        return merged

    def scan_all_sections(self, sections: List[Tuple[int, int, str]],
                          runtime_calls: Dict[str, Set[str]] = None) -> Dict[str, Set[str]]:
        """扫描所有代码段，返回合并后的 IAT"""
        total = 0
        for va, size, name in sections:
            if size > 0:
                n = self.scan_code_section(va, size)
                total += n
                if n:
                    print(f"  [IATScanner] {name} @ 0x{va:x}: {n} calls")

        if runtime_calls:
            return self.merge_with_runtime(runtime_calls)

        print(f"  [IATScanner] Total: {total} calls across all sections")
        return dict(self._found_imports)

    # === Internal helpers ===

    @staticmethod
    def _is_call_jmp_mem(insn) -> bool:
        """检查是否是 call/jmp [mem] 指令"""
        if not hasattr(insn, 'mnemonic'):
            return False
        m = insn.mnemonic.lower()
        if m not in ('call', 'jmp'):
            return False
        # Check for memory operand (e.g., [rip+disp])
        op_str = insn.op_str
        return '[' in op_str

    def _get_mem_operand(self, insn) -> Optional[int]:
        """从 [rip+disp] 计算实际内存地址"""
        # Capstone provides disp value for RIP-relative addressing
        if hasattr(insn, 'operands') and len(insn.operands) > 0:
            op = insn.operands[0]
            if op.type == 2:  # X86_OP_MEM
                if op.mem.base == 0 and op.mem.index == 0:  # RIP-relative
                    return insn.address + insn.size + op.mem.disp
        return None

    def _read_ptr(self, addr: int) -> Optional[int]:
        """从 dump 中读取 8 字节指针"""
        rva = addr - self.image_base
        if 0 <= rva < len(self.dump) - 7:
            return struct.unpack_from('<Q', self.dump, rva)[0]
        return None

    def _is_proxy_stub(self, addr: int) -> bool:
        """检查地址是否是 proxy stub (FF 25 模式)"""
        rva = addr - self.image_base
        if 0 <= rva < len(self.dump) - 6:
            data = self.dump[rva:rva + 6]
            return data[:2] == b'\xff\x25'  # jmp m64
        return False


def scan_iat_from_dump(dump_data: bytes, image_base: int,
                       dll_exports: Dict[int, Tuple[str, str]],
                       sections: List[Tuple[int, int, str]],
                       runtime_calls: Dict[str, Set[str]] = None) -> Dict[str, Set[str]]:
    """便捷函数: 从 dump 扫描 IAT"""
    scanner = InstructionBasedIATScanner(dump_data, image_base)
    scanner.load_dll_exports(dll_exports)
    return scanner.scan_all_sections(sections, runtime_calls)
