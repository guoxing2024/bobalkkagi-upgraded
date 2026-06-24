"""
VM Signature Extractor — P3: 从真实样本自动提取 VM 入口签名
=============================================================
Bobalkkagi v4.0 — 不靠理论，从已有 Themida dump 的 .themida 段提取实际 VM 入口特征。

工作原理:
  1. 扫描 .themida 段的头 32KB
  2. 找到 PUSH/PUSH/MOV/MOV/MOV/JMP 模式块
  3. 提取助记符序列作为签名
  4. 输出可直接喂给 VMAnalyzer 的 Python 代码

用法:
  python -m bobalkkagi.vm.signature_extractor dump1.dump dump2.dump ...
"""

import sys
import struct
import os
from typing import List, Dict, Tuple
from dataclasses import dataclass

try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64
except ImportError:
    print("Requires: pip install capstone")
    sys.exit(1)


@dataclass
class ExtractedSignature:
    dump_file: str
    themida_offset: int      # .themida 在文件中的偏移
    entry_va: int            # VM 入口 VA
    mnemonics: List[str]     # 入口指令序列
    handler_table_offset: int
    bytecode_ptr_offset: int
    vsp_offset: int

    def to_python(self) -> str:
        """生成可直接放入 VMAnalyzer 的签名代码"""
        return (
            f'    VMEntrySignature(\n'
            f'        engine=VM_ENGINE_THEMIDA,\n'
            f'        name="extracted_from_{os.path.basename(self.dump_file).replace(".","_")}",\n'
            f'        prologue_mnemonics={self.mnemonics},\n'
            f'        handler_table_offset=0x{self.handler_table_offset:x},\n'
            f'        bytecode_ptr_offset=0x{self.bytecode_ptr_offset:x},\n'
            f'        vsp_offset=0x{self.vsp_offset:x},\n'
            f'    ),'
        )


def extract_signature_from_dump(dump_path: str, image_base: int = 0x140000000) -> List[ExtractedSignature]:
    """从单个 dump 提取 VM 签名"""
    with open(dump_path, 'rb') as f:
        data = f.read()

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    results = []

    # 找 .themida 段
    pe_off = struct.unpack_from('<I', data, 0x3C)[0]
    num_sec = struct.unpack_from('<H', data, pe_off + 6)[0]
    oh = pe_off + 24
    magic = struct.unpack_from('<H', data, oh)[0]
    opt_hdr_size = struct.unpack_from('<H', data, pe_off + 20)[0]
    sec_offset = oh + opt_hdr_size

    for i in range(num_sec):
        s = sec_offset + i * 40
        name = data[s:s+8].rstrip(b'\x00').decode('ascii', errors='replace')
        vsize = struct.unpack_from('<I', data, s+8)[0]
        vaddr = struct.unpack_from('<I', data, s+12)[0]
        roff = struct.unpack_from('<I', data, s+20)[0]

        if 'themida' in name.lower() or 'winlice' in name.lower():
            va = image_base + vaddr
            print(f"  .themida @ VA=0x{va:x}, file=0x{roff:x}, size=0x{vsize:x}")

            # 扫描头 32KB
            scan_start = roff
            scan_size = min(vsize, 0x8000)
            if scan_start + scan_size > len(data):
                scan_size = len(data) - scan_start

            # 找 VM 入口模式: 连续 PUSH → MOV → JMP
            chunk = data[scan_start:scan_start + scan_size]
            mnemonics = []
            addresses = []

            for insn in md.disasm(chunk, va):
                m = insn.mnemonic.lower()
                addr = insn.address

                if m in ('push', 'mov', 'lea', 'sub', 'xor', 'pop'):
                    mnemonics.append(m)
                    addresses.append(addr)
                elif m == 'jmp' and len(mnemonics) >= 4:
                    # 找到疑似 VM 入口: 至少 4 条前置指令 + JMP
                    mnemonics.append(m)
                    addresses.append(addr)

                    sig = ExtractedSignature(
                        dump_file=os.path.basename(dump_path),
                        themida_offset=scan_start,
                        entry_va=addresses[0],
                        mnemonics=mnemonics.copy(),
                        handler_table_offset=0x20,    # 默认值，需手工调整
                        bytecode_ptr_offset=0x48,     # 默认值
                        vsp_offset=0x50,              # 默认值
                    )
                    results.append(sig)

                    print(f"    Entry @ 0x{addresses[0]:x}: {' '.join(mnemonics)}")
                    mnemonics = []
                    addresses = []
                    break  # 只取第一个入口
                else:
                    mnemonics = []
                    addresses = []

            break  # 只处理第一个 themida 段

    return results


def main():
    if len(sys.argv) < 2:
        print(f"Usage: python -m bobalkkagi.vm.signature_extractor dump1.dump [dump2.dump ...]")
        print()
        # 默认扫描已知样本
        known_dumps = [
            r"D:\Tools\RE\dumps\temp\伦伦软件.exe.dump",
            r"D:\Tools\RE\bobalkkagi-repo\testfiles\Sample.exe.dump",
        ]
        existing = [d for d in known_dumps if os.path.exists(d)]
        if existing:
            print(f"Auto-scanning {len(existing)} known dumps...")
            sys.argv.extend(existing)
        else:
            return

    all_signatures = []

    for dump_path in sys.argv[1:]:
        if not os.path.exists(dump_path):
            print(f"  ⚠ Not found: {dump_path}")
            continue

        print(f"\n=== {os.path.basename(dump_path)} ===")
        sigs = extract_signature_from_dump(dump_path)
        all_signatures.extend(sigs)

    if all_signatures:
        print(f"\n{'='*60}")
        print(f"  Extracted {len(all_signatures)} VM entry signatures")
        print(f"{'='*60}")
        print()
        print("# Copy this into bobalkkagi/vm/analyzer.py THEMIDA_VM_SIGNATURES:")
        print()
        for sig in all_signatures:
            print(sig.to_python())


if __name__ == '__main__':
    main()
