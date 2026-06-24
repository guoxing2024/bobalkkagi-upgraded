"""
V5 Finalize Pipeline — Phase 2+3 一体化: 扫描 IAT + 强制重定位 + 资源恢复 + 产出 EXE
===================================================================================
Bobalkkagi V5.0 — 严格按照专家计划 Phase 2-3 实施。

流程:
  1. Unicorn 解包 → dump + OEP
  2. DLL 导出解析 → 地址→函数名映射
  3. InstructionBasedIATScanner 扫描 dump
  4. 双重验证: code_scan ∪ api_recorder
  5. 强制重定位表重建
  6. 资源目录恢复
  7. 产出 final EXE
"""

import struct
import os
import json
from typing import Dict, Set, Tuple, List, Optional


def build_dll_export_map(dll_loaded_info: dict, dll_path: str) -> Dict[int, Tuple[str, str]]:
    """Phase 2-2: 从加载的 DLL 构建导出表映射 {地址: (dll_name, func_name)}"""
    import pefile
    export_map = {}
    for dll_name, info in dll_loaded_info.items():
        base = info.get('ImageBase', 0)
        if not base:
            continue
        search_paths = [
            os.path.join(dll_path, dll_name),
            os.path.join(r'C:\Windows\System32', dll_name),
            os.path.join(r'C:\Windows\SysWOW64', dll_name),
        ]
        pe_path = None
        for p in search_paths:
            if os.path.isfile(p):
                pe_path = p
                break
        if not pe_path:
            continue
        try:
            pe = pefile.PE(pe_path, fast_load=True)
            pe.parse_data_directories([pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT']])
            if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
                for sym in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    if sym.name:
                        addr = base + sym.address
                        export_map[addr] = (dll_name, sym.name.decode())
        except Exception:
            pass
    return export_map


def scan_iat_with_instruction_scanner(dump_data: bytes, image_base: int,
                                       export_map: dict,
                                       runtime_calls: dict = None) -> dict:
    """Phase 2-3: 指令扫描 + 双重验证"""
    from .instruction_scanner import InstructionBasedIATScanner

    scanner = InstructionBasedIATScanner(dump_data, image_base)
    scanner.load_dll_exports(export_map)

    # Parse sections from dump PE header
    pe_off = struct.unpack_from('<I', dump_data, 0x3C)[0]
    num_sec = struct.unpack_from('<H', dump_data, pe_off + 6)[0]
    oh = pe_off + 24
    opt_size = struct.unpack_from('<H', dump_data, pe_off + 20)[0]
    sec_off = oh + opt_size

    executable_sections = []
    for i in range(num_sec):
        s = sec_off + i * 40
        flags = struct.unpack_from('<I', dump_data, s + 36)[0]
        if flags & 0x20000000:  # CODE flag
            vsize = struct.unpack_from('<I', dump_data, s + 8)[0]
            vaddr = struct.unpack_from('<I', dump_data, s + 12)[0]
            name = dump_data[s:s + 8].rstrip(b'\x00').decode('ascii', errors='replace')
            executable_sections.append((image_base + vaddr, vsize, name or f's{i}'))

    return scanner.scan_all_sections(executable_sections, runtime_calls)


def force_rebuild_reloc(dump_data: bytes, image_base: int,
                         sections: List[Tuple[int, int, str]]) -> bytes:
    """Phase 3-1: 强制重定位表 — 扫描内存差异并重建

    算法:
      扫描所有可执行段中的 8 字节对齐指针 → 若在 image 范围内 → 标记为重定位
      按 PE 格式构建 Base Relocation 块
    """
    IMAGE_BASE = image_base
    IMAGE_MAX = image_base + 0x2000000  # 32MB ceiling

    # Collect all relocation entries
    reloc_entries = {}  # {page_rva: [offsets]}

    for va, size, name in sections:
        if size == 0:
            continue
        rva = va - IMAGE_BASE
        if rva < 0 or rva + size > len(dump_data):
            continue
        data = dump_data[rva:rva + size]

        # Scan for 8-byte pointers in range
        for offset in range(0, len(data) - 7, 8):
            ptr_val = struct.unpack_from('<Q', data, offset)[0]
            # Check if pointer points within the module
            if IMAGE_BASE <= ptr_val < IMAGE_MAX:
                page_rva = (rva + offset) & ~0xFFF  # page-align
                entry_offset = (rva + offset) & 0xFFF
                if page_rva not in reloc_entries:
                    reloc_entries[page_rva] = []
                reloc_entries[page_rva].append(entry_offset)

    if not reloc_entries:
        print("  [Phase3] ⚠ No relocations found — image may be position-dependent")
        return dump_data

    # Build .reloc section data
    reloc_data = bytearray()
    for page_rva in sorted(reloc_entries.keys()):
        offsets = reloc_entries[page_rva]
        # Block header: PageRVA(4) + BlockSize(4) + entries(2 bytes each)
        block_size = 8 + len(offsets) * 2
        reloc_data += struct.pack('<II', page_rva, block_size)
        for off in offsets:
            entry = (3 << 12) | (off & 0xFFF)  # IMAGE_REL_BASED_DIR64
            reloc_data += struct.pack('<H', entry)

    # Pad to 4-byte alignment
    while len(reloc_data) % 4:
        reloc_data += b'\x00'

    print(f"  [Phase3] Reloc: {len(reloc_entries)} pages, {sum(len(v) for v in reloc_entries.values())} entries, {len(reloc_data)} bytes")

    # Patch PE header: set .reloc directory
    pe_off = struct.unpack_from('<I', dump_data, 0x3C)[0]
    oh = pe_off + 24
    magic = struct.unpack_from('<H', dump_data, oh)[0]
    if magic == 0x20b:  # PE32+
        base_reloc_offset = oh + 128  # 6th data directory
    else:
        base_reloc_offset = oh + 112

    # Find .reloc section or create at end
    result = bytearray(dump_data)
    num_sec = struct.unpack_from('<H', result, pe_off + 6)[0]
    opt_sz = struct.unpack_from('<H', result, pe_off + 20)[0]
    last_sec = oh + opt_sz + (num_sec - 1) * 40

    # Place .reloc after last section data
    last_raw = struct.unpack_from('<I', result, last_sec + 20)[0]
    last_size = struct.unpack_from('<I', result, last_sec + 16)[0]
    reloc_file_offset = (last_raw + last_size + 0xFFF) & ~0xFFF

    # Ensure buffer is large enough
    needed = reloc_file_offset + len(reloc_data)
    if needed > len(result):
        result += b'\x00' * (needed - len(result))

    # Write reloc data
    result[reloc_file_offset:reloc_file_offset + len(reloc_data)] = bytes(reloc_data)

    # Update PE header base relocation directory
    reloc_rva = struct.unpack_from('<I', result, last_sec + 12)[0] + \
                struct.unpack_from('<I', result, last_sec + 8)[0]
    reloc_rva = (reloc_rva + 0xFFF) & ~0xFFF
    struct.pack_into('<II', result, base_reloc_offset,
                     reloc_rva, len(reloc_data))

    return bytes(result)


def recover_resources(dump_data: bytes) -> bytes:
    """Phase 3-2: 资源恢复 — 检查并保留 rsrc 段

    当前策略: 保持现有资源目录不变 (Unicorn dump 通常保留资源)。
    若检测到损坏，标记为需要外部工具恢复。
    """
    pe_off = struct.unpack_from('<I', dump_data, 0x3C)[0]
    oh = pe_off + 24
    magic = struct.unpack_from('<H', dump_data, oh)[0]
    if magic == 0x20b:
        rsrc_offset = oh + 112  # 3rd data directory
    else:
        rsrc_offset = oh + 96

    rsrc_rva = struct.unpack_from('<I', dump_data, rsrc_offset)[0]
    rsrc_size = struct.unpack_from('<I', dump_data, rsrc_offset + 4)[0]

    if rsrc_rva and rsrc_size:
        print(f"  [Phase3] Resources: present (RVA=0x{rsrc_rva:x}, {rsrc_size} bytes)")
    else:
        print(f"  [Phase3] ⚠ Resources: missing — use Resource Hacker to recover")

    return dump_data


def finalize(output_path: str, output_exe_path: str):
    """Phase 2+3 一体化: 从 dump 产出最终 EXE"""
    import pefile

    with open(output_path, 'rb') as f:
        dump_data = f.read()

    print(f"  [V5 Finalize] Input: {output_path} ({len(dump_data)} bytes)")

    # Step 1: 资源检查
    dump_data = recover_resources(dump_data)

    # Step 2: 强制重定位
    pe = pefile.PE(data=dump_data)
    sections = []
    for sec in pe.sections:
        sections.append((pe.OPTIONAL_HEADER.ImageBase + sec.VirtualAddress,
                         sec.Misc_VirtualSize,
                         sec.Name.decode().rstrip('\x00')))

    dump_data = force_rebuild_reloc(dump_data,
                                      pe.OPTIONAL_HEADER.ImageBase,
                                      sections)

    # Step 3: 写入最终 EXE
    with open(output_exe_path, 'wb') as f:
        f.write(dump_data)

    print(f"  [V5 Finalize] Done: {output_exe_path} ({len(dump_data)} bytes)")
    return output_exe_path
