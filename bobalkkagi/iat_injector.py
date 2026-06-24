"""
V6 IAT Injector — 重建 PE 导入表
==================================
从 .iat.txt manifest 读取导入列表，直接写入 PE 导入目录。
"""

import struct
import os
from typing import Dict, List, Set


def parse_iat_manifest(manifest_path: str) -> Dict[str, List[str]]:
    """解析 IAT manifest 文件"""
    imports = {}
    if not os.path.isfile(manifest_path):
        return imports
    with open(manifest_path, 'r') as f:
        for line in f:
            line = line.strip()
            if not line or '!' not in line:
                continue
            dll, func = line.split('!', 1)
            if dll not in imports:
                imports[dll] = []
            imports[dll].append(func)
    return imports


def inject_iat(exe_path: str, manifest_path: str, output_path: str = None):
    """将 manifest 中的导入表注入 EXE

    方法:
      1. 在 PE 末尾追加 .idata 段
      2. 构建 IMAGE_IMPORT_DESCRIPTOR 链
      3. 构建 INT/IAT thunk 表
      4. 更新 PE header
    """
    imports = parse_iat_manifest(manifest_path)
    if not imports:
        print(f"  [IAT Inject] No imports found in manifest")
        return exe_path

    with open(exe_path, 'rb') as f:
        data = bytearray(f.read())

    # PE header parsing
    pe_off = struct.unpack_from('<I', data, 0x3C)[0]
    num_sec = struct.unpack_from('<H', data, pe_off + 6)[0]
    oh = pe_off + 24
    magic = struct.unpack_from('<H', data, oh)[0]
    opt_hdr_size = struct.unpack_from('<H', data, pe_off + 20)[0]

    # Build import data
    # Layout: [dll_names] [thunk_tables] [import_descriptors] [null_descriptor]
    dll_list = sorted(imports.keys())
    total_imports = sum(len(v) for v in imports.values())

    # Calculate section placement first (need idata_va for RVA computation)
    sec_offset = oh + opt_hdr_size
    last_sec = sec_offset + (num_sec - 1) * 40
    last_raw = struct.unpack_from('<I', data, last_sec + 20)[0]
    last_raw_size = struct.unpack_from('<I', data, last_sec + 16)[0]
    last_va = struct.unpack_from('<I', data, last_sec + 12)[0]
    last_vs = struct.unpack_from('<I', data, last_sec + 8)[0]

    idata_raw = (last_raw + last_raw_size + 0xFFF) & ~0xFFF
    idata_va  = (last_va + last_vs + 0xFFF) & ~0xFFF

    # Now build section data with correct RVAs
    raw_section = bytearray()

    # 1. DLL names (null-terminated)
    dll_name_offsets = {}
    for dll in dll_list:
        dll_name_offsets[dll] = len(raw_section)
        raw_section += dll.encode('ascii') + b'\x00'

    # Align to 8
    while len(raw_section) % 8:
        raw_section += b'\x00'

    # 2. Hint/Name entries for each import
    hint_name_offsets = {}
    for dll in dll_list:
        for func in imports[dll]:
            key = f"{dll}!{func}"
            hint_name_offsets[key] = len(raw_section)
            raw_section += struct.pack('<H', 0)  # Hint = 0 (ordinal lookup)
            raw_section += func.encode('ascii') + b'\x00'
            while len(raw_section) % 2:
                raw_section += b'\x00'

    # Align to 8
    while len(raw_section) % 8:
        raw_section += b'\x00'

    # 3. INT/IAT thunk tables (OriginalFirstThunk and FirstThunk)
    thunk_offsets = {}
    for dll in dll_list:
        thunk_offsets[dll] = len(raw_section)
        for func in imports[dll]:
            key = f"{dll}!{func}"
            hint_rva = idata_va + hint_name_offsets[key]
            raw_section += struct.pack('<Q', (1 << 63) | hint_rva)

    # Add null terminator for each DLL's thunk table
    for dll in dll_list:
        raw_section += struct.pack('<Q', 0)

    # 4. IMAGE_IMPORT_DESCRIPTOR array
    desc_start_raw = len(raw_section)
    for dll in dll_list:
        int_rva  = idata_va + thunk_offsets[dll]
        name_rva = idata_va + dll_name_offsets[dll]
        raw_section += struct.pack('<IIIII', int_rva, 0, 0, name_rva, int_rva)

    # Null terminator descriptor (20 bytes of zeros)
    null_desc_raw = len(raw_section)
    raw_section += b'\x00' * 20

    # Pad to 16-byte alignment for section
    while len(raw_section) % 16:
        raw_section += b'\x00'

    # Extend file if needed
    idata_size = len(raw_section)

    # Extend file if needed
    needed = idata_raw + idata_size
    while len(data) < needed:
        data += b'\x00'

    # Write section data
    data[idata_raw:idata_raw + idata_size] = bytes(raw_section)

    # Write new section header
    sec_name = b'.idata\x00\x00'  # 8 bytes
    data[last_sec + 40:last_sec + 40 + 8] = sec_name
    struct.pack_into('<I', data, last_sec + 40 + 8, idata_size)
    struct.pack_into('<I', data, last_sec + 40 + 12, idata_va)
    struct.pack_into('<I', data, last_sec + 40 + 16, idata_size)
    struct.pack_into('<I', data, last_sec + 40 + 20, idata_raw)
    struct.pack_into('<I', data, last_sec + 40 + 36, 0xC0000040)  # INITIALIZED_DATA | READ

    # Update number of sections
    struct.pack_into('<H', data, pe_off + 6, num_sec + 1)

    # Update SizeOfImage
    new_image_size = idata_va + ((idata_size + 0xFFF) & ~0xFFF)
    struct.pack_into('<I', data, oh + 56, new_image_size)

    # Update import directory in PE header
    if magic == 0x20b:  # PE32+
        import_dir_off = oh + 112
    else:
        import_dir_off = oh + 104

    desc_rva = idata_va + desc_start_raw
    desc_size = (null_desc_raw + 20) - desc_start_raw
    struct.pack_into('<I', data, import_dir_off, desc_rva)
    struct.pack_into('<I', data, import_dir_off + 4, desc_size)

    # Write output
    out = output_path or exe_path.replace('.exe', '_injected.exe')
    with open(out, 'wb') as f:
        f.write(data)

    print(f"  [IAT Inject] {len(dll_list)} DLLs, {total_imports} imports → {out}")
    return out


def inject_from_manifest(exe_path: str, output_path: str = None):
    """从 .iat.txt manifest 注入 IAT"""
    manifest = exe_path + '.iat.txt'
    if not os.path.isfile(manifest):
        manifest = exe_path.replace('.exe', '.iat.txt')
    if not os.path.isfile(manifest):
        print(f"  [IAT Inject] No .iat.txt found")
        return exe_path
    return inject_iat(exe_path, manifest, output_path)
