"""
Runtime Scylla IAT Scanner — P5: 使用 Unicorn 运行时 DLL 基址的全内存扫描
===========================================================================
与静态扫描不同，此版本使用 Unicorn 加载 DLL 时的运行时基址来解析 thunk 地址。
"""

import os, struct
from typing import Dict, List, Set, Tuple, Optional


def scan_iat_runtime(dump_data: bytes, dump_path: str = None,
                     dll_dir: str = "win10_v1903",
                     dll_bases: Dict[str, int] = None,
                     image_base: int = 0x140000000) -> Dict[str, List[str]]:
    """
    使用运行时 DLL 基址扫描 IAT。

    Args:
        dump_data: dump 原始字节
        dll_dir: DLL 文件目录 (用于解析导出表)
        dll_bases: {dll_name_lower: runtime_base} — Unicorn 中的 DLL 基址
        image_base: 主程序基址

    Returns: {dll_name: [func_name, ...]}
    """
    if dll_bases is None:
        dll_bases = {}

    # 解析 DLL 导出表 (存储为 RVA → name)
    dll_exports: Dict[str, Dict[int, str]] = {}  # dll_lower → {rva → name}
    dll_paths: Dict[str, str] = {}

    if os.path.isdir(dll_dir):
        for fname in os.listdir(dll_dir):
            if fname.lower().endswith('.dll'):
                path = os.path.join(dll_dir, fname)
                name_lower = fname.lower()
                dll_paths[name_lower] = path
                exports = _parse_dll_exports_rva(path)
                if exports:
                    dll_exports[name_lower] = exports

    # 扫描 thunk 模式
    iat_slots: Dict[int, int] = {}  # target_addr → api_addr
    i = 0
    while i < len(dump_data) - 6:
        if dump_data[i:i+2] in (b'\xff\x15', b'\xff\x25'):
            disp = struct.unpack_from('<i', dump_data, i + 2)[0]
            target = image_base + i + 6 + disp
            if 0 < target - image_base < len(dump_data) - 8:
                try:
                    api_addr = struct.unpack_from('<Q', dump_data, target - image_base)[0]
                except:
                    i += 6; continue
                if api_addr > 0x1000:
                    iat_slots[target] = api_addr
            i += 6
        else:
            i += 1

    # 解析每个 thunk 地址 → DLL + 函数名
    result: Dict[str, List[str]] = {}
    for target, api_addr in iat_slots.items():
        for dll_name, dll_base in dll_bases.items():
            if dll_base <= api_addr < dll_base + 0x2000000:
                rva = api_addr - dll_base
                exports = dll_exports.get(dll_name)
                if exports and rva in exports:
                    func = exports[rva]
                    result.setdefault(dll_name, []).append(func)
                break

    return result


def _parse_dll_exports_rva(path: str) -> Optional[Dict[int, str]]:
    """解析 DLL 导出表 → {rva: func_name}"""
    try:
        with open(path, 'rb') as f:
            data = f.read()
        pe_off = struct.unpack_from('<I', data, 0x3C)[0]
        oh = pe_off + 24
        magic = struct.unpack_from('<H', data, oh)[0]

        if magic == 0x20b:
            export_rva = struct.unpack_from('<I', data, oh+112+0)[0]
            export_size = struct.unpack_from('<I', data, oh+112+4)[0]
        else:
            export_rva = struct.unpack_from('<I', data, oh+96+0)[0]
            export_size = struct.unpack_from('<I', data, oh+96+4)[0]

        if export_rva == 0 or export_size == 0:
            return None

        exp = data[export_rva:export_rva+min(export_size, 0x4000)]
        num_funcs = struct.unpack_from('<I', exp, 20)[0]
        num_names = struct.unpack_from('<I', exp, 24)[0]
        addr_rva = struct.unpack_from('<I', exp, 28)[0]
        name_rva = struct.unpack_from('<I', exp, 32)[0]
        ord_rva  = struct.unpack_from('<I', exp, 36)[0]

        # ordinals → RVA
        ord_to_rva: Dict[int, int] = {}
        for i in range(min(num_funcs, 5000)):
            off = addr_rva + i * 4
            if off + 4 > len(data): break
            rva = struct.unpack_from('<I', data, off)[0]
            if rva: ord_to_rva[i] = rva

        # names → RVA
        exports: Dict[int, str] = {}
        for i in range(min(num_names, 5000)):
            noff = name_rva + i * 4
            ooff = ord_rva + i * 2
            if noff + 4 > len(data) or ooff + 2 > len(data): break
            name_ptr = struct.unpack_from('<I', data, noff)[0]
            ordinal = struct.unpack_from('<H', data, ooff)[0]
            func_rva = ord_to_rva.get(ordinal)
            if func_rva and name_ptr < len(data):
                null_pos = data.find(b'\x00', name_ptr)
                if null_pos > name_ptr:
                    name = data[name_ptr:null_pos].decode('ascii', errors='replace')
                    exports[func_rva] = name

        return exports
    except:
        return None
