"""
Scylla-style IAT Scanner — P5: 全内存 thunk 扫描 + DLL 导出表解析
==================================================================
Bobalkkagi v5.0 — 不依赖原始PE导入表，直接从 dump 中扫描所有 FF 15/FF 25
模式，通过 DLL 导出表解析 API 名称。

原理 (同 Scylla):
  1. 扫描 dump 所有可执行段
  2. 找 FF 15 (call [rip+disp]) 和 FF 25 (jmp [rip+disp]) 模式
  3. 计算目标地址 = 当前地址 + 6 + disp
  4. 目标地址中的值 → DLL 导出表反查 → API 名称
  5. 构建完整 IAT

与现有 api_recorder 的区别:
  - api_recorder: 动态 (只记录实际调用的 API)
  - scylla_scan: 静态 (扫描所有潜在调用点, 包括未执行到的代码路径)
"""

import struct
import os
from typing import Dict, List, Set, Tuple, Optional
from dataclasses import dataclass, field


@dataclass
class IATEntry:
    addr: int          # thunk slot address (VA)
    api_addr: int      # resolved API address (VA)
    dll: str           # DLL name
    func: str          # function name
    is_ordinal: bool = False


@dataclass
class DLLExportInfo:
    """DLL 导出表信息"""
    name: str
    base: int
    size: int
    exports: Dict[int, str] = field(default_factory=dict)  # addr → name
    ordinals: Dict[int, int] = field(default_factory=dict)  # ordinal → addr


class ScyllaIATScanner:
    """
    Scylla-style 全内存 IAT 扫描器。

    用法:
        scanner = ScyllaIATScanner(dll_directory="win10_v1903")
        entries = scanner.scan(dump_data, image_base=0x140000000,
                               max_scan=0x200000)
    """

    # x64 thunk patterns
    CALL_RIP = b'\xff\x15'    # call [rip+disp]
    JMP_RIP  = b'\xff\x25'    # jmp  [rip+disp]

    def __init__(self, dll_directory: str = "win10_v1903"):
        self._dll_dir = dll_directory
        self._dll_cache: Dict[str, DLLExportInfo] = {}
        self._load_dll_exports()

    def _load_dll_exports(self):
        """预加载 DLL 导出表"""
        if not os.path.isdir(self._dll_dir):
            return

        for fname in os.listdir(self._dll_dir):
            if fname.lower().endswith('.dll'):
                path = os.path.join(self._dll_dir, fname)
                try:
                    info = self._parse_dll_exports(path)
                    if info:
                        self._dll_cache[info.name.lower()] = info
                except:
                    pass

    def _parse_dll_exports(self, path: str) -> Optional[DLLExportInfo]:
        """解析单个 DLL 的导出表"""
        try:
            with open(path, 'rb') as f:
                data = f.read()

            pe_off = struct.unpack_from('<I', data, 0x3C)[0]
            oh = pe_off + 24
            magic = struct.unpack_from('<H', data, oh)[0]

            if magic == 0x20b:  # PE32+
                export_rva = struct.unpack_from('<I', data, oh + 112 + 0)[0]
                export_size = struct.unpack_from('<I', data, oh + 112 + 4)[0]
            else:
                export_rva = struct.unpack_from('<I', data, oh + 96 + 0)[0]
                export_size = struct.unpack_from('<I', data, oh + 96 + 4)[0]

            if export_rva == 0 or export_size == 0:
                return None

            name = os.path.basename(path)

            # IMAGE_EXPORT_DIRECTORY
            exp = data[export_rva:export_rva + min(export_size, 0x4000)]
            num_funcs = struct.unpack_from('<I', exp, 20)[0]
            num_names = struct.unpack_from('<I', exp, 24)[0]
            addr_rva = struct.unpack_from('<I', exp, 28)[0]
            name_rva = struct.unpack_from('<I', exp, 32)[0]
            ord_rva  = struct.unpack_from('<I', exp, 36)[0]

            info = DLLExportInfo(name=name, base=0, size=len(data))
            addr_base = max(export_rva, addr_rva)

            for i in range(min(num_funcs, 5000)):
                func_rva_off = addr_rva + i * 4
                if func_rva_off + 4 > len(data):
                    break
                func_rva = struct.unpack_from('<I', data, func_rva_off)[0]
                if func_rva == 0:
                    continue
                info.ordinals[i] = func_rva

            # Resolve names
            for i in range(min(num_names, 5000)):
                ord_off = ord_rva + i * 2
                name_off = name_rva + i * 4
                if ord_off + 2 > len(data) or name_off + 4 > len(data):
                    break
                ordinal = struct.unpack_from('<H', data, ord_off)[0]
                name_ptr_rva = struct.unpack_from('<I', data, name_off)[0]
                if name_ptr_rva >= len(data):
                    continue
                null_pos = data.find(b'\x00', name_ptr_rva)
                if null_pos > name_ptr_rva:
                    func_name = data[name_ptr_rva:null_pos].decode('ascii', errors='replace')
                    func_rva = info.ordinals.get(ordinal, 0)
                    if func_rva:
                        info.exports[func_rva] = func_name

            return info
        except:
            return None

    def resolve_address(self, addr: int) -> Optional[Tuple[str, str]]:
        """解析 API 地址 → (dll_name, func_name)"""
        for name_lower, info in self._dll_cache.items():
            if info.base <= addr < info.base + info.size:
                # 查找导出表
                func_name = info.exports.get(addr)
                if func_name:
                    return (info.name, func_name)
                # 尝试序号
                return (info.name, f"#{addr - info.base:x}")
        return None

    def scan(self, dump_data: bytes, image_base: int = 0x140000000,
             max_scan: int = 0x200000) -> List[IATEntry]:
        """
        扫描 dump 中的 thunk 模式。

        Returns: IATEntry 列表
        """
        entries = []
        seen = set()

        data = dump_data[:min(len(dump_data), max_scan)]
        i = 0

        while i < len(data) - 6:
            word = data[i:i+2]
            if word == self.CALL_RIP or word == self.JMP_RIP:
                # FF 15 xx xx xx xx → call [rip + disp]
                # FF 25 xx xx xx xx → jmp  [rip + disp]
                disp = struct.unpack_from('<i', data, i + 2)[0]
                target = image_base + i + 6 + disp

                if target not in seen and 0 < target - image_base < len(dump_data):
                    try:
                        api_addr = struct.unpack_from('<Q', dump_data, target - image_base)[0]
                    except:
                        i += 6
                        continue

                    if api_addr and api_addr > 0x1000:
                        dll_func = self.resolve_address(api_addr)
                        if dll_func:
                            entries.append(IATEntry(
                                addr=target, api_addr=api_addr,
                                dll=dll_func[0], func=dll_func[1]
                            ))
                            seen.add(target)

                i += 6
            else:
                i += 1

        return entries


def scan_iat_from_dump(dump_path: str, dll_dir: str = "win10_v1903",
                       image_base: int = 0x140000000) -> List[IATEntry]:
    """便捷函数: 从 dump 文件扫描 IAT"""
    with open(dump_path, 'rb') as f:
        data = f.read()

    scanner = ScyllaIATScanner(dll_directory=dll_dir)
    return scanner.scan(data, image_base)
