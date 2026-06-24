"""
Import Scanner — 基于thunk扫描的IAT重建
=========================================
Bobalkkagi升级 — P0: 真实IAT重建

原理（Scylla-style）：
在dump的内存中扫描 call [rip+offset] / jmp [rip+offset] / mov reg, [rip+offset] 模式。
这些指令的 offset 指向IAT槽位，槽位中存储的是API地址（来自DLL导出表）。
通过匹配这些地址到已知DLL的导出表，可以重建完整的导入表。

产出：{dll_name: [func_name, ...]} 字典，可直接用于IATRebuilder合并。
"""

import struct
import logging

logger = logging.getLogger("Bobalkkagi.ImportScanner")

try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64
    HAS_CAPSTONE = True
except ImportError:
    HAS_CAPSTONE = False

# 已知DLL的导出表缓存
_dll_export_cache = {}


def load_dll_exports(dll_path):
    """加载单个DLL的导出表，返回 {address: name, ...}"""
    import pefile
    if dll_path in _dll_export_cache:
        return _dll_export_cache[dll_path]
    
    try:
        pe = pefile.PE(dll_path, fast_load=True)
        pe.parse_data_directories()
        exports = {}
        if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            base = pe.OPTIONAL_HEADER.ImageBase
            for sym in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if sym.name and sym.address:
                    exports[base + sym.address] = sym.name.decode('utf-8')
        _dll_export_cache[dll_path] = exports
        return exports
    except Exception as e:
        logger.warning(f"Failed to load exports from {dll_path}: {e}")
        _dll_export_cache[dll_path] = {}
        return {}


def scan_thunks(dump_data, image_base=0x140000000, verbose=True):
    """
    在dump中扫描thunk指令，重建IAT。
    
    Args:
        dump_data: bytes — 完整内存dump
        image_base: int — 镜像基址
        verbose: bool — 是否打印日志
    
    Returns:
        {dll_name: [func_name, ...]} — 按DLL分组的函数列表
    """
    if not HAS_CAPSTONE:
        if verbose:
            print("  [ImportScanner] capstone not available, skipping")
        return {}
    
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = False
    
    # 收集所有thunk地址
    thunk_addrs = set()  # 所有被引用的IAT槽位地址
    rip_refs = []        # (ref_addr, target_addr) 引用位置和槽位地址
    
    if verbose:
        print(f"  [ImportScanner] 扫描 {len(dump_data)} bytes...")
    
    scan_size = min(len(dump_data), 0x1000000)  # 最多扫描16MB
    # Skip PE header: code starts at offset 0x1000 (first section VA)
    scan_offset = 0x1000  
    if scan_offset >= scan_size:
        if verbose:
            print(f"  [ImportScanner] dump too small to scan")
        return {}
    
    try:
        for insn in md.disasm(dump_data[scan_offset:scan_size], image_base + scan_offset):
            # call [rip+offset]
            if insn.mnemonic == 'call' and insn.op_str.startswith('qword ptr [rip + 0x'):
                try:
                    offset = int(insn.op_str.split('0x')[1].rstrip(']'), 16)
                    target = insn.address + insn.size + offset
                    thunk_addrs.add(target)
                    rip_refs.append((insn.address, target))
                except:
                    pass
            
            # jmp [rip+offset]
            elif insn.mnemonic == 'jmp' and insn.op_str.startswith('qword ptr [rip + 0x'):
                try:
                    offset = int(insn.op_str.split('0x')[1].rstrip(']'), 16)
                    target = insn.address + insn.size + offset
                    thunk_addrs.add(target)
                    rip_refs.append((insn.address, target))
                except:
                    pass
    except Exception as e:
        if verbose:
            print(f"  [ImportScanner] scan error: {e}")
    
    if not thunk_addrs:
        if verbose:
            print(f"  [ImportScanner] 未发现thunk模式")
        return {}
    
    if verbose:
        print(f"  [ImportScanner] 发现 {len(thunk_addrs)} 个thunk槽位, {len(rip_refs)} 处引用")
    
    # 读取thunk槽位中的API地址
    api_addrs = {}
    for addr in thunk_addrs:
        off = addr - image_base
        if 0 <= off + 8 <= len(dump_data):
            api_addr = struct.unpack('<Q', dump_data[off:off+8])[0]
            api_addrs[addr] = api_addr
    
    if verbose:
        valid = sum(1 for v in api_addrs.values() if v != 0)
        print(f"  [ImportScanner] {valid}/{len(api_addrs)} 槽位有有效地址")
    
    return api_addrs


def match_to_exports(api_addrs, dll_exports, verbose=True):
    """
    将API地址匹配到DLL导出表。
    
    Args:
        api_addrs: {thunk_addr: api_addr, ...}
        dll_exports: {dll_name: {func_addr: func_name, ...}, ...}
    
    Returns:
        {dll_name: [func_name, ...], ...}
    """
    # 建立地址→函数名反向索引
    addr_to_name = {}
    for dll, exports in dll_exports.items():
        for addr, name in exports.items():
            addr_to_name[addr] = (dll, name)
    
    result = {}
    unmatched = 0
    
    for thunk_addr, api_addr in api_addrs.items():
        if api_addr == 0:
            continue
        if api_addr in addr_to_name:
            dll, name = addr_to_name[api_addr]
            if dll not in result:
                result[dll] = []
            if name not in result[dll]:
                result[dll].append(name)
        else:
            unmatched += 1
    
    if verbose:
        matched = sum(len(v) for v in result.values())
        print(f"  [ImportScanner] 匹配: {matched} 个函数, {len(result)} 个DLL")
        if unmatched:
            print(f"  [ImportScanner] 未匹配: {unmatched} 个地址（可能需要补充DLL导出表）")
        for dll, funcs in sorted(result.items()):
            func_list = ', '.join(funcs[:5])
            extra = f" ...({len(funcs)})" if len(funcs) > 5 else ""
            print(f"    {dll}: {func_list}{extra}")
    
    return result


def build_dll_export_map(dll_dir, dll_names=None, verbose=True):
    """
    从DLL目录构建 {dll_name: {addr: name}} 导出映射。
    
    Args:
        dll_dir: DLL目录路径
        dll_names: 可选，只加载指定的DLL列表
    """
    import os
    import pefile
    
    result = {}
    loaded = 0
    
    for fn in os.listdir(dll_dir):
        if not fn.lower().endswith('.dll'):
            continue
        if dll_names and fn.lower() not in dll_names:
            continue
        
        path = os.path.join(dll_dir, fn)
        try:
            pe = pefile.PE(path, fast_load=True)
            pe.parse_data_directories()
            exports = {}
            if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
                base = pe.OPTIONAL_HEADER.ImageBase
                for sym in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    if sym.name and sym.address:
                        exports[base + sym.address] = sym.name.decode('utf-8')
            if exports:
                result[fn.lower()] = exports
                loaded += 1
        except:
            pass
    
    if verbose:
        print(f"  [ImportScanner] 加载了 {loaded} 个DLL导出表")
    
    return result


def scan_and_reconstruct_iat(dump_data, image_base, dll_dir, verbose=True):
    """
    完整流程：扫描thunk → 匹配导出 → 返回IAT字典
    
    返回: {dll_name: [func_name, ...], ...}
    """
    # Step 1: 扫描thunk
    api_addrs = scan_thunks(dump_data, image_base, verbose)
    if not api_addrs:
        return {}
    
    # Step 2: 构建导出表映射
    dll_exports = build_dll_export_map(dll_dir, verbose=verbose)
    
    # Step 3: 匹配
    result = match_to_exports(api_addrs, dll_exports, verbose)
    
    return result
