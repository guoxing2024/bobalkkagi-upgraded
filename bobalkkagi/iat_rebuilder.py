"""
IAT Reconstructor for Themida memory dumps
===========================================
Bobalkkagi升级 — 阶段三：从原始PE导入表重建dump的IAT

Themida在脱壳后，dump中的IAT地址是Unicorn模拟地址(0x7FFxxxxx)，
这些地址在真实进程中无效。需要：
1. 从原始PE拷贝导入描述符和thunk表到dump
2. 保留原始thunk（Windows加载器会在加载时解析）
3. 修复数据目录和section属性
"""

import struct
import pefile
import logging

logger = logging.getLogger("Bobalkkagi.IATRebuilder")

SIZE_OF_IMPORT_DESCRIPTOR = 20  # 5 * 4 bytes

class IATRebuilder:
    """Rebuild import table from original PE into memory dump"""
    
    def __init__(self, dump_data: bytearray, orig_pe_path: str, runtime_calls: dict = None):
        self.dump_data = dump_data
        self.orig_pe = pefile.PE(orig_pe_path, fast_load=True)
        self.runtime_calls = runtime_calls or {}  # {dll_name: [func_name, ...]}
        self._parse_dump_headers()
        self._parse_orig_imports()
    
    def _parse_dump_headers(self):
        """Parse dump PE headers"""
        if self.dump_data[:2] != b'MZ':
            raise ValueError("Dump has no MZ header")
        
        self.pe_offset = struct.unpack('<I', self.dump_data[0x3c:0x40])[0]
        fh = self.pe_offset + 4
        self.num_sections = struct.unpack('<H', self.dump_data[fh+2:fh+4])[0]
        
        oh = self.pe_offset + 24
        self.magic = struct.unpack('<H', self.dump_data[oh:oh+2])[0]
        self.is_pe32plus = (self.magic == 0x20b)
        self.opt_hdr_size = struct.unpack('<H', self.dump_data[fh+16:fh+18])[0]
        
        if self.is_pe32plus:
            self.image_base = struct.unpack('<Q', self.dump_data[oh+24:oh+32])[0]
        else:
            self.image_base = struct.unpack('<I', self.dump_data[oh+24:oh+28])[0]
        
        self.section_offset = oh + self.opt_hdr_size
        
        # Parse sections
        self.sections = []
        for i in range(self.num_sections):
            s = self.section_offset + i * 40
            name = self.dump_data[s:s+8].rstrip(b'\x00').decode('ascii', errors='replace')
            vsize = struct.unpack('<I', self.dump_data[s+8:s+12])[0]
            vaddr = struct.unpack('<I', self.dump_data[s+12:s+16])[0]
            rsize = struct.unpack('<I', self.dump_data[s+16:s+20])[0]
            roff = struct.unpack('<I', self.dump_data[s+20:s+24])[0]
            flags = struct.unpack('<I', self.dump_data[s+36:s+40])[0]
            self.sections.append({
                'name': name, 'vsize': vsize, 'vaddr': vaddr,
                'rsize': rsize, 'roff': roff, 'flags': flags, 'idx': i
            })
        
        # Data directories
        # PE32: NumberOfRvaAndSizes at oh+92, data dirs start at oh+96
        # PE32+: NumberOfRvaAndSizes at oh+108, data dirs start at oh+112
        if self.is_pe32plus:
            num_data_dir = struct.unpack('<I', self.dump_data[oh+108:oh+112])[0]
            data_dir_offset = oh + 112
        else:
            num_data_dir = struct.unpack('<I', self.dump_data[oh+92:oh+96])[0]
            data_dir_offset = oh + 96
        self.data_dirs = []
        for i in range(16):
            dd = data_dir_offset + i * 8
            va = struct.unpack('<I', self.dump_data[dd:dd+4])[0]
            sz = struct.unpack('<I', self.dump_data[dd+4:dd+8])[0]
            self.data_dirs.append({'va': va, 'size': sz, 'offset': dd})
    
    def _parse_orig_imports(self):
        """Parse import table from original PE and merge with runtime calls"""
        self.orig_pe.parse_data_directories()
        self.orig_imports = []
        
        # Step 1: Collect imports from original PE
        orig_by_dll = {}
        if hasattr(self.orig_pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in self.orig_pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode('utf-8') if entry.dll else "unknown"
                functions = []
                for imp in entry.imports:
                    if imp.name:
                        functions.append(imp.name.decode('utf-8'))
                    else:
                        functions.append(f"ord({imp.ordinal})")
                orig_by_dll[dll_name.lower()] = {
                    'dll': dll_name,
                    'functions': functions,
                    'first_thunk': entry.struct.FirstThunk,
                    'name_rva': entry.struct.Name,
                }
        
        # Step 2: Merge with runtime calls (if available)
        # Runtime calls caught by api_recorder during emulation
        # give us a much more complete picture of what's actually used
        merged_dlls = set(list(orig_by_dll.keys()) + [d.lower() for d in self.runtime_calls.keys()])
        
        for dll_lower in sorted(merged_dlls):
            orig = orig_by_dll.get(dll_lower, {})
            runtime_funcs = self.runtime_calls.get(dll_lower, [])
            
            # Original functions + runtime functions merged
            orig_funcs = set(orig.get('functions', []))
            runtime_funcs_set = set(runtime_funcs) - {'__load__'}  # filter out load markers
            
            all_funcs = list(orig_funcs | runtime_funcs_set)
            all_funcs.sort()
            
            # Determine DLL name (use original form if available)
            dll_name = orig.get('dll', dll_lower)
            
            # Build import data structures
            import_entries = []
            for func_name in all_funcs:
                class _MockImport:
                    def __init__(self, name_str):
                        self.name = name_str.encode('utf-8') if name_str else None
                        self.ordinal = 0
                        self.address = 0
                import_entries.append(_MockImport(func_name))
            
            self.orig_imports.append({
                'dll': dll_name,
                'original_rva': orig.get('first_thunk', 0) if orig else 0,
                'first_thunk': orig.get('first_thunk', 0) if orig else 0,
                'name_rva': orig.get('name_rva', 0) if orig else 0,
                'functions': all_funcs,
                'imports': import_entries,
            })
            
            # Print merge info
            if runtime_funcs_set:
                added = runtime_funcs_set - orig_funcs
                if added:
                    pass  # Called from pipeline.py which prints the summary
    
    def find_section_by_va(self, rva):
        """Find section containing a given RVA"""
        for sec in self.sections:
            if sec['vaddr'] <= rva < sec['vaddr'] + sec['vsize']:
                return sec
        return None
    
    def rva_to_offset(self, rva):
        """Convert RVA to file offset using section table"""
        sec = self.find_section_by_va(rva)
        if sec:
            return sec['roff'] + (rva - sec['vaddr'])
        return rva  # Fallback for flat map
    
    def analyze(self):
        """Analyze import state"""
        print("=== IAT/Import 分析 ===")
        print(f"\n原始PE导入表 ({len(self.orig_imports)}个DLL):")
        for imp in self.orig_imports:
            funcs = imp['functions'][:5]
            extra = f"... 共{len(imp['functions'])}个" if len(imp['functions']) > 5 else ""
            print(f"  {imp['dll']}: OriginThunk=0x{imp['original_rva']:x} "
                  f"FirstThunk=0x{imp['first_thunk']:x} Name=0x{imp['name_rva']:x}")
            print(f"    函数: {', '.join(funcs)} {extra}")
        
        # Check what's at the original import directories in the dump
        print("\n=== Dump中的原始导入表数据 ===")
        for imp in self.orig_imports:
            # OriginalFirstThunk
            oft_off = self.rva_to_offset(imp['original_rva'])
            ft_off = self.rva_to_offset(imp['first_thunk'])
            
            if oft_off < len(self.dump_data):
                oft_val = struct.unpack('<Q', self.dump_data[oft_off:oft_off+8])[0]
                print(f"  {imp['dll']}:")
                print(f"    OriginalFirstThunk @ 0x{imp['original_rva']:x}: value=0x{oft_val:016x}")
            else:
                print(f"  {imp['dll']}: OriginalFirstThunk 0x{imp['original_rva']:x}: 超出文件!")
            
            if ft_off < len(self.dump_data):
                ft_val = struct.unpack('<Q', self.dump_data[ft_off:ft_off+8])[0]
                print(f"    FirstThunk @ 0x{imp['first_thunk']:x}: value=0x{ft_val:016x}")
            else:
                print(f"    FirstThunk 0x{imp['first_thunk']:x}: 超出文件!")
        
        # Check available space in .idata section
        idata_sec = None
        for sec in self.sections:
            if sec['name'] == '.idata':
                idata_sec = sec
                break
        if not idata_sec:
            # Find section with import data by checking data_dir
            imp_va = self.data_dirs[1]['va']
            idata_sec = self.find_section_by_va(imp_va)
        
        if idata_sec:
            print(f"\n.idata section: VA=0x{idata_sec['vaddr']:x}, "
                  f"VSize=0x{idata_sec['vsize']:x}, "
                  f"file offset=0x{idata_sec['roff']:x}")
            # Calculate used vs free space
            idata_used = self.data_dirs[1]['va'] - idata_sec['vaddr'] + self.data_dirs[1]['size'] \
                if self.data_dirs[1]['va'] else 0
            print(f"  Import directory VA=0x{self.data_dirs[1]['va']:x}, Size=0x{self.data_dirs[1]['size']:x}")
            print(f"  Used: 0x{idata_used:x}, Available: 0x{idata_sec['vsize']:x}")
    
    def validate_imports(self) -> tuple:
        """
        Validate original PE import table for anomalies.
        Returns: (warnings_list, is_trusted_bool)
          - is_trusted=True: 导入表可信，可以直接使用
          - is_trusted=False: 导入表异常，建议用运行时扫描补充
        """
        warnings = []
        has_known_dlls = False
        all_trusted = True
        
        # Known Windows system DLLs for reference
        known_dlls = {
            'kernel32.dll', 'kernelbase.dll', 'ntdll.dll', 'user32.dll',
            'gdi32.dll', 'win32u.dll', 'advapi32.dll', 'ole32.dll',
            'oleaut32.dll', 'comctl32.dll', 'comdlg32.dll', 'shell32.dll',
            'shlwapi.dll', 'ws2_32.dll', 'wininet.dll', 'crypt32.dll',
            'bcrypt.dll', 'iphlpapi.dll', 'winmm.dll', 'd3d11.dll',
            'dwmapi.dll', 'imm32.dll', 'rpcrt4.dll', 'sechost.dll',
            'ucrtbase.dll', 'msvcrt.dll', 'combase.dll', 'shcore.dll',
            'd2d1.dll', 'dxgi.dll', 'dwrite.dll', 'wtsapi32.dll',
            'setupapi.dll', 'cfgmgr32.dll', 'devobj.dll', 'wintrust.dll',
        }
        
        if not self.orig_imports:
            warnings.append("❌ 原始PE导入表为空! 无法重建IAT")
            return warnings, False
        
        for imp in self.orig_imports:
            dll = imp['dll'].lower()
            func_count = len(imp['functions'])
            
            if dll in known_dlls:
                has_known_dlls = True
            
            if not imp['dll'] or len(imp['dll'].strip()) == 0:
                warnings.append(f"  ⚠ 空DLL名称 (索引 #{self.orig_imports.index(imp)})")
                continue
            
            if dll not in known_dlls and not dll.startswith('api-ms-win-') and not dll.startswith('ext-ms-win-'):
                warnings.append(f"  ⚠ 非标准DLL: {imp['dll']} (可能为Themida伪造)")
            
            func_expected = {
                'kernel32.dll': 20, 'kernelbase.dll': 15, 'ntdll.dll': 15,
                'user32.dll': 10, 'gdi32.dll': 10, 'ole32.dll': 5,
                'advapi32.dll': 5, 'shell32.dll': 10, 'crypt32.dll': 5,
                'wininet.dll': 5, 'shlwapi.dll': 5,
            }
            if dll in func_expected and func_count < func_expected[dll]:
                warnings.append(f"  ⚠ {imp['dll']}: 仅{func_count}个导入, 预期>={func_expected[dll]} (Themida隐藏了大部分)")
                all_trusted = False
        
        known_suspicious = {'api-ms-win-core-libraryloader-l1-2-1.dll', 'ext-ms-win-ntuser-window-l1-1-0.dll'}
        for imp in self.orig_imports:
            if imp['dll'].lower() in known_suspicious:
                warnings.append(f"  ⚠ {imp['dll']}: API集DLL可能不是完整导入表")
        
        # Summary
        is_trusted = has_known_dlls and all_trusted
        if not is_trusted and warnings:
            warnings.insert(0, "  📋 导入表可信度: 低 — 当前IAT基于原始PE导入表，Themida可能隐藏了大部分导入")
            warnings.insert(1, "    建议: 使用运行时IAT扫描工具(如Scylla)获取完整导入表")
        elif is_trusted:
            warnings.insert(0, "  📋 导入表可信度: 高 — 直接使用原始PE导入表")
        
        return warnings, is_trusted
    
    def rebuild(self, verbose=True):
        """
        Rebuild IAT by:
        1. Copying import descriptors from original PE
        2. Building thunk tables pointing to function name entries
        3. Fixing data directories
        """
        if verbose:
            self.analyze()
        
        # Validate import table and warn
        warnings, is_trusted = self.validate_imports()
        if warnings:
            print("\n=== IAT 有效性检查 ===")
            for w in warnings:
                print(w)
            if any("导入表为空" in w for w in warnings):
                print("  ❌ 导入表为空，放弃IAT重建")
                return False
            if not is_trusted:
                print("  ⚠ 导入表可信度低 — 重建后的IAT可能不完整")
                print("  ⚠ 建议: 配合运行时IAT扫描工具(如Scylla)获取完整导入表")
        
        # We need the .idata section to have enough space
        # Approach: write import data into .idata section's free space
        # or allocate space in a new section
        
        idata_sec = None
        for sec in self.sections:
            if sec['name'] == '.idata':
                idata_sec = sec
                break
        
        if not idata_sec:
            print("⚠  没有.idata section，尝试使用第一个非代码section")
            for sec in self.sections:
                if sec['flags'] & 0x80000000 == 0 and sec['vsize'] >= 0x1000:
                    idata_sec = sec
                    break
        
        if not idata_sec:
            print("❌ 找不到可用的section存放IAT数据")
            return False
        
        # Calculate required space
        num_dlls = len(self.orig_imports)
        # Size = num_dlls * 20 (import descriptors) + 20 (terminator) + 
        #        DLL names + function names + thunk table
        TOTAL_DESCS = (num_dlls + 1) * SIZE_OF_IMPORT_DESCRIPTOR
        
        # Estimate name size
        names_size = 0
        total_thunks = 0
        for imp in self.orig_imports:
            names_size += len(imp['dll']) + 1  # DLL name + null
            for func_name in imp['functions']:
                names_size += len(func_name) + 1  # func name + null
                total_thunks += 1
            total_thunks += 1  # Terminator thunk
        
        # Each thunk = 8 bytes (64-bit)
        thunks_size = total_thunks * 8
        
        # Hint/Name table entries: each = 2 bytes hint + name + null
        hint_name_size = 0
        for imp in self.orig_imports:
            for func_name in imp['functions']:
                hint_name_size += 2 + len(func_name) + 1  # hint (2 bytes) + name + null
        
        total_size = TOTAL_DESCS + names_size + hint_name_size
        
        print(f"\n=== IAT 重建 ===")
        print(f"  DLL数量: {num_dlls}")
        print(f"  总thunk: {total_thunks}")
        print(f"  需要空间: 0x{total_size:x} ({total_size} bytes)")
        print(f"  可用空间: 0x{idata_sec['vsize']:x} ({idata_sec['vsize']} bytes)")
        
        if total_size > idata_sec['vsize']:
            print(f"❌ .idata空间不足: 需要0x{total_size:x}, 可用0x{idata_sec['vsize']:x}")
            print(f"   建议: 增大.idata section或在PE中新增一个节存放IAT")
            return False
        
        # Layout within .idata section:
        # [Import Descriptors] [DLL Names] [Hint/Name Table] [Thunks (INT)] [Thunks (IAT)]
        
        # Start at the beginning of .idata section
        base_rva = idata_sec['vaddr']
        file_base = idata_sec['roff']
        
        desc_rva = base_rva
        desc_file_off = file_base
        
        # DLL names after descriptors
        names_rva = desc_rva + TOTAL_DESCS
        names_file_off = file_base + TOTAL_DESCS
        
        # Hint/name table after DLL names
        hintname_rva = names_rva + names_size
        hintname_file_off = names_file_off + names_size
        
        # INT (OriginalFirstThunk table) after hint/name entries
        int_rva = hintname_rva + hint_name_size
        int_file_off = hintname_file_off + hint_name_size
        
        # IAT (FirstThunk table) - can be same as INT or separate
        iat_rva = int_rva + thunks_size
        iat_file_off = int_file_off + thunks_size
        
        # Write data
        curr_name_off = names_file_off
        curr_hintname_off = hintname_file_off
        curr_int_off = int_file_off
        curr_iat_off = iat_file_off
        
        changes = []
        
        for imp_idx, imp in enumerate(self.orig_imports):
            desc_off = desc_file_off + imp_idx * SIZE_OF_IMPORT_DESCRIPTOR
            
            # Write DLL name
            dll_name_bytes = imp['dll'].encode('ascii') + b'\x00'
            self.dump_data[curr_name_off:curr_name_off+len(dll_name_bytes)] = dll_name_bytes
            name_rva = base_rva + (curr_name_off - file_base)
            
            # Write INT (thunk table)
            int_start_rva = base_rva + (curr_int_off - file_base)
            iat_start_rva = base_rva + (curr_iat_off - file_base)
            
            for func_idx, func_name in enumerate(imp['functions']):
                # Write hint/name entry
                hint_name = struct.pack('<H', 0) + func_name.encode('ascii') + b'\x00'
                self.dump_data[curr_hintname_off:curr_hintname_off+len(hint_name)] = hint_name
                hint_name_rva = base_rva + (curr_hintname_off - file_base)
                
                # Write INT (OriginalFirstThunk) - points to hint/name entry
                struct.pack_into('<Q', self.dump_data, curr_int_off, hint_name_rva)
                
                # Write IAT (FirstThunk) - same content, loader will fix
                struct.pack_into('<Q', self.dump_data, curr_iat_off, hint_name_rva)
                
                curr_hintname_off += len(hint_name)
                curr_int_off += 8
                curr_iat_off += 8
            
            # Write INT/IAT terminator (null entry)
            struct.pack_into('<Q', self.dump_data, curr_int_off, 0)
            struct.pack_into('<Q', self.dump_data, curr_iat_off, 0)
            curr_int_off += 8
            curr_iat_off += 8
            
            # Write import descriptor
            desc = struct.pack(
                '<IIIII',
                int_start_rva,       # OriginalFirstThunk
                0,                   # TimeDateStamp
                0,                   # ForwarderChain
                name_rva,            # Name
                iat_start_rva        # FirstThunk
            )
            self.dump_data[desc_off:desc_off+len(desc)] = desc
            changes.append(f"  {imp['dll']}: desc=0x{desc_rva:x}, INT=0x{int_start_rva:x}, "
                          f"IAT=0x{iat_start_rva:x}, name=0x{name_rva:x}")
            
            curr_name_off += len(dll_name_bytes)
        
        # Write terminating import descriptor (all zeros)
        term_desc = b'\x00' * SIZE_OF_IMPORT_DESCRIPTOR
        term_off = desc_file_off + num_dlls * SIZE_OF_IMPORT_DESCRIPTOR
        self.dump_data[term_off:term_off+len(term_desc)] = term_desc
        
        # Update data directory
        # Entry 1 = Import Directory
        imp_dir_off = self.data_dirs[1]['offset']
        struct.pack_into('<I', self.dump_data, imp_dir_off, desc_rva)  # VA
        struct.pack_into('<I', self.dump_data, imp_dir_off+4, TOTAL_DESCS)  # Size
        
        # Entry 12 = IAT Directory
        iat_dir_off = self.data_dirs[12]['offset']
        struct.pack_into('<I', self.dump_data, iat_dir_off, int_rva)  # VA = INT start
        struct.pack_into('<I', self.dump_data, iat_dir_off+4, thunks_size)  # Size
        
        print(f"\n✅ IAT重建完成:")
        print(f"  Import dir: VA=0x{desc_rva:x}, Size=0x{TOTAL_DESCS:x}")
        print(f"  IAT dir: VA=0x{int_rva:x}, Size=0x{thunks_size:x}")
        
        # Make .idata writable (for loader to patch IAT)
        for sec in self.sections:
            if sec['name'] == '.idata':
                old_flags = sec['flags']
                new_flags = old_flags | 0x80000000  # Add MEM_WRITE
                struct.pack_into('<I', self.dump_data, self.section_offset + sec['idx'] * 40 + 36, new_flags)
                if verbose:
                    print(f"  .idata flags: 0x{old_flags:08x} → 0x{new_flags:08x}")
                break
        
        if verbose:
            for c in changes:
                print(c)
        
        return True


def rebuild_iat(dump_path, orig_pe_path, output_path=None):
    """Convenience function to rebuild IAT"""
    with open(dump_path, 'rb') as f:
        data = bytearray(f.read())
    
    rebuilder = IATRebuilder(data, orig_pe_path)
    success = rebuilder.rebuild()
    
    if output_path and success:
        with open(output_path, 'wb') as f:
            f.write(data)
        print(f"保存: {output_path}")
    
    return success


if __name__ == '__main__':
    import sys
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <dump.exe> <original.exe> [output.exe]")
        sys.exit(1)
    
    output = sys.argv[3] if len(sys.argv) > 3 else sys.argv[1]
    rebuild_iat(sys.argv[1], sys.argv[2], output)
