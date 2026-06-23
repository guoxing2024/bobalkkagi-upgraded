"""
PE Rebuilder for Themida memory dumps
======================================
Bobalkkagi升级 — 阶段三：将Unicorn模拟器的原始内存dump重建为可加载PE文件

工作原理：
Themida脱壳后的dump是一个从ImageBase开始的连续内存快照。
原始PE的section headers中，.themida的RSize=0（磁盘上加密，运行时解密展开）。
但在Unicorn dump中，.themida已被解密并展开在内存中。
重建器需要：
1. 修复所有section的RawSize = VirtualSize
2. 将RawOffset修正为VA（因为文件是平铺内存映射）
3. 正确设置OEP
4. 重建IAT（如果有导入表数据）
"""

import struct
import os
import logging

logger = logging.getLogger("Bobalkkagi.PERebuilder")

class PERebuilder:
    """Rebuild PE section headers from raw memory dump to create loadable PE"""
    
    def __init__(self, data: bytearray):
        self.data = data
        self.pe_offset = 0
        self._parse_headers()
    
    def _parse_headers(self):
        """Parse PE headers"""
        if self.data[:2] != b'MZ':
            raise ValueError("Not a valid PE file (no MZ header)")
        
        self.pe_offset = struct.unpack('<I', self.data[0x3c:0x40])[0]
        
        if self.data[self.pe_offset:self.pe_offset+4] != b'PE\x00\x00':
            raise ValueError("Not a valid PE file (no PE signature)")
        
        # File header
        fh = self.pe_offset + 4
        self.machine = struct.unpack('<H', self.data[fh:fh+2])[0]
        self.num_sections = struct.unpack('<H', self.data[fh+2:fh+4])[0]
        self.size_opt_header = struct.unpack('<H', self.data[fh+16:fh+18])[0]
        
        # Optional header
        oh = self.pe_offset + 24
        self.magic = struct.unpack('<H', self.data[oh:oh+2])[0]
        self.is_pe32plus = (self.magic == 0x20b)
        
        if self.is_pe32plus:
            self.image_base = struct.unpack('<Q', self.data[oh+24:oh+32])[0]
            self.size_of_image = struct.unpack('<I', self.data[oh+56:oh+60])[0]
            self.section_alignment = struct.unpack('<I', self.data[oh+32:oh+36])[0]
            self.file_alignment = struct.unpack('<I', self.data[oh+36:oh+40])[0]
            self.size_of_headers = struct.unpack('<I', self.data[oh+60:oh+64])[0]
            self.entry_rva = struct.unpack('<I', self.data[oh+16:oh+20])[0]
        else:
            self.image_base = struct.unpack('<I', self.data[oh+24:oh+28])[0]
            self.size_of_image = struct.unpack('<I', self.data[oh+56:oh+60])[0]
            self.section_alignment = struct.unpack('<I', self.data[oh+32:oh+36])[0]
            self.file_alignment = struct.unpack('<I', self.data[oh+36:oh+40])[0]
            self.size_of_headers = struct.unpack('<I', self.data[oh+60:oh+64])[0]
            self.entry_rva = struct.unpack('<I', self.data[oh+16:oh+20])[0]
        
        # Section headers
        self.section_offset = oh + self.size_opt_header
        self.sections = []
        
        for i in range(self.num_sections):
            s = self.section_offset + i * 40
            name_raw = self.data[s:s+8]
            name = name_raw.rstrip(b'\x00').decode('ascii', errors='replace')
            vsize = struct.unpack('<I', self.data[s+8:s+12])[0]
            vaddr = struct.unpack('<I', self.data[s+12:s+16])[0]
            rsize = struct.unpack('<I', self.data[s+16:s+20])[0]
            roff = struct.unpack('<I', self.data[s+20:s+24])[0]
            flags = struct.unpack('<I', self.data[s+36:s+40])[0]
            
            self.sections.append({
                'name': name, 'name_raw': name_raw,
                'vsize': vsize, 'vaddr': vaddr,
                'rsize': rsize, 'roff': roff,
                'flags': flags, 'header_off': s,
                'index': i
            })
    
    def analyze_dump_layout(self):
        """Analyze the current dump file layout"""
        file_size = len(self.data)
        print(f"=== PE 重建分析 ===")
        print(f"Image base: 0x{self.image_base:016x}")
        print(f"Size of image: 0x{self.size_of_image:x} ({self.size_of_image} bytes)")
        print(f"File size: 0x{file_size:x} ({file_size} bytes)")
        print(f"PE type: {'PE32+' if self.is_pe32plus else 'PE32'}")
        print(f"Section alignment: 0x{self.section_alignment:x}")
        print(f"File alignment: 0x{self.file_alignment:x}")
        print(f"Current entry RVA: 0x{self.entry_rva:x}")
        print(f"\n{'Section':<16} {'VA':<12} {'VSize':<10} {'ROff':<10} {'RSize':<10} {'Flags':<10} {'Status':<12}")
        print('-' * 80)
        
        for sec in self.sections:
            status = "OK"
            flags_str = f"0x{sec['flags']:08x}"
            
            if sec['rsize'] == 0 and sec['vsize'] > 0:
                status = "RSize=0! 需修复"
            elif sec['rsize'] < sec['vsize']:
                status = f"RSize<VS 差={sec['vsize']-sec['rsize']:x}"
            
            # Check if raw data would fit in file
            if sec['rsize'] > 0 and sec['roff'] + sec['rsize'] > file_size:
                status = "数据超文件!"
            
            print(f"{sec['name']:<16} 0x{sec['vaddr']:08x} 0x{sec['vsize']:x} "
                  f"0x{sec['roff']:x} 0x{sec['rsize']:x} {flags_str} {status}")
    
    def rebuild_section_headers(self):
        """
        Fix section headers for a flat memory dump.
        
        Strategy: For a raw memory dump (flat memory image), each section's
        data is at file offset = its VA (because the dump starts at ImageBase).
        
        Set ROff = VA, RSize = VSize for all sections that need fixing.
        """
        file_size = len(self.data)
        fixed_count = 0
        
        for sec in self.sections:
            vaddr = sec['vaddr']
            vsize = sec['vsize']
            
            # Align vsize to section alignment
            aligned_vsize = ((vsize + self.section_alignment - 1) // 
                           self.section_alignment) * self.section_alignment
            
            # New raw offset = VA (since dump is flat memory)
            new_roff = vaddr
            new_rsize = aligned_vsize
            
            # Check data exists in file at the right place
            data_end = new_roff + aligned_vsize
            if data_end > file_size:
                # Data extends beyond file - this may be OK for sections that
                # don't actually have data (e.g., .bss or TLS template)
                actual_data = file_size - new_roff
                if actual_data > 0:
                    new_rsize = ((actual_data + self.file_alignment - 1) // 
                                self.file_alignment) * self.file_alignment
                    print(f"  ⚠ {sec['name']}: 超出文件边界 {data_end:x}>{file_size:x}, 截断为0x{new_rsize:x}")
                else:
                    # No data at this offset - keep original but flag it
                    print(f"  ⚠ {sec['name']}: VA 0x{vaddr:x} 超出文件范围, 保留原值")
                    continue
            
            # Apply fix
            old_roff = sec['roff']
            old_rsize = sec['rsize']
            
            struct.pack_into('<I', self.data, sec['header_off'] + 16, new_rsize)
            struct.pack_into('<I', self.data, sec['header_off'] + 20, new_roff)
            
            changed = (old_roff != new_roff or old_rsize != new_rsize)
            if changed:
                print(f"  ✏ {sec['name']:<12}: ROff 0x{old_roff:x}→0x{new_roff:x}, "
                      f"RSize 0x{old_rsize:x}→0x{new_rsize:x}")
                fixed_count += 1
        
        return fixed_count
    
    def fix_entry_point(self, oep=None):
        """Fix entry point in PE header"""
        oh = self.pe_offset + 24
        
        if oep is not None:
            rva = oep - self.image_base
        else:
            # Keep current
            return False
        
        old_rva = struct.unpack('<I', self.data[oh+16:oh+20])[0]
        struct.pack_into('<I', self.data, oh+16, rva)
        print(f"  ✏ Entry RVA: 0x{old_rva:x} → 0x{rva:x} (full addr: 0x{oep:x})")
        return True
    
    def fix_size_of_image(self):
        """Recalculate SizeOfImage from section layout"""
        oh = self.pe_offset + 24
        
        last_end = 0
        for sec in self.sections:
            end = sec['vaddr'] + sec['vsize']
            if end > last_end:
                last_end = end
        
        # Align to section alignment
        aligned_size = ((last_end + self.section_alignment - 1) // 
                       self.section_alignment) * self.section_alignment
        
        old_size = self.size_of_image
        if old_size != aligned_size:
            struct.pack_into('<I', self.data, oh+56, aligned_size)
            print(f"  ✏ SizeOfImage: 0x{old_size:x} → 0x{aligned_size:x}")
            self.size_of_image = aligned_size
            return True
        return False
    
    def fix_checksum(self):
        """Zero out PE checksum (Windows will calculate it on load)"""
        oh = self.pe_offset + 24
        if self.is_pe32plus:
            struct.pack_into('<I', self.data, oh+64, 0)  # PE32+ checksum at +64
        else:
            struct.pack_into('<I', self.data, oh+64, 0)  # PE32 checksum at +64
    
    def rebuild(self, oep=None, output_path=None, verbose=True):
        """
        Full PE rebuild:
        1. Analyze layout
        2. Fix section headers
        3. Fix entry point
        4. Fix SizeOfImage
        5. Zero checksum
        6. Write output
        """
        if verbose:
            self.analyze_dump_layout()
        
        print("\n=== 开始重建 ===")
        
        fixed = self.rebuild_section_headers()
        if fixed > 0:
            print(f"  修复了 {fixed} 个section headers")
        else:
            print("  section headers 无需修复")
        
        if oep:
            self.fix_entry_point(oep)
        
        self.fix_size_of_image()
        self.fix_checksum()
        
        if output_path:
            with open(output_path, 'wb') as f:
                f.write(self.data)
            print(f"\n✅ 重建完成: {output_path}")
            print(f"   大小: {os.path.getsize(output_path)} bytes")
        
        return True


def rebuild_dump(input_path, output_path, oep=None):
    """Convenience function to rebuild a dump"""
    with open(input_path, 'rb') as f:
        data = bytearray(f.read())
    
    rebuilder = PERebuilder(data)
    rebuilder.rebuild(oep=oep, output_path=output_path)
    return rebuilder


if __name__ == '__main__':
    import sys
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <input.dump> <output.exe> [oep_hex]")
        sys.exit(1)
    
    input_path = sys.argv[1]
    output_path = sys.argv[2]
    oep = int(sys.argv[3], 16) if len(sys.argv) > 3 else None
    
    rebuild_dump(input_path, output_path, oep)
