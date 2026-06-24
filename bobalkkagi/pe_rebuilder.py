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
                # Critical Themida sections - these MUST have full data
                CRITICAL_SECTIONS = {'.themida', '.boot', '.text', '.idata', '.rsrc'}
                is_critical = sec['name'] in CRITICAL_SECTIONS
                
                actual_data = file_size - new_roff
                if actual_data <= 0:
                    if is_critical:
                        print(f"  ❌ {sec['name']}: 关键段 VA 0x{vaddr:x} 完全超出文件范围! 重建后无法运行")
                    else:
                        print(f"  ⚠ {sec['name']}: VA 0x{vaddr:x} 超出文件范围, 保留原值")
                    continue
                
                # Partial data exists
                if is_critical:
                    print(f"  ❌ {sec['name']}: 关键段超出文件边界 {data_end:x}>{file_size:x}, "
                          f"仅0x{actual_data:x}/0x{aligned_vsize:x}字节可用 — 重建后该段数据不完整!")
                    new_rsize = ((actual_data + self.file_alignment - 1) // 
                                self.file_alignment) * self.file_alignment
                else:
                    new_rsize = ((actual_data + self.file_alignment - 1) // 
                                self.file_alignment) * self.file_alignment
                    print(f"  ⚠ {sec['name']}: 超出文件边界 {data_end:x}>{file_size:x}, 截断为0x{new_rsize:x}")
            
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
            # Guard: if OEP is outside valid PE range (e.g. DLL address from
            # Unicorn crash), fall back to original entry point or skip.
            if rva < 0 or rva > 0xFFFFFFFF:
                print(f"  ⚠ Entry RVA 0x{rva:x} out of range — skipping entry point fix")
                print(f"     (OEP=0x{oep:x}, ImageBase=0x{self.image_base:x})")
                return False
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

        # P4: 强制重定位表重建 + 资源恢复
        self.force_reloc_rebuild()
        self.recover_resources()

        if output_path:
            with open(output_path, 'wb') as f:
                f.write(self.data)
            print(f"\n✅ 重建完成: {output_path}")
            print(f"   大小: {os.path.getsize(output_path)} bytes")

        return True

    # ===== P4: 强制重定位表重建 =====

    def force_reloc_rebuild(self):
        """P4: 扫描内存指针写入，重建 .reloc 目录

        Themida 经常剥离重定位表。此方法扫描 dump 中所有
        指向 ImageBase 范围的 64位指针，标记为重定位项。
        """
        image_base = self.image_base
        if not image_base:
            return

        reloc_entries = []
        data = self.data

        # 扫描所有 8 字节对齐的指针
        for offset in range(0, len(data) - 8, 8):
            try:
                ptr = struct.unpack_from('<Q', data, offset)[0]
            except:
                continue
            # 指针指向 ImageBase 范围 → 潜在重定位
            if image_base <= ptr < image_base + len(data):
                reloc_entries.append(offset)

        if not reloc_entries:
            return

        # 查找或创建 .reloc 段
        reloc_sec = None
        for sec in self.sections:
            if sec['name'] == '.reloc':
                reloc_sec = sec
                break

        if not reloc_sec:
            # 在文件末尾添加 .reloc 段
            self._add_reloc_section(reloc_entries)
        else:
            print(f"  🔧 Reloc: {len(reloc_entries)} entries (existing .reloc)")

    def _add_reloc_section(self, entries: list):
        """P4: 添加新的 .reloc 段"""
        from collections import defaultdict

        # 按页(4KB)分组
        pages = defaultdict(list)
        for offset in entries:
            page = offset & ~0xFFF
            pages[page].append(offset & 0xFFF)

        # 构建 .reloc 数据
        reloc_data = bytearray()
        for page, offsets in sorted(pages.items()):
            block_size = 8 + len(offsets) * 2
            # IMAGE_BASE_RELOCATION header
            reloc_data += struct.pack('<II', page, block_size)
            for off in offsets:
                # Type: IMAGE_REL_BASED_DIR64 (10)
                entry = (10 << 12) | off
                reloc_data += struct.pack('<H', entry)

        # Pad to 4KB
        aligned = ((len(reloc_data) + 0xFFF) // 0x1000) * 0x1000
        reloc_data += b'\x00' * (aligned - len(reloc_data))

        # Add section
        new_rva = max(s['vaddr'] + max(s['vsize'], s['rsize']) for s in self.sections)
        new_rva = (new_rva + 0xFFF) & ~0xFFF
        new_roff = (len(self.data) + 0xFFF) & ~0xFFF

        self.data += b'\x00' * (new_roff - len(self.data))
        self.data += bytes(reloc_data)

        self.sections.append({
            'name': '.reloc', 'vsize': len(reloc_data), 'vaddr': new_rva,
            'rsize': len(reloc_data), 'roff': new_roff,
            'flags': 0x42000040, 'idx': len(self.sections)
        })

        # Update data directory for relocations
        oh = self.pe_offset + 24
        if self.is_pe32plus:
            dd = oh + 112 + 5 * 8  # entry 5 = base relocations
        else:
            dd = oh + 96 + 5 * 8
        struct.pack_into('<I', self.data, dd, new_rva)
        struct.pack_into('<I', self.data, dd + 4, len(reloc_data))

        # Update number of sections
        fh = self.pe_offset + 4
        new_count = len(self.sections)
        struct.pack_into('<H', self.data, fh + 2, new_count)

        print(f"  🔧 Reloc: {len(entries)} entries → .reloc @ 0x{new_rva:x}")

    # ===== P4: 资源目录恢复 =====

    def recover_resources(self):
        """P4: 检查并恢复损坏/缺失的资源目录"""
        # 检查现有资源目录
        oh = self.pe_offset + 24
        if self.is_pe32plus:
            rsrc_rva = struct.unpack_from('<I', self.data, oh + 112 + 2 * 8)[0]
            rsrc_size = struct.unpack_from('<I', self.data, oh + 112 + 2 * 8 + 4)[0]
        else:
            rsrc_rva = struct.unpack_from('<I', self.data, oh + 96 + 2 * 8)[0]
            rsrc_size = struct.unpack_from('<I', self.data, oh + 96 + 2 * 8 + 4)[0]

        if rsrc_rva and rsrc_size:
            print(f"  📦 Resources: present (RVA=0x{rsrc_rva:x}, size={rsrc_size})")
            return

        # 资源目录为空 → 标记为 "需要外部工具恢复"
        print(f"  ⚠ Resources: missing — use external tool (Resource Hacker) to recover")


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
