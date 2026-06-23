"""
CRC Integrity Check Bypass for Themida
========================================
Bobalkkagi升级 — 阶段一：CRC校验绕过

Themida 3.x uses CRC32 integrity checks to detect code tampering.
This module scans the .boot section for CRC check patterns and
patches conditional jumps that would trigger on checksum mismatch.

Strategy:
1. Before emulation starts, scan .boot section for CRC check patterns
2. Pattern: `cmp reg32, [rsp+offset]` followed by `jne/jz/je/jnz` 
3. Replace the conditional jump with NOPs (always pass the check)
"""

import struct
import logging

logger = logging.getLogger("Bobalkkagi.CRCBypass")

try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64
    HAS_CAPSTONE = True
except ImportError:
    HAS_CAPSTONE = False
    logger.warning("capstone not available, CRC bypass disabled")


def scan_and_patch_crc(data: bytearray, base_addr: int, section_va: int, section_size: int) -> int:
    """
    Scan a memory section for CRC check patterns and patch them.
    
    Pattern detection:
    - Looks for: `cmp reg32, [rsp+offset]` or `cmp reg32, imm32`
      followed by conditional jump
    - The comparison typically checks a CRC32 result against a stored value
    
    Returns: number of patches applied
    """
    if not HAS_CAPSTONE:
        return 0
    
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True  # Need detail for operand info
    
    section_start = section_va - (base_addr & 0xFFFFFFFF)  # Convert to file offset
    section_data = data[section_start:section_start + min(section_size, len(data) - section_start)]
    
    patches = 0
    last_cmp_addr = 0
    last_cmp_info = None
    
    try:
        for insn in md.disasm(section_data, base_addr + section_va):
            mnemonic = insn.mnemonic.lower()
            
            # Track CMP instructions
            if mnemonic == 'cmp':
                last_cmp_addr = insn.address
                last_cmp_info = insn
                continue
            
            # Check if we see a conditional jump after a CMP
            if mnemonic in ('jne', 'jne', 'jnz', 'jz', 'je', 'jb', 'jbe', 'ja', 'jae', 'jl', 'jle', 'jg', 'jge'):
                if last_cmp_addr > 0 and (insn.address - last_cmp_addr) <= 10:
                    # We have a CMP followed by conditional jump within 10 bytes
                    # This is a potential CRC check
                    
                    # Read the jump instruction bytes
                    jump_start = section_start + (last_cmp_addr - base_addr)
                    if jump_start < len(data):
                        # Replace conditional jump with: mov eax, 1 (B8 01 00 00 00) + 2 nops
                        # or: NOP (0x90) x size_of_jump
                        jump_size = insn.size
                        nop_patch = b'\x90' * jump_size
                        
                        if jump_start + jump_size <= len(data):
                            data[jump_start:jump_start + jump_size] = nop_patch
                            patches += 1
                            logger.info(f"CRC bypass @ 0x{insn.address:x}: patched {mnemonic} to NOPs")
                    
                    last_cmp_addr = 0
                    last_cmp_info = None
                else:
                    last_cmp_addr = 0
                    last_cmp_info = None
            else:
                last_cmp_addr = 0
                last_cmp_info = None
                
    except Exception as e:
        logger.warning(f"CRC scan error: {e}")
    
    return patches


def crc_bypass_post_load(uc, themida_section, boot_section, image_base):
    """
    Apply CRC bypass patches after PE loading but before emulation.
    
    Reads the .boot section from Unicorn memory, scans for CRC check
    patterns, and patches them in-place.
    """
    if not HAS_CAPSTONE:
        print("  [CRC] capstone not installed, skipping bypass")
        return 0
    
    base_name = themida_section[0]
    base_addr = themida_section[1]
    base_size = themida_section[2]
    
    boot_base = boot_section[1]
    boot_size = boot_section[2]
    
    try:
        # Read boot section from Unicorn memory
        code = uc.mem_read(boot_base, min(boot_size, 0x10000))  # Read first 64KB
        data = bytearray(code)
        
        patches = scan_and_patch_crc(data, boot_base, 0, len(data))
        if patches > 0:
            # Write patched code back
            uc.mem_write(boot_base, bytes(data))
            print(f"  [CRC] 已绕过 {patches} 个CRC检查点")
        
        return patches
    except Exception as e:
        print(f"  [CRC] 绕过失败: {e}")
        return 0
