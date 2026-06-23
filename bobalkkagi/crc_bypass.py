"""
CRC Integrity Check Bypass for Themida
========================================
Bobalkkagi升级 — 阶段一：CRC校验绕过

Themida 3.x uses CRC32 integrity checks to detect code tampering.
This module scans the .boot section for CRC check patterns and
patches conditional jumps that would trigger on checksum mismatch.

策略模式:
  safe (安全模式 - 默认):
    - 只patch CMP+Jcc 附近有 ROL/ROR/CRC32 指令的模式
    - 降低误伤正常条件跳转
  aggressive (激进模式):
    - CMP + 条件跳转(10字节内) 全部NOP
    - 适用于"只要能跑就行"的场景，但可能误伤
"""

import struct
import logging

logger = logging.getLogger("Bobalkkagi.CRCBypass")

# CRC补丁日志：记录所有被NOP的地址和原始字节，用于回滚
CRC_PATCH_LOG = []  # [(address, original_bytes), ...]

def get_crc_patch_log():
    """获取所有CRC补丁记录，用于回滚"""
    return list(CRC_PATCH_LOG)

def clear_crc_patch_log():
    """清空CRC补丁记录"""
    CRC_PATCH_LOG.clear()

def rollback_crc_patches(uc, boot_base):
    """
    回滚所有CRC补丁，恢复原始字节。
    在脱壳失败或行为异常时调用。
    """
    count = 0
    for addr, orig_bytes in CRC_PATCH_LOG:
        try:
            uc.mem_write(boot_base + addr, orig_bytes)
            count += 1
        except Exception as e:
            logger.warning(f"CRC rollback failed @ 0x{boot_base + addr:x}: {e}")
    CRC_PATCH_LOG.clear()
    logger.info(f"CRC rollback: restored {count} patches")
    return count

try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64
    HAS_CAPSTONE = True
except ImportError:
    HAS_CAPSTONE = False
    logger.warning("capstone not available, CRC bypass disabled")

# CRC校验相关的指令助记符（用于安全模式识别）
CRC_RELATED_MNEMONICS = {
    'rol', 'ror', 'rcr', 'rcl',      # 循环移位（CRC常用）
    'shr', 'shl', 'sar', 'sal',       # 移位
    'xor', 'and', 'or',               # 逻辑运算
    'add', 'sub', 'imul', 'mul',      # 算术运算
    'crc32',                          # x86 CRC32指令
}

def scan_and_patch_crc(data: bytearray, base_addr: int, section_va: int, section_size: int, mode: str = 'safe') -> int:
    """
    Scan a memory section for CRC check patterns and patch them.
    
    Args:
        data: Section data
        base_addr: Base address for disassembly
        section_va: Section virtual address (unused, kept for compat)
        section_size: Section size
        mode: 'safe' (default) or 'aggressive'
            safe: Only patch CMP+Jcc if there are CRC-related instructions nearby
            aggressive: Patch ALL CMP+Jcc pairs within 10 bytes
    
    Returns: number of patches applied
    """
    if not HAS_CAPSTONE:
        return 0
    
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    
    section_start = section_va - (base_addr & 0xFFFFFFFF)
    section_data = data[section_start:section_start + min(section_size, len(data) - section_start)]
    
    if len(section_data) < 16:
        logger.warning(f"CRC scan: section data too small ({len(section_data)} bytes)")
        return 0
    
    patches = 0
    last_cmp_addr = 0
    last_cmp_has_crc_context = False
    
    # Track recent instructions for CRC context detection
    recent_mnemonics = []
    
    try:
        for insn in md.disasm(section_data, base_addr + section_va):
            mnemonic = insn.mnemonic.lower()
            recent_mnemonics.append(mnemonic)
            if len(recent_mnemonics) > 5:
                recent_mnemonics.pop(0)
            
            # Track CMP instructions
            if mnemonic == 'cmp':
                last_cmp_addr = insn.address
                # Check if any recent instruction is CRC-related
                last_cmp_has_crc_context = any(m in CRC_RELATED_MNEMONICS for m in recent_mnemonics)
                continue
            
            # Check conditional jumps after CMP
            if mnemonic in ('jne', 'jne', 'jnz', 'jz', 'je', 'jb', 'jbe', 'ja', 'jae', 'jl', 'jle', 'jg', 'jge'):
                if last_cmp_addr > 0 and (insn.address - last_cmp_addr) <= 10:
                    should_patch = False
                    
                    if mode == 'aggressive':
                        # Aggressive: patch all CMP+Jcc
                        should_patch = True
                    elif mode == 'safe':
                        # Safe: only patch if CRC context detected
                        should_patch = last_cmp_has_crc_context
                    
                    if should_patch:
                        jump_start = section_start + (last_cmp_addr - base_addr)
                        if jump_start < len(data):
                            jump_size = insn.size
                            
                            # Record original bytes for rollback
                            addr_in_section = last_cmp_addr - (section_va - (base_addr & 0xFFFFFFFF))
                            orig = bytes(data[jump_start:jump_start + jump_size])
                            CRC_PATCH_LOG.append((addr_in_section, orig))
                            
                            nop_patch = b'\x90' * jump_size
                            
                            if jump_start + jump_size <= len(data):
                                data[jump_start:jump_start + jump_size] = nop_patch
                                patches += 1
                                logger.info(f"CRC bypass [{mode}] @ 0x{insn.address:x}: patched {mnemonic} to NOPs [recorded for rollback]")
                    
                    last_cmp_addr = 0
                    last_cmp_has_crc_context = False
                else:
                    last_cmp_addr = 0
                    last_cmp_has_crc_context = False
            else:
                # Non-jump instruction resets CMP tracking
                last_cmp_addr = 0
                last_cmp_has_crc_context = False
                
    except Exception as e:
        logger.warning(f"CRC scan error: {e}")
    
    return patches


def crc_bypass_post_load(uc, themida_section, boot_section, image_base, mode='safe'):
    """
    Apply CRC bypass patches after PE loading but before emulation.
    
    Args:
        mode: 'safe' (default) or 'aggressive'
    """
    if not HAS_CAPSTONE:
        print("  [CRC] capstone not installed, skipping bypass")
        return 0
    
    boot_base = boot_section[1]
    boot_size = boot_section[2]
    
    try:
        read_size = min(boot_size, 0x10000)
        if read_size <= 0:
            print(f"  [CRC] warning: boot section size={boot_size}, skip scan")
            return 0
        
        code = uc.mem_read(boot_base, read_size)
        if not code or len(code) == 0:
            print(f"  [CRC] warning: empty boot section at 0x{boot_base:x}")
            return 0
            
        data = bytearray(code)
        
        patches = scan_and_patch_crc(data, boot_base, 0, len(data), mode=mode)
        if patches > 0:
            uc.mem_write(boot_base, bytes(data))
            print(f"  [CRC] [{mode}] 已绕过 {patches} 个CRC检查点")
        
        return patches
    except Exception as e:
        print(f"  [CRC] 绕过失败: {e}")
        return 0
