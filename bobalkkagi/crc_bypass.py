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

def scan_and_patch_crc(data: bytearray, base_addr: int, section_va: int, section_size: int, mode: str = 'safe') -> dict:
    """
    Scan a memory section for CRC check patterns and patch them.
    
    Returns: {
        "patches": int,     # 打补丁数
        "completed": bool,   # 是否完整扫描
        "error": str|None    # 错误信息
    }
    """
    result = {"patches": 0, "completed": False, "error": None}
    
    if not HAS_CAPSTONE:
        result["error"] = "capstone not available"
        return result
    
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    
    section_start = section_va - (base_addr & 0xFFFFFFFF)
    section_data = data[section_start:section_start + min(section_size, len(data) - section_start)]
    
    if len(section_data) < 16:
        result["error"] = f"section data too small ({len(section_data)} bytes)"
        return result
    
    patches = 0
    last_cmp_addr = 0
    last_cmp_has_crc_context = False
    recent_mnemonics = []
    
    try:
        for insn in md.disasm(section_data, base_addr + section_va):
            mnemonic = insn.mnemonic.lower()
            # ... (rest of the loop logic continues below)

            recent_mnemonics.append(mnemonic)
            if len(recent_mnemonics) > 5:
                recent_mnemonics.pop(0)

            if mnemonic == 'cmp':
                last_cmp_addr = insn.address
                last_cmp_has_crc_context = any(m in CRC_RELATED_MNEMONICS for m in recent_mnemonics)
                continue

            if mnemonic in ('jne', 'jne', 'jnz', 'jz', 'je', 'jb', 'jbe', 'ja', 'jae', 'jl', 'jle', 'jg', 'jge'):
                if last_cmp_addr > 0 and (insn.address - last_cmp_addr) <= 10:
                    should_patch = False
                    if mode == 'aggressive':
                        should_patch = True
                    elif mode == 'safe':
                        should_patch = last_cmp_has_crc_context

                    if should_patch:
                        jump_start = section_start + (last_cmp_addr - base_addr)
                        if jump_start < len(data):
                            jump_size = insn.size
                            addr_in_section = last_cmp_addr - (section_va - (base_addr & 0xFFFFFFFF))
                            orig = bytes(data[jump_start:jump_start + jump_size])
                            CRC_PATCH_LOG.append((addr_in_section, orig))
                            nop_patch = b'\x90' * jump_size
                            if jump_start + jump_size <= len(data):
                                data[jump_start:jump_start + jump_size] = nop_patch
                                patches += 1

                    last_cmp_addr = 0
                    last_cmp_has_crc_context = False
                else:
                    last_cmp_addr = 0
                    last_cmp_has_crc_context = False
            else:
                last_cmp_addr = 0
                last_cmp_has_crc_context = False

        result["patches"] = patches
        result["completed"] = True
        return result

    except Exception as e:
        result["patches"] = patches
        result["completed"] = False
        result["error"] = str(e)
        logger.warning(f"CRC scan error (partial={patches}): {e}")
        return result


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
        
        result = scan_and_patch_crc(data, boot_base, 0, len(data), mode=mode)
        if result["patches"] > 0:
            uc.mem_write(boot_base, bytes(data))
            status = "完整扫描" if result["completed"] else "部分扫描"
            print(f"  [CRC] [{mode}] {status}: 绕过 {result['patches']} 个CRC检查点")
            if not result["completed"]:
                print(f"  [CRC] ⚠ 扫描未完成: {result['error']}")
        elif result["error"]:
            print(f"  [CRC] 跳过: {result['error']}")
        
        return result["patches"]
    except Exception as e:
        print(f"  [CRC] 绕过失败: {e}")
        return 0
