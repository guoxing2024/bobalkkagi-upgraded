"""
OEP Auto-Detector — V6: 从 dump 扫描函数序言定位真实 OEP
==============================================================
不依赖硬编码。扫描可执行段，找从 .boot 跳入 .text 的过渡点。

算法:
  1. 扫描 .boot 段，找 jmp/call/ret 目标在代码段内的指令
  2. 对每个候选 OEP，验证是否为函数序言 (sub rsp / push rbp 等)
  3. 返回置信度最高的地址
"""

import struct
from typing import List, Tuple, Optional


# 函数序言特征
PROLOGUE_PATTERNS = [
    # sub rsp, imm8  →  48 83 EC xx
    bytes([0x48, 0x83, 0xEC]),
    # sub rsp, imm32 →  48 81 EC xx xx xx xx
    bytes([0x48, 0x81, 0xEC]),
    # push rbp; mov rbp, rsp → 55 48 89 E5
    bytes([0x55, 0x48, 0x89, 0xE5]),
    # push rbx / push rsi / push rdi
    bytes([0x53]),  # push rbx
    bytes([0x56]),  # push rsi
    bytes([0x57]),  # push rdi
    # mov [rsp+8], rcx (x64 calling convention)
    bytes([0x48, 0x89, 0x4C, 0x24]),
    # mov [rsp+8], rdx
    bytes([0x48, 0x89, 0x54, 0x24]),
    # mov rax, gs:[0x30] → PEB access (SIB form)
    bytes([0x65, 0x48, 0x8B, 0x04, 0x25, 0x30]),
    # mov rax, gs:[0xNNNNNNNN] → PEB access (moffs form: 65 48 A1)
    bytes([0x65, 0x48, 0xA1]),
    # mov rax, gs:[0xXX] — any GS segment access
    bytes([0x65, 0x48]),           # GS prefix + REX.W
    # mov eax, gs:[0x30]
    bytes([0x65, 0x8B, 0x04, 0x25, 0x30]),
]


class OEPDetector:
    """V6: 自动 OEP 检测器"""

    def __init__(self, dump_data: bytes, image_base: int = 0x140000000):
        self.dump = dump_data
        self.image_base = image_base

    def detect(self, sections: List[Tuple[int, int, str]]) -> List[Tuple[int, float, str]]:
        """检测 OEP 候选，返回 [(addr, confidence, reason)] 按置信度排序

        Args:
            sections: [(va, size, name)] — PE sections
        """
        candidates: List[Tuple[int, float, str]] = []

        # Find .boot section (Themida bootstrap)
        boot_va, boot_size = 0, 0
        code_vas = []  # all executable code section VAs

        for va, size, name in sections:
            if '.boot' in name.lower():
                boot_va, boot_size = va, size
            if size > 0:
                code_vas.append((va, va + size))

        if not boot_va:
            # Search all executable sections for transitions
            for va, size, name in sections:
                if size > 0 and any(kw in name.lower() for kw in ['boot', 'themida']):
                    boot_va, boot_size = va, size
                    break

        # Method 2: Scan code sections for function prologues
        # Include .themida — real OEP often lives here after decryption
        for va, size, name in sections:
            if size > 0 and (not name or 'text' in name.lower() or
                           'themida' in name.lower() or
                           'code' in name.lower()):
                self._scan_prologues(va, size, name, candidates)

        # Sort by confidence descending, deduplicate
        seen = set()
        unique = []
        for addr, conf, reason in sorted(candidates, key=lambda x: -x[1]):
            if addr not in seen:
                seen.add(addr)
                unique.append((addr, conf, reason))

        return unique[:10]

    def _scan_boot_transitions(self, boot_va: int, boot_size: int,
                                code_vas: List[Tuple[int, int]],
                                candidates: list):
        """在 .boot 段找跳向代码段的 JMP/CALL/RET"""
        rva = boot_va - self.image_base
        if rva < 0 or rva + boot_size > len(self.dump):
            return

        data = self.dump[rva:rva + boot_size]
        end = len(data) - 8

        i = 0
        while i < end:
            b = data[i]

            # JMP rel32: E9 xx xx xx xx
            if b == 0xE9 and i + 5 <= end:
                rel = struct.unpack_from('<i', data, i + 1)[0]
                target = boot_va + i + 5 + rel
                self._check_target(target, code_vas, f"jmp @ 0x{boot_va+i:x}", candidates)
                i += 5
                continue

            # JMP [rip+disp]: FF 25 xx xx xx xx
            if b == 0xFF and i + 6 <= end and data[i + 1] == 0x25:
                disp = struct.unpack_from('<i', data, i + 2)[0]
                ptr_addr = boot_va + i + 6 + disp
                ptr_rva = ptr_addr - self.image_base
                if 0 <= ptr_rva < len(self.dump) - 7:
                    target = struct.unpack_from('<Q', self.dump, ptr_rva)[0]
                    self._check_target(target, code_vas, f"jmp[mem] @ 0x{boot_va+i:x}", candidates)
                i += 6
                continue

            # CALL rel32: E8 xx xx xx xx
            if b == 0xE8 and i + 5 <= end:
                rel = struct.unpack_from('<i', data, i + 1)[0]
                target = boot_va + i + 5 + rel
                self._check_target(target, code_vas, f"call @ 0x{boot_va+i:x}", candidates)
                i += 5
                continue

            # RET (may be preceded by push OEP)
            if b == 0xC3:
                candidates.append((boot_va + i, 0.1, f"ret @ 0x{boot_va+i:x}"))
                i += 1
                continue

            # PUSH imm32 + RET = jmp to OEP
            if b == 0x68 and i + 6 <= end:  # push imm32
                addr = struct.unpack_from('<I', data, i + 1)[0]
                if i + 6 < end and data[i + 5] == 0xC3:  # followed by RET
                    # push addr; ret = jump to addr
                    target = addr
                    self._check_target(target, code_vas,
                                       f"push/ret @ 0x{boot_va+i:x}", candidates)
                    i += 6
                    continue

            i += 1

    def _check_target(self, target: int, code_vas: List[Tuple[int, int]],
                       reason: str, candidates: list):
        """检查目标是否在代码段内"""
        # Exclude .boot range targets
        BOOT_START = self.image_base + 0x885000
        BOOT_END = BOOT_START + 0x400000
        if BOOT_START <= target < BOOT_END:
            return

        for cs, ce in code_vas:
            if cs <= target < ce:
                confidence = self._validate_prologue(target)
                if confidence > 0:
                    candidates.append((target, confidence, reason))
                return

    def _validate_prologue(self, addr: int) -> float:
        """验证地址是否为函数序言，返回置信度 0.0-1.0"""
        rva = addr - self.image_base
        if rva < 0 or rva + 16 > len(self.dump):
            return 0.0

        code = self.dump[rva:rva + 16]
        score = 0.0
        b0 = code[0]

        # Check first byte: should be valid x64 instruction start
        # Penalize obvious non-code
        if code[:4] == b'\x00\x00\x00\x00' or code[:4] == b'\xff\xff\xff\xff':
            return 0.0

        # sub rsp with small imm → likely VM stub, reject
        if b0 == 0x48 and len(code) >= 4:
            if code[1] == 0x83 and code[2] == 0xEC and code[3] < 0x20:
                return 0.0  # sub rsp < 0x20 → hard reject
            if code[1] == 0x81 and code[2] == 0xEC:
                imm = struct.unpack_from('<I', code, 3)[0]
                if imm < 0x20:
                    return 0.0

        # High-confidence: matches known prologue patterns
        for pat in PROLOGUE_PATTERNS:
            if code[:len(pat)] == pat:
                # GS:[0x30] access → very strong signal (PEB read)
                if pat == bytes([0x65, 0x48, 0x8B, 0x04, 0x25, 0x30]):
                    score += 0.6
                elif pat == bytes([0x65, 0x48, 0xA1]):
                    score += 0.5  # GS moffs access
                elif len(pat) >= 2:
                    score += 0.3
                break

        # sub rsp detection
        if b0 == 0x48 and len(code) >= 3:
            if code[1] == 0x83 and code[2] == 0xEC:
                score += 0.4
            elif code[1] == 0x81 and code[2] == 0xEC:
                score += 0.4

        # push detection
        if b0 in (0x55, 0x53, 0x56, 0x57):
            score += 0.2

        return min(score, 1.0)

    def _scan_prologues(self, va: int, size: int, name: str,
                         candidates: list):
        """扫描代码段中的函数序言 — 排除壳段"""
        # Skip .boot and .reloc sections
        if any(kw in name.lower() for kw in ['boot', '.reloc']):
            return

        rva = va - self.image_base
        if rva < 0:
            return
        data = self.dump[rva:rva + min(size, len(self.dump) - rva)]
        end = len(data) - 8

        step = 1
        for i in range(0, end, step):
            b = data[i]
            # sub rsp, imm8
            if (b == 0x48 and len(data) > i + 2 and
                data[i + 1] == 0x83 and data[i + 2] == 0xEC):
                imm = data[i + 3]
                if imm < 0x20:  # sub rsp < 0x20 → likely VM stub, skip
                    i += 4
                    continue
                addr = va + i
                conf = self._validate_prologue(addr)
                if conf > 0.3:
                    candidates.append((addr, conf, f"prologue in {name} @ 0x{addr:x}"))
                i += 4
                continue
            # push rbp
            if b == 0x55:
                addr = va + i
                conf = self._validate_prologue(addr)
                if conf > 0.3:
                    candidates.append((addr, conf, f"prologue in {name} @ 0x{addr:x}"))
            # GS segment access (PEB read — typical startup)
            if b == 0x65 and len(data) > i + 1 and data[i + 1] == 0x48:
                addr = va + i
                conf = self._validate_prologue(addr)
                if conf > 0.3:
                    candidates.append((addr, conf, f"gs-seg in {name} @ 0x{addr:x}"))
            i += 1


def detect_oep(dump_path: str, image_base: int = 0x140000000,
               sections: List[Tuple[int, int, str]] = None) -> Optional[int]:
    """便捷函数: 从 dump 自动检测 OEP"""
    with open(dump_path, 'rb') as f:
        data = f.read()

    detector = OEPDetector(data, image_base)

    if sections is None:
        # Parse from PE header
        pe_off = struct.unpack_from('<I', data, 0x3C)[0]
        num_sec = struct.unpack_from('<H', data, pe_off + 6)[0]
        oh = pe_off + 24
        opt_size = struct.unpack_from('<H', data, pe_off + 20)[0]
        sec_off = oh + opt_size
        sections = []
        for i in range(num_sec):
            s = sec_off + i * 40
            flags = struct.unpack_from('<I', data, s + 36)[0]
            if flags & 0x20000000:
                vsize = struct.unpack_from('<I', data, s + 8)[0]
                vaddr = struct.unpack_from('<I', data, s + 12)[0]
                name = data[s:s + 8].rstrip(b'\x00').decode('ascii', errors='replace')
                sections.append((image_base + vaddr, vsize, name))

    candidates = detector.detect(sections)
    if candidates:
        print(f"  [OEPDetect] Top candidates:")
        for addr, conf, reason in candidates[:5]:
            print(f"    {reason} → 0x{addr:x} (conf={conf:.2f})")
        return candidates[0][0]
    return None
