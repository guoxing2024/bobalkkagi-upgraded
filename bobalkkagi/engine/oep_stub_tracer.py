"""
V6 OEP Stub Tracer — 追踪 Themida OEP 包装存根直到真正入口
==============================================================
Bobalkkagi V6 — 不依赖硬编码 OEP，在 Unicorn 模拟中动态追踪。

原理:
  1. 当 Unicorn RIP 首次到达 OEP 存根 (65 48 A1 30 00 00 00)
  2. 进入单步追踪模式
  3. 记录每条指令，直到遇到 JMP/CALL/RET
  4. 跳转目标 = 真实 OEP

使用方法:
  在 UC_HOOK_CODE 中，检测 PEB 访问模式，触发追踪。
"""

import struct
from typing import Optional, List


class OEPStubTracer:
    """Themida OEP 包装存根追踪器"""

    def __init__(self, uc: 'Uc', image_base: int, verbose: bool = False):
        self.uc = uc
        self.image_base = image_base
        self.verbose = verbose
        self._trace_active = False
        self._trace_log: List[dict] = []
        self._real_oep: Optional[int] = None
        self._peb_code_seen = False

    def check_peb_access(self, address: int) -> bool:
        """检查当前指令是否在读取 PEB (GS:[0x30])

        Returns True if OEP stub detected — caller should activate tracing.
        """
        try:
            code = bytes(self.uc.mem_read(address, 16))
        except Exception:
            return False

        # Pattern: 65 48 A1 30 00 00 00 (mov rax, gs:[0x30])
        if code[:9] == bytes([0x65, 0x48, 0xA1, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00]):
            if self.verbose:
                print(f"  [StubTracer] PEB access detected @ 0x{address:x}")
            self._peb_code_seen = True
            self._trace_active = True
            return True
        return False

    def trace_instruction(self, address: int) -> Optional[int]:
        """追踪单条指令 — 寻找 JMP/CALL/RET 目标

        Returns target address if OEP found, None otherwise.
        """
        if not self._trace_active:
            return None

        try:
            code = bytes(self.uc.mem_read(address, 15))
        except Exception:
            self._trace_active = False
            return None

        # Decode the first instruction
        b0 = code[0]

        # JMP rel32  (E9 XX XX XX XX)
        if b0 == 0xE9 and len(code) >= 5:
            rel = struct.unpack_from('<i', code, 1)[0]
            target = address + 5 + rel
            return self._found_oep(target, f"jmp @ 0x{address:x}")

        # JMP rel8  (EB XX)
        if b0 == 0xEB:
            rel = struct.unpack_from('<b', code, 1)[0]
            target = address + 2 + rel
            return self._found_oep(target, f"jmp short @ 0x{address:x}")

        # JMP [rip+disp] (FF 25)
        if b0 == 0xFF and len(code) >= 6 and code[1] == 0x25:
            # This is an indirect jump — read target from memory
            disp = struct.unpack_from('<i', code, 2)[0]
            ptr_addr = address + 6 + disp
            try:
                ptr_data = self.uc.mem_read(ptr_addr, 8)
                target = struct.unpack('<Q', bytes(ptr_data))[0]
                return self._found_oep(target, f"jmp [mem] @ 0x{address:x}")
            except Exception:
                pass

        # CALL rel32 (E8)
        if b0 == 0xE8 and len(code) >= 5:
            rel = struct.unpack_from('<i', code, 1)[0]
            target = address + 5 + rel
            return self._found_oep(target, f"call @ 0x{address:x}")

        # JMP reg (FF E0-E7)
        if b0 == 0xFF and len(code) >= 2 and code[1] in range(0xE0, 0xE8):
            # We can't easily trace register-based jumps
            # Record the context and continue
            pass

        # RET (C3, C2)
        if b0 == 0xC3 or (b0 == 0xC2 and len(code) >= 3):
            # RET — pop return address from stack
            try:
                rsp = self.uc.reg_read(UC_X86_REG_RSP)
                ret_data = self.uc.mem_read(rsp, 8)
                target = struct.unpack('<Q', bytes(ret_data))[0]
                return self._found_oep(target, f"ret @ 0x{address:x}")
            except Exception:
                pass

        # PUSH imm32; RET (68 XX XX XX XX ... C3) — typical Themida OEP dispatch
        if b0 == 0x68 and len(code) >= 6:
            push_val = struct.unpack_from('<I', code, 1)[0]
            if len(code) >= 7 and code[5] == 0xC3:
                # push addr; ret = jmp to addr
                return self._found_oep(push_val, f"push/ret @ 0x{address:x}")

        # Record trace
        if len(self._trace_log) < 100:
            self._trace_log.append({
                'address': address,
                'bytes': code[:8].hex(),
                'rip': address,
            })

        # Limit: after 500 instructions, give up
        if len(self._trace_log) > 500:
            if self.verbose:
                print(f"  [StubTracer] No OEP found after 500 instructions, giving up")
            self._trace_active = False
            return None

        return None  # still tracing

    def _found_oep(self, target: int, src: str) -> int:
        """找到真实 OEP"""
        self._real_oep = target
        self._trace_active = False
        if self.verbose:
            print(f"  [StubTracer] Real OEP: 0x{target:x} ({src})")

        # Verify the OEP has a valid prologue
        try:
            oep_code = bytes(self.uc.mem_read(target, 16))
            if self.verbose:
                print(f"  [StubTracer] OEP code: {oep_code[:12].hex()}")
            # Check for sub rsp
            if oep_code[:3] == bytes([0x48, 0x83, 0xEC]):
                if self.verbose:
                    print(f"  [StubTracer] ✓ sub rsp prologue confirmed")
            elif oep_code[0] == 0x55:
                if self.verbose:
                    print(f"  [StubTracer] ✓ push rbp prologue confirmed")
        except Exception:
            pass

        return target

    @property
    def trace_active(self) -> bool:
        return self._trace_active

    @property
    def real_oep(self) -> Optional[int]:
        return self._real_oep

    def get_log(self) -> List[dict]:
        """Get the trace log for later analysis"""
        return list(self._trace_log)


# UC_X86_REG imports for the trace function
try:
    from unicorn.x86_const import UC_X86_REG_RSP, UC_X86_REG_RIP
except ImportError:
    UC_X86_REG_RSP = 0
    UC_X86_REG_RIP = 0
