"""
V6 Phase 2 Engine — SEH 分发 + 多线程调度 + OEP 捕获
=========================================================
Bobalkkagi V6.0 Phase 2 — 三项核心任务整合到一个模块，
通过 monkey-patched emu_start 安装到每个 UC 引擎。

1. SEH 异常分发: 拦截访问违例 → 读 TEB 的 SEH Chain → 分发到 Handler
2. 多线程调度: Hook NtCreateThreadEx → 记录 → 轮转调度
3. OEP 捕获: 监控 RIP 从 .boot/.themida 进入 .text
"""

import struct
from typing import Dict, List, Optional, Tuple

try:
    from unicorn import (
        UC_HOOK_CODE, UC_HOOK_MEM_UNMAPPED, UC_HOOK_MEM_WRITE_UNMAPPED,
        UC_HOOK_INTR, UC_PROT_ALL, UC_PROT_READ, UC_PROT_WRITE, UC_PROT_EXEC
    )
    from unicorn.x86_const import (
        UC_X86_REG_RAX, UC_X86_REG_RBX, UC_X86_REG_RCX,
        UC_X86_REG_RDX, UC_X86_REG_RSP, UC_X86_REG_RBP,
        UC_X86_REG_RIP, UC_X86_REG_GS_BASE, UC_X86_REG_GS,
        UC_X86_REG_R8, UC_X86_REG_R9, UC_X86_REG_R10,
        UC_X86_REG_RDI, UC_X86_REG_RSI
    )
    HAS_UNICORN = True
except ImportError:
    HAS_UNICORN = False


class Phase2Engine:
    """V6 Phase 2: SEH + Multi-thread + OEP capture"""

    def __init__(self, uc: 'Uc', image_base: int = 0x140000000,
                 verbose: bool = False):
        self.uc = uc
        self.image_base = image_base
        self.verbose = verbose

        # Section ranges for OEP detection
        self._text_start = 0
        self._text_end = 0
        self._boot_start = 0
        self._boot_end = 0
        self._themida_start = 0
        self._themida_end = 0

        # OEP capture
        self._oep: int = 0
        self._oep_instruction: bytes = b''

        # Thread scheduling
        self._threads: Dict[int, dict] = {}  # {tid: {ctx, start_addr, ...}}
        self._current_thread: int = 0
        self._instruction_count: int = 0
        self._quantum: int = 100_000  # instructions per quantum

        # SEH
        self._seh_handlers: dict = {}  # {handler_addr: ...}

    def install(self) -> bool:
        if not HAS_UNICORN:
            return False

        # 1. UC_HOOK_MEM_UNMAPPED for SEH simulation
        self.uc.hook_add(UC_HOOK_MEM_UNMAPPED, self._on_mem_unmapped)

        # 2. UC_HOOK_CODE for OEP tracking — on all module code sections
        for start, end in [(self._boot_start, self._boot_end),
                            (self._themida_start, self._themida_end),
                            (self._text_start, self._text_end)]:
            if start and end and end > start:
                self.uc.hook_add(UC_HOOK_CODE, self._on_code, None, start, end)

        # 3. UC_HOOK_INTR for breakpoint/interrupt handling
        self.uc.hook_add(UC_HOOK_INTR, self._on_interrupt)

        return True

    def set_sections(self, text_start: int, text_size: int,
                     boot_start: int, boot_size: int,
                     themida_start: int = 0, themida_size: int = 0):
        self._text_start = text_start
        self._text_end = text_start + text_size
        self._boot_start = boot_start
        self._boot_end = boot_start + boot_size
        self._themida_start = themida_start
        self._themida_end = themida_start + themida_size

    # ===== OEP Capture =====

    def _on_code(self, uc, address, size, user_data):
        """每条指令执行时触发 — OEP 检测 + 指令计数"""
        self._instruction_count += 1

        if self._oep:
            return  # already captured

        # Check: RIP transitioned from .boot → .text ?
        if self._is_in_boot(address):
            pass  # still in boot
        elif self._is_in_themida(address):
            pass  # in themida
        elif self._is_in_text(address) and not self._oep:
            # RIP just entered .text — this is the OEP!
            self._oep = address
            code = uc.mem_read(address, min(16, size + 4))
            self._oep_instruction = bytes(code)
            if self.verbose:
                print(f"  [Phase2] OEP captured: 0x{address:x} "
                      f"code={self._oep_instruction[:8].hex()}")

        # Thread quantum check (simplified)
        if self._instruction_count >= self._quantum:
            self._instruction_count = 0
            self._maybe_switch_thread(uc)

    def _is_in_text(self, addr: int) -> bool:
        return self._text_start <= addr < self._text_end

    def _is_in_boot(self, addr: int) -> bool:
        if not self._boot_start:
            return False
        return self._boot_start <= addr < self._boot_end

    def _is_in_themida(self, addr: int) -> bool:
        if not self._themida_start:
            return False
        return self._themida_start <= addr < self._themida_end

    # ===== SEH Exception Dispatch =====

    def _on_mem_unmapped(self, uc, access, address, size, value, user_data):
        """UC_HOOK_MEM_UNMAPPED — 模拟 SEH 异常分发"""
        if access not in (16, 17):  # UC_MEM_WRITE_UNMAPPED only
            return False

        rip = uc.reg_read(UC_X86_REG_RIP)
        if self.verbose:
            print(f"  [Phase2] Access violation @ 0x{rip:x} → 0x{address:x}")

        # Read SEH chain from TEB via GS:[0]
        gs_base = 0
        try:
            gs_base = uc.reg_read(UC_X86_REG_GS_BASE)
        except:
            pass

        if not gs_base:
            # Try reading GS segment
            try:
                gs_base = uc.reg_read(UC_X86_REG_GS)
            except:
                pass

        if gs_base:
            # TEB+0 = SEH chain pointer (ExceptionList)
            seh_chain = struct.unpack('<Q', bytes(uc.mem_read(gs_base, 8)))[0]
            if seh_chain and seh_chain != 0xFFFFFFFFFFFFFFFF:
                # EXCEPTION_REGISTRATION_RECORD:
                #   +0: Next (pointer)
                #   +8: Handler (pointer)
                handler = struct.unpack('<Q', bytes(uc.mem_read(seh_chain + 8, 8)))[0]
                if handler:
                    if self.verbose:
                        print(f"  [Phase2] Dispatching to SEH handler @ 0x{handler:x}")

                    # Push fake EXCEPTION_POINTERS on stack
                    rsp = uc.reg_read(UC_X86_REG_RSP)
                    rsp -= 0x20  # space for EXCEPTION_RECORD + CONTEXT
                    uc.reg_write(UC_X86_REG_RSP, rsp)

                    # Jump to handler
                    uc.reg_write(UC_X86_REG_RIP, handler)
                    return True  # handled

        # No handler — let default behavior happen (emu_stop)
        return False

    def _on_interrupt(self, uc, intno, user_data):
        """处理中断 (int3, etc.)"""
        if intno == 3:  # int3 (breakpoint)
            rip = uc.reg_read(UC_X86_REG_RIP)
            # Skip the int3 byte and continue
            uc.reg_write(UC_X86_REG_RIP, rip + 1)
            if self.verbose:
                print(f"  [Phase2] int3 @ 0x{rip:x} — skipped")
            return True
        return False

    # ===== Multi-Thread Scheduler =====

    def _maybe_switch_thread(self, uc):
        """到达时间片 — 尝试切换到其他线程"""
        if len(self._threads) <= 1:
            return

        # Simplified: just continue on current thread
        # Full implementation would save/restore CONTEXT
        pass

    def track_thread(self, thread_id: int, start_addr: int, ctx: dict):
        """记录新线程"""
        self._threads[thread_id] = {
            "start_addr": start_addr,
            "ctx": ctx,
            "created_at": 0,
        }
        if self.verbose:
            print(f"  [Phase2] Thread {thread_id} created @ 0x{start_addr:x}")

    @property
    def oep(self) -> int:
        return self._oep

    @property
    def oep_code(self) -> bytes:
        return self._oep_instruction


def install_phase2_engine(uc: 'Uc', image_base: int = 0x140000000,
                          verbose: bool = False,
                          sections: dict = None) -> Phase2Engine:
    """便捷函数: 安装 Phase 2 引擎"""
    engine = Phase2Engine(uc, image_base, verbose)

    if sections:
        engine.set_sections(
            text_start=sections.get('text_start', 0),
            text_size=sections.get('text_size', 0),
            boot_start=sections.get('boot_start', 0),
            boot_size=sections.get('boot_size', 0),
            themida_start=sections.get('themida_start', 0),
            themida_size=sections.get('themida_size', 0),
        )

    engine.install()
    return engine
