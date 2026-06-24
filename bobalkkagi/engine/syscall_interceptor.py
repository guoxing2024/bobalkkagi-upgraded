"""
V6 Syscall Interceptor — Unicorn UC_HOOK_INSN(syscall) handler
=================================================================
Bobalkkagi V6.0 Day 3-4: 在 Unicorn 中拦截所有 syscall 指令,
拦截反调试相关的 NtQueryInformationProcess / NtQuerySystemInformation 等。

原理:
  Unicorn 模拟到 syscall (0F 05) 指令时, 我们的回调被触发。
  读取 RAX = syscall 号, RDX/R8/R9 = 参数。
  如果是反调试相关的调用 → 伪造返回值 → RIP += 2 跳过 syscall。
  如果是正常调用 → 记录日志并允许继续 (或 stub 返回).

架构:
  UC_HOOK_INSN(syscall) → dispatch_syscall(uc, rax, args)
    → handle_nt_query_info_process(0x19)
    → handle_nt_query_system_info(0x36)
    → handle_nt_set_info_thread(0x1A)
    → handle_nt_create_thread(0xC3) — 记录/track
    → fallback: log unknown syscall, allow execution
"""

import struct
from typing import Dict, List, Optional, Tuple

try:
    from unicorn import Uc, UC_HOOK_INSN
    from unicorn.x86_const import UC_X86_REG_RAX, UC_X86_REG_RIP
    from unicorn.x86_const import UC_X86_REG_RCX, UC_X86_REG_RDX
    from unicorn.x86_const import UC_X86_REG_R8, UC_X86_REG_R9, UC_X86_REG_R10
    from unicorn.x86_const import UC_X86_REG_RSP
    HAS_UNICORN = True
except ImportError:
    HAS_UNICORN = False


class SyscallInterceptor:
    """V6: Unicorn syscall 劫持器"""

    # Syscall numbers (Windows x64)
    SYSCALL_MAP = {
        0x19: "NtQueryInformationProcess",
        0x1A: "NtSetInformationThread",
        0x1F: "NtQueryInformationThread",
        0x36: "NtQuerySystemInformation",
        0xC3: "NtCreateThreadEx",
        0x18: "NtQueryVirtualMemory",
        0x55: "NtCreateFile",
        0x06: "NtClose",
    }

    # Anti-debug info classes we intercept
    ANTI_DEBUG_CLASSES = {
        0x07: "ProcessDebugPort",
        0x1F: "ProcessDebugFlags",
        0x1E: "ProcessDebugObjectHandle",
        0x23: "SystemKernelDebuggerInformation",  # NtQuerySystemInformation
        0x11: "ThreadHideFromDebugger",           # NtSetInformationThread
    }

    def __init__(self, uc: 'Uc', verbose: bool = False):
        self.uc = uc
        self.verbose = verbose
        self.call_log: List[dict] = []
        self.stats = {"total": 0, "intercepted": 0, "passthrough": 0}

    def install(self):
        """注册 UC_HOOK_INSN(syscall)"""
        if not HAS_UNICORN:
            return False
        self.uc.hook_add(UC_HOOK_INSN, self._on_syscall, None, 1, 0,
                        getattr(__import__('unicorn.x86_const'),
                                'UC_X86_INS_SYSCALL', None))
        return True

    def _on_syscall(self, uc, user_data):
        """syscall 指令回调 — 入口点"""
        rax = uc.reg_read(UC_X86_REG_RAX)
        rip = uc.reg_read(UC_X86_REG_RIP)
        self.stats["total"] += 1

        func_name = self.SYSCALL_MAP.get(rax, f"syscall_0x{rax:x}")

        # Read args: RCX=r10, RDX, R8, R9
        r10 = uc.reg_read(UC_X86_REG_R10)  # first arg for syscall
        rdx = uc.reg_read(UC_X86_REG_RDX)  # second arg
        r8 = uc.reg_read(UC_X86_REG_R8)    # third arg
        r9 = uc.reg_read(UC_X86_REG_R9)    # fourth arg

        handled = False

        if rax == 0x19:  # NtQueryInformationProcess
            handled = self._handle_nt_query_info(uc, rdx, r8, r9)
        elif rax == 0x1A:  # NtSetInformationThread
            handled = self._handle_nt_set_info_thread(uc, rdx, r8)
        elif rax == 0x36:  # NtQuerySystemInformation
            handled = self._handle_nt_query_system_info(uc, rdx, r8)
        elif rax == 0x1F:  # NtQueryInformationThread
            handled = self._handle_nt_query_info_thread(uc, rdx, r8)
        elif rax == 0xC3:  # NtCreateThreadEx
            handled = self._handle_nt_create_thread(uc)

        if handled:
            self.stats["intercepted"] += 1
            if self.verbose:
                print(f"  [Syscall] {func_name} (0x{rax:x}) @ 0x{rip:x} -> HANDLED")
        else:
            self.stats["passthrough"] += 1
            if self.verbose and self.stats["passthrough"] <= 20:
                print(f"  [Syscall] {func_name} (0x{rax:x}) @ 0x{rip:x}")

        self.call_log.append({
            "rip": rip, "rax": rax, "name": func_name,
            "r10": r10, "rdx": rdx, "r8": r8, "handled": handled
        })

    def _handle_nt_query_info(self, uc, info_class: int, out_buf: int, out_len: int) -> bool:
        """NtQueryInformationProcess(0x19) — 拦截反调试查询

        RDX = ProcessInformationClass
        R8  = output buffer
        R9  = output length
        """
        if info_class in (0x07, 0x1E, 0x1F):  # DebugPort, DebugObjectHandle, DebugFlags
            # Write 0 to output buffer
            if out_buf and out_len >= 4:
                uc.mem_write(out_buf, struct.pack('<I', 0))
            # RAX = 0 (STATUS_SUCCESS), skip syscall
            uc.reg_write(UC_X86_REG_RAX, 0)
            self._skip_syscall(uc)
            return True
        return False

    def _handle_nt_set_info_thread(self, uc, info_class: int, info_ptr: int) -> bool:
        """NtSetInformationThread(0x1A) — 拦截 ThreadHideFromDebugger

        RDX = ThreadInformationClass (0x11 = ThreadHideFromDebugger)
        """
        if info_class == 0x11:
            # ThreadHideFromDebugger — just return success
            uc.reg_write(UC_X86_REG_RAX, 0)
            self._skip_syscall(uc)
            return True
        return False

    def _handle_nt_query_system_info(self, uc, info_class: int, out_buf: int) -> bool:
        """NtQuerySystemInformation(0x36) — 拦截内核调试器检测

        RDX = SystemInformationClass (0x23 = SystemKernelDebuggerInformation)
        """
        if info_class == 0x23 and out_buf:
            # Write: KdDebuggerEnabled=0, KdDebuggerNotPresent=1
            uc.mem_write(out_buf, bytes([0, 0, 1, 0]))
            uc.reg_write(UC_X86_REG_RAX, 0)
            self._skip_syscall(uc)
            return True
        return False

    def _handle_nt_query_info_thread(self, uc, info_class: int, out_buf: int) -> bool:
        """NtQueryInformationThread(0x1F) — 拦截线程调试信息查询

        RDX = ThreadInformationClass
        """
        if info_class == 0x11:  # ThreadHideFromDebugger check
            uc.mem_write(out_buf, bytes([0, 0, 0, 0]))
            uc.reg_write(UC_X86_REG_RAX, 0)
            self._skip_syscall(uc)
            return True
        return False

    def _handle_nt_create_thread(self, uc) -> bool:
        """NtCreateThreadEx(0xC3) — 记录线程创建, 不拦截"""
        # We don't block this — just track for multi-threading later
        return False

    @staticmethod
    def _skip_syscall(uc):
        """RIP += 2 (跳过 0F 05)"""
        rip = uc.reg_read(UC_X86_REG_RIP)
        uc.reg_write(UC_X86_REG_RIP, rip + 2)


def install_syscall_interceptor(uc: 'Uc', verbose: bool = False) -> SyscallInterceptor:
    """便捷函数: 安装 syscall 拦截器"""
    interceptor = SyscallInterceptor(uc, verbose)
    interceptor.install()
    return interceptor
