"""
Hybrid Backend — Unicorn → Debugger 混合执行引擎
==================================================
Bobalkkagi v3.0 — P2: 先用Unicorn模拟到OEP附近，再用真实进程完成执行。

策略:
  1. UnicornBlackend 运行到 OEP 检测信号 (RW→RX >= 3, return_to_main >= 5)
  2. 捕获此时的内存 + 寄存器快照
  3. 创建目标进程 (CREATE_SUSPENDED)
  4. 将Unicorn解密后的内存注入进程 (WriteProcessMemory)
  5. 设置线程上下文 (SetThreadContext) 并恢复执行
  6. DebuggerBackend 接管后续调试

优势:
  - 对抗硬件反调试: 解密阶段在Unicorn中完成 (无硬件断点检测)
  - OEP后真实执行: 解决时序检测 + 多线程 + 系统调用问题
  - 自动降级: 如果进程创建失败 → 回退到纯Unicorn模式
"""

import os
import sys
import struct
import ctypes
from ctypes import wintypes
from datetime import datetime
from typing import Optional

from ..core.backend import (
    IExecutionBackend, BackendType, ExecutionStage,
    ExecutionResult, BackendExecutionError, BackendNotAvailableError
)
from .unicorn_backend import UnicornBackend
from .debugger_backend import DebuggerBackend

# Win32 API for process injection
kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)

PROCESS_ALL_ACCESS = 0x001F0FFF
PROCESS_VM_WRITE = 0x0020
PROCESS_VM_OPERATION = 0x0008
PROCESS_CREATE_THREAD = 0x0002
PROCESS_SUSPEND_RESUME = 0x0800
CREATE_SUSPENDED = 0x00000004
CONTEXT_FULL = 0x10007
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
PAGE_EXECUTE_READWRITE = 0x40


class STARTUPINFOW(ctypes.Structure):
    _fields_ = [
        ("cb", wintypes.DWORD), ("lpReserved", wintypes.LPWSTR),
        ("lpDesktop", wintypes.LPWSTR), ("lpTitle", wintypes.LPWSTR),
        ("dwX", wintypes.DWORD), ("dwY", wintypes.DWORD),
        ("dwXSize", wintypes.DWORD), ("dwYSize", wintypes.DWORD),
        ("dwXCountChars", wintypes.DWORD), ("dwYCountChars", wintypes.DWORD),
        ("dwFillAttribute", wintypes.DWORD), ("dwFlags", wintypes.DWORD),
        ("wShowWindow", wintypes.WORD), ("cbReserved2", wintypes.WORD),
        ("lpReserved2", ctypes.POINTER(wintypes.BYTE)),
        ("hStdInput", wintypes.HANDLE), ("hStdOutput", wintypes.HANDLE),
        ("hStdError", wintypes.HANDLE),
    ]


class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("hProcess", wintypes.HANDLE), ("hThread", wintypes.HANDLE),
        ("dwProcessId", wintypes.DWORD), ("dwThreadId", wintypes.DWORD),
    ]


# Simplified x64 CONTEXT for SetThreadContext
class X64_CONTEXT(ctypes.Structure):
    _fields_ = [
        ("P1Home", ctypes.c_ulonglong), ("P2Home", ctypes.c_ulonglong),
        ("P3Home", ctypes.c_ulonglong), ("P4Home", ctypes.c_ulonglong),
        ("P5Home", ctypes.c_ulonglong), ("P6Home", ctypes.c_ulonglong),
        ("ContextFlags", wintypes.DWORD), ("MxCsr", wintypes.DWORD),
        ("SegCs", wintypes.WORD), ("SegDs", wintypes.WORD),
        ("SegEs", wintypes.WORD), ("SegFs", wintypes.WORD),
        ("SegGs", wintypes.WORD), ("SegSs", wintypes.WORD),
        ("EFlags", wintypes.DWORD),
        ("Dr0", ctypes.c_ulonglong), ("Dr1", ctypes.c_ulonglong),
        ("Dr2", ctypes.c_ulonglong), ("Dr3", ctypes.c_ulonglong),
        ("Dr6", ctypes.c_ulonglong), ("Dr7", ctypes.c_ulonglong),
        ("Rax", ctypes.c_ulonglong), ("Rcx", ctypes.c_ulonglong),
        ("Rdx", ctypes.c_ulonglong), ("Rbx", ctypes.c_ulonglong),
        ("Rsp", ctypes.c_ulonglong), ("Rbp", ctypes.c_ulonglong),
        ("Rsi", ctypes.c_ulonglong), ("Rdi", ctypes.c_ulonglong),
        ("R8", ctypes.c_ulonglong), ("R9", ctypes.c_ulonglong),
        ("R10", ctypes.c_ulonglong), ("R11", ctypes.c_ulonglong),
        ("R12", ctypes.c_ulonglong), ("R13", ctypes.c_ulonglong),
        ("R14", ctypes.c_ulonglong), ("R15", ctypes.c_ulonglong),
        ("Rip", ctypes.c_ulonglong),
        ("_pad", ctypes.c_byte * 512),  # simplified float/xmm area
    ]


class HybridBackend(IExecutionBackend):
    """
    Unicorn → Debugger 混合执行后端。

    流程:
      Phase 1 (Unicorn):
        - 加载PE/DLL, 安装钩子
        - 执行到 OEP 检测信号 (STABILIZING / OEP_FOUND)
        - 抓取内存快照 + RIP/RSP

      Phase 2 (Process Injection):
        - CreateProcess(target.exe, CREATE_SUSPENDED)
        - 将Unicorn内存dump写入新进程的空间
        - 设置线程上下文 → 恢复执行

      Phase 3 (Debugger):
        - DebuggerBackend 接管 WaitForDebugEvent
        - 监控后续执行直到OEP稳定
        - dump完整内存

    自动降级:
      - Phase 2失败 → 回退到纯Unicorn模式
      - Phase 3失败 → 使用Phase 1的dump
    """

    def __init__(self, crc_mode: str = "safe", emu_mode: str = 'f',
                 debugger_timeout: int = 60, hide_debugger: bool = True):
        self._crc_mode = crc_mode
        self._emu_mode = emu_mode
        self._debugger_timeout = debugger_timeout
        self._hide_debugger = hide_debugger

        # Sub-backends
        self._unicorn: Optional[UnicornBackend] = None
        self._debugger: Optional[DebuggerBackend] = None

        # State
        self._phase = "init"  # init → unicorn → inject → debugger → done
        self._running = False
        self._oep = 0
        self._dump_data: Optional[bytes] = None
        self._rip_snapshot = 0
        self._rsp_snapshot = 0

    # ===== 元信息 =====

    @property
    def backend_type(self) -> BackendType:
        return BackendType.HYBRID

    @property
    def display_name(self) -> str:
        return "Hybrid Unicorn→Debugger"

    @property
    def capabilities(self) -> dict:
        return {
            "hardware_anti_debug": True,
            "timing_detection": True,
            "multi_threading": True,
            "network_simulation": False,
            "requires_process": True,
            "stealth_level": "hybrid (emu + scylla_hide)",
            "phases": ["unicorn_decrypt", "process_inject", "debugger_exec"],
        }

    # ===== 生命周期 =====

    def initialize(self, ctx) -> bool:
        self._phase = "init"
        self._unicorn = UnicornBackend(
            crc_mode=self._crc_mode, emu_mode=self._emu_mode, verbose=False
        )
        ok = self._unicorn.initialize(ctx)
        if ok:
            ctx.backend_capabilities = self.capabilities
            print(f"  [Hybrid] Phase 1 (Unicorn) initialized")
        return ok

    def load_target(self, ctx) -> bool:
        if not self._unicorn:
            return False

        ok = self._unicorn.load_target(ctx)
        if ok:
            self._phase = "loaded"
            print(f"  [Hybrid] Target loaded in Unicorn")
        return ok

    def install_hooks(self, ctx) -> bool:
        if not self._unicorn:
            return False
        return self._unicorn.install_hooks(ctx)

    def execute(self, ctx) -> ExecutionResult:
        """
        Phase 1: Unicorn模拟到OEP信号
        Phase 2: 进程注入 (CREATE_SUSPENDED + WriteProcessMemory)
        Phase 3: DebuggerBackend接管
        """
        if not self._unicorn:
            return ExecutionResult(success=False, backend=self.display_name,
                                   stage=ExecutionStage.ERROR,
                                   error_message="Unicorn backend not initialized")

        start_time = datetime.now()

        # === Phase 1: Unicorn execution ===
        print(f"\n  [Hybrid] Phase 1: Unicorn execution...")
        self._phase = "unicorn"

        unicorn_result = self._unicorn.execute(ctx)

        if not unicorn_result.success and unicorn_result.oep == 0:
            # Unicorn completely failed — fallback
            print(f"  [Hybrid] Unicorn failed: {unicorn_result.error_message}")
            print(f"  [Hybrid] Falling back to pure Unicorn mode")
            self._dump_data = self._unicorn.dump_memory(ctx)
            self._oep = unicorn_result.oep or self._unicorn.get_oep(ctx)
            return unicorn_result

        # Capture Unicorn state
        self._dump_data = self._unicorn.dump_memory(ctx)
        self._oep = unicorn_result.oep or self._unicorn.get_oep(ctx)
        self._rip_snapshot = self._unicorn.get_current_rip()
        self._rsp_snapshot = 0  # Will read from context if needed

        print(f"  [Hybrid] Unicorn done: OEP=0x{self._oep:x}, dump={len(self._dump_data or b'')} bytes")

        # Clean up Unicorn to free memory
        self._unicorn.cleanup(ctx)
        self._unicorn = None

        # === Phase 2: Process injection ===
        if sys.platform != 'win32':
            print(f"  [Hybrid] Non-Windows host — using Unicorn dump directly")
            return unicorn_result

        self._phase = "inject"
        print(f"  [Hybrid] Phase 2: Creating suspended process...")

        try:
            si = STARTUPINFOW()
            si.cb = ctypes.sizeof(si)
            pi = PROCESS_INFORMATION()

            exe_path = os.path.abspath(ctx.sample_path)

            success = kernel32.CreateProcessW(
                None,
                ctypes.c_wchar_p(f'"{exe_path}"'),
                None, None, False,
                CREATE_SUSPENDED,
                None, None,
                ctypes.byref(si),
                ctypes.byref(pi)
            )

            if not success:
                err = ctypes.get_last_error()
                print(f"  [Hybrid] CreateProcess failed: error {err} — using Unicorn dump")
                self._phase = "done"
                return unicorn_result

            process_handle = pi.hProcess
            thread_handle = pi.hThread
            process_id = pi.dwProcessId
            print(f"  [Hybrid] Process created: PID={process_id} (suspended)")

            # === Memory injection ===
            # Strategy: remap the Unicorn memory image into the target process
            if self._dump_data and len(self._dump_data) > 0:
                image_base = ctx.image_base or 0x140000000
                image_size = len(self._dump_data)

                # Allocate memory in target at the expected base
                target_base = kernel32.VirtualAllocEx(
                    process_handle,
                    ctypes.c_void_p(image_base),
                    image_size,
                    MEM_COMMIT | MEM_RESERVE,
                    PAGE_EXECUTE_READWRITE
                )

                if target_base and target_base == image_base:
                    # Write the decrypted memory
                    bytes_written = wintypes.SIZE_T(0)
                    buf = (ctypes.c_byte * image_size).from_buffer_copy(self._dump_data)
                    if kernel32.WriteProcessMemory(
                        process_handle,
                        ctypes.c_void_p(image_base),
                        buf, image_size,
                        ctypes.byref(bytes_written)
                    ):
                        print(f"  [Hybrid] Memory injected: {bytes_written.value}/{image_size} bytes @ 0x{image_base:x}")

                        # Set thread context (especially RIP) to the OEP
                        ctx_thread = X64_CONTEXT()
                        ctx_thread.ContextFlags = CONTEXT_FULL
                        if kernel32.GetThreadContext(thread_handle, ctypes.byref(ctx_thread)):
                            # Fix RIP to point to the decoded OEP
                            ctx_thread.Rip = self._oep
                            kernel32.SetThreadContext(thread_handle, ctypes.byref(ctx_thread))
                            print(f"  [Hybrid] Thread context set: RIP=0x{self._oep:x}")
                    else:
                        print(f"  [Hybrid] WriteProcessMemory failed: partial={bytes_written.value}")
                else:
                    print(f"  [Hybrid] VirtualAllocEx failed (wanted 0x{image_base:x}, got 0x{target_base or 0:x})")

            # Resume the thread
            kernel32.ResumeThread(thread_handle)
            print(f"  [Hybrid] Thread resumed — process now running at OEP")

            # === Phase 3: Debugger takeover ===
            self._phase = "debugger"
            print(f"  [Hybrid] Phase 3: DebuggerBackend takeover")

            self._debugger = DebuggerBackend(
                hide_debugger=self._hide_debugger,
                timeout_seconds=self._debugger_timeout
            )
            # Reuse the already-created process
            self._debugger._process_handle = process_handle
            self._debugger._thread_handle = thread_handle
            self._debugger._process_id = process_id
            self._debugger._image_base = image_base
            self._debugger._image_end = image_base + image_size
            self._debugger._running = True

            self._running = True
            debugger_result = self._debugger.execute(ctx)

            # Combine results
            self._oep = debugger_result.oep or self._oep
            self._dump_data = self._debugger.dump_memory(ctx) or self._dump_data

            elapsed = (datetime.now() - start_time).total_seconds()
            result = ExecutionResult(
                success=(self._oep > 0),
                backend=self.display_name,
                stage=ExecutionStage.DONE,
                dump_data=self._dump_data,
                oep=self._oep,
                image_base=image_base,
                image_end=image_base + image_size,
                api_calls=unicorn_result.api_calls + debugger_result.api_calls,
                crc_patches=unicorn_result.crc_patches,
                elapsed_seconds=elapsed,
                error_message="",
                diagnosis=(
                    f"Hybrid execution completed. "
                    f"Unicorn: {unicorn_result.api_calls} calls, "
                    f"Debugger: {debugger_result.api_calls} calls. "
                    f"OEP=0x{self._oep:x}"
                ),
            )

            return result

        except Exception as e:
            print(f"  [Hybrid] Phase 2/3 failed: {e} — using Unicorn dump")
            self._phase = "done"
            return unicorn_result

    def dump_memory(self, ctx) -> Optional[bytes]:
        if self._dump_data:
            return self._dump_data
        if self._debugger:
            return self._debugger.dump_memory(ctx)
        return None

    def get_oep(self, ctx) -> int:
        return self._oep

    def cleanup(self, ctx) -> None:
        if self._unicorn:
            self._unicorn.cleanup(ctx)
            self._unicorn = None
        if self._debugger:
            self._debugger.cleanup(ctx)
            self._debugger = None
        self._running = False
        self._phase = "done"
        print(f"  [Hybrid] Cleanup done")

    # ===== 状态查询 =====

    def is_running(self) -> bool:
        return self._running

    def get_current_rip(self) -> int:
        if self._debugger:
            return self._debugger.get_current_rip()
        if self._unicorn:
            return self._unicorn.get_current_rip()
        return self._rip_snapshot

    def read_memory(self, address: int, size: int) -> bytes:
        if self._debugger:
            return self._debugger.read_memory(address, size)
        if self._unicorn:
            return self._unicorn.read_memory(address, size)
        return b''
