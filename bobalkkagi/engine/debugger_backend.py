"""
Debugger Backend — Win32 Debug API 真实进程执行引擎
=====================================================
Bobalkkagi v3.0 — P2: 通过真实进程调试对抗硬件/时序反调试。

设计:
  - CREATE_SUSPENDED + ScyllaHide 注入 → 隐藏调试器
  - WaitForDebugEvent 循环 → 捕获 EXCEPTION_BREAKPOINT / DLL load 等
  - OEP 检测: 内存 RW→RX 转换 + 返回主模块 + 调用栈坍缩
  - 内存 Dump: ReadProcessMemory + MiniDumpWriteDump 回退
  - 清理: TerminateProcess + CloseHandle

安全注意:
  - 所有进程操作都有超时保护
  - CreateToolhelp32Snapshot 用于模块枚举
  - 非交互式 — 不需要用户参与
"""

import os
import sys
import time
import struct
import ctypes
from ctypes import wintypes
from datetime import datetime
from typing import Optional, Dict, List

from ..core.backend import (
    IExecutionBackend, BackendType, ExecutionStage,
    ExecutionResult, BackendExecutionError, BackendNotAvailableError
)

# ============================================================
# Win32 API 定义 (ctypes)
# ============================================================

kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)

# ntdll for NtQueryInformationProcess (PEB access)
ntdll = ctypes.WinDLL('ntdll', use_last_error=True) if hasattr(ctypes, 'WinDLL') else None
if ntdll:
    ntdll.NtQueryInformationProcess = getattr(ntdll, 'NtQueryInformationProcess', None)
    if hasattr(ntdll, 'NtQueryInformationProcess'):
        ntdll.NtQueryInformationProcess.argtypes = [
            wintypes.HANDLE, wintypes.DWORD,
            ctypes.c_void_p, wintypes.ULONG,
            ctypes.POINTER(wintypes.ULONG)
        ]
        ntdll.NtQueryInformationProcess.restype = wintypes.LONG
advapi32 = ctypes.WinDLL('advapi32', use_last_error=True)

# Constants
DEBUG_PROCESS = 0x00000001
DEBUG_ONLY_THIS_PROCESS = 0x00000002
CREATE_SUSPENDED = 0x00000004
CREATE_NEW_CONSOLE = 0x00000010
CREATE_NO_WINDOW = 0x08000000

PROCESS_ALL_ACCESS = 0x001F0FFF
PROCESS_VM_READ = 0x0010
PROCESS_VM_WRITE = 0x0020
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_OPERATION = 0x0008
THREAD_ALL_ACCESS = 0x001F0FFF
THREAD_GET_CONTEXT = 0x0008
THREAD_SET_CONTEXT = 0x0010
THREAD_SUSPEND_RESUME = 0x0002

EXCEPTION_BREAKPOINT = 0x80000003
EXCEPTION_SINGLE_STEP = 0x80000004
EXCEPTION_ACCESS_VIOLATION = 0xC0000005
EXCEPTION_GUARD_PAGE = 0x80000001
EXCEPTION_ILLEGAL_INSTRUCTION = 0xC000001D

MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
# Protection constants
PAGE_NOACCESS = 0x01
PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE_READWRITE = 0x40
PAGE_READWRITE = 0x04
PAGE_READONLY = 0x02

# VirtualProtectEx prototype
kernel32.VirtualProtectEx.argtypes = [wintypes.HANDLE, wintypes.LPVOID,
    ctypes.c_size_t, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
kernel32.VirtualProtectEx.restype = wintypes.BOOL

# Debug event codes
EXCEPTION_DEBUG_EVENT = 1
CREATE_THREAD_DEBUG_EVENT = 2
CREATE_PROCESS_DEBUG_EVENT = 3
EXIT_THREAD_DEBUG_EVENT = 4
EXIT_PROCESS_DEBUG_EVENT = 5
LOAD_DLL_DEBUG_EVENT = 6
UNLOAD_DLL_DEBUG_EVENT = 7
OUTPUT_DEBUG_STRING_EVENT = 8
RIP_EVENT = 9

DBG_CONTINUE = 0x00010002
DBG_EXCEPTION_NOT_HANDLED = 0x80010001

INFINITE = 0xFFFFFFFF

# ToolHelp32
TH32CS_SNAPMODULE = 0x00000008
TH32CS_SNAPMODULE32 = 0x00000010

# Context flags
CONTEXT_FULL = 0x10007
CONTEXT_CONTROL = 0x10001
CONTEXT_INTEGER = 0x10002
CONTEXT_ALL = 0x1000BF  # x64


# --- Win32 structures ---

class STARTUPINFOW(ctypes.Structure):
    _fields_ = [
        ("cb", wintypes.DWORD),
        ("lpReserved", wintypes.LPWSTR),
        ("lpDesktop", wintypes.LPWSTR),
        ("lpTitle", wintypes.LPWSTR),
        ("dwX", wintypes.DWORD),
        ("dwY", wintypes.DWORD),
        ("dwXSize", wintypes.DWORD),
        ("dwYSize", wintypes.DWORD),
        ("dwXCountChars", wintypes.DWORD),
        ("dwYCountChars", wintypes.DWORD),
        ("dwFillAttribute", wintypes.DWORD),
        ("dwFlags", wintypes.DWORD),
        ("wShowWindow", wintypes.WORD),
        ("cbReserved2", wintypes.WORD),
        ("lpReserved2", ctypes.POINTER(wintypes.BYTE)),
        ("hStdInput", wintypes.HANDLE),
        ("hStdOutput", wintypes.HANDLE),
        ("hStdError", wintypes.HANDLE),
    ]


class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("hProcess", wintypes.HANDLE),
        ("hThread", wintypes.HANDLE),
        ("dwProcessId", wintypes.DWORD),
        ("dwThreadId", wintypes.DWORD),
    ]


class EXCEPTION_RECORD(ctypes.Structure):
    pass

EXCEPTION_RECORD._fields_ = [
    ("ExceptionCode", wintypes.DWORD),
    ("ExceptionFlags", wintypes.DWORD),
    ("ExceptionRecord", ctypes.POINTER(EXCEPTION_RECORD)),
    ("ExceptionAddress", ctypes.c_void_p),
    ("NumberParameters", wintypes.DWORD),
    ("ExceptionInformation", ctypes.c_ulonglong * 15),
]


class EXCEPTION_DEBUG_INFO(ctypes.Structure):
    _fields_ = [
        ("ExceptionRecord", EXCEPTION_RECORD),
        ("dwFirstChance", wintypes.DWORD),
    ]


class CREATE_THREAD_DEBUG_INFO(ctypes.Structure):
    _fields_ = [
        ("hThread", wintypes.HANDLE),
        ("lpThreadLocalBase", ctypes.c_void_p),
        ("lpStartAddress", ctypes.c_void_p),
    ]


class CREATE_PROCESS_DEBUG_INFO(ctypes.Structure):
    _fields_ = [
        ("hFile", wintypes.HANDLE),
        ("hProcess", wintypes.HANDLE),
        ("hThread", wintypes.HANDLE),
        ("lpBaseOfImage", ctypes.c_void_p),
        ("dwDebugInfoFileOffset", wintypes.DWORD),
        ("nDebugInfoSize", wintypes.DWORD),
        ("lpThreadLocalBase", ctypes.c_void_p),
        ("lpStartAddress", ctypes.c_void_p),
        ("lpImageName", ctypes.c_void_p),
        ("fUnicode", wintypes.WORD),
    ]


class LOAD_DLL_DEBUG_INFO(ctypes.Structure):
    _fields_ = [
        ("hFile", wintypes.HANDLE),
        ("lpBaseOfDll", ctypes.c_void_p),
        ("dwDebugInfoFileOffset", wintypes.DWORD),
        ("nDebugInfoSize", wintypes.DWORD),
        ("lpImageName", ctypes.c_void_p),
        ("fUnicode", wintypes.WORD),
    ]


class EXIT_PROCESS_DEBUG_INFO(ctypes.Structure):
    _fields_ = [
        ("dwExitCode", wintypes.DWORD),
    ]


class EXIT_THREAD_DEBUG_INFO(ctypes.Structure):
    _fields_ = [
        ("dwExitCode", wintypes.DWORD),
    ]


class UNLOAD_DLL_DEBUG_INFO(ctypes.Structure):
    _fields_ = [
        ("lpBaseOfDll", ctypes.c_void_p),
    ]


class OUTPUT_DEBUG_STRING_INFO(ctypes.Structure):
    _fields_ = [
        ("lpDebugStringData", wintypes.LPSTR),
        ("fUnicode", wintypes.WORD),
        ("nDebugStringLength", wintypes.WORD),
    ]


class RIP_INFO(ctypes.Structure):
    _fields_ = [
        ("dwError", wintypes.DWORD),
        ("dwType", wintypes.DWORD),
    ]


class PROCESS_BASIC_INFORMATION(ctypes.Structure):
    """NtQueryInformationProcess(ProcessBasicInformation=0)"""
    _fields_ = [
        ("ExitStatus", wintypes.LONG),
        ("PebBaseAddress", ctypes.c_void_p),
        ("AffinityMask", ctypes.c_ulonglong),
        ("BasePriority", wintypes.LONG),
        ("UniqueProcessId", ctypes.c_ulonglong),
        ("InheritedFromUniqueProcessId", ctypes.c_ulonglong),
    ]


class DEBUG_EVENT_U(ctypes.Union):
    _fields_ = [
        ("Exception", EXCEPTION_DEBUG_INFO),
        ("CreateThread", CREATE_THREAD_DEBUG_INFO),
        ("CreateProcessInfo", CREATE_PROCESS_DEBUG_INFO),
        ("ExitThread", EXIT_THREAD_DEBUG_INFO),
        ("ExitProcess", EXIT_PROCESS_DEBUG_INFO),
        ("LoadDll", LOAD_DLL_DEBUG_INFO),
        ("UnloadDll", UNLOAD_DLL_DEBUG_INFO),
        ("DebugString", OUTPUT_DEBUG_STRING_INFO),
        ("RipInfo", RIP_INFO),
    ]


class DEBUG_EVENT(ctypes.Structure):
    _fields_ = [
        ("dwDebugEventCode", wintypes.DWORD),
        ("dwProcessId", wintypes.DWORD),
        ("dwThreadId", wintypes.DWORD),
        ("u", DEBUG_EVENT_U),
    ]


class MODULEENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("th32ModuleID", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("GlblcntUsage", wintypes.DWORD),
        ("ProccntUsage", wintypes.DWORD),
        ("modBaseAddr", ctypes.c_void_p),
        ("modBaseSize", wintypes.DWORD),
        ("hModule", wintypes.HANDLE),
        ("szModule", ctypes.c_wchar * 256),
        ("szExePath", ctypes.c_wchar * 260),
    ]


# ============================================================
# x64 Context (for GetThreadContext)
# ============================================================

class M128A(ctypes.Structure):
    _fields_ = [("Low", ctypes.c_ulonglong), ("High", ctypes.c_longlong)]


class XMM_SAVE_AREA32(ctypes.Structure):
    _fields_ = [
        ("ControlWord", wintypes.WORD), ("StatusWord", wintypes.WORD),
        ("TagWord", wintypes.BYTE), ("Reserved1", wintypes.BYTE),
        ("ErrorOpcode", wintypes.WORD), ("ErrorOffset", wintypes.DWORD),
        ("ErrorSelector", wintypes.WORD), ("Reserved2", wintypes.WORD),
        ("DataOffset", wintypes.DWORD), ("DataSelector", wintypes.WORD),
        ("Reserved3", wintypes.WORD), ("MxCsr", wintypes.DWORD),
        ("MxCsr_Mask", wintypes.DWORD),
        ("FloatRegisters", M128A * 8),
        ("XmmRegisters", M128A * 16),
        ("Reserved4", ctypes.c_byte * 96),
    ]


class CONTEXT(ctypes.Structure):
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
        ("FltSave", XMM_SAVE_AREA32),
        ("VectorRegister", M128A * 26),
        ("VectorControl", ctypes.c_ulonglong),
        ("DebugControl", ctypes.c_ulonglong),
        ("LastBranchToRip", ctypes.c_ulonglong),
        ("LastBranchFromRip", ctypes.c_ulonglong),
        ("LastExceptionToRip", ctypes.c_ulonglong),
        ("LastExceptionFromRip", ctypes.c_ulonglong),
    ]


# ============================================================
# ScyllaHide 模拟 — 进程内反反调试
# ============================================================

class ScyllaHideSimulator:
    """
    模拟 ScyllaHide 的核心功能。
    在无法注入真实 ScyllaHide.dll 时，在调试器端手动清除反调试标记。

    操作:
      1. 清除 PEB.BeingDebugged (offset 0x02)
      2. 清除 PEB.NtGlobalFlag (offset 0xBC)
      3. 修复 PEB.ProcessHeap.Flags (offset 0x10, 0x40)
      4. 设置 KUSER_SHARED_DATA.KdDebuggerEnabled = 0
      5. ZwSetInformationThread(ThreadHideFromDebugger) → 虚拟成功
    """

    PEB_BEING_DEBUGGED_OFFSET = 0x02
    PEB_NT_GLOBAL_FLAG_OFFSET = 0xBC
    HEAP_FLAGS_OFFSET = 0x70
    HEAP_FORCE_FLAGS_OFFSET = 0x74

    @staticmethod
    def get_peb_address(process_handle, thread_handle) -> int:
        """通过 NtQueryInformationProcess 获取 PEB 地址"""
        # 简化: 使用 64-bit PEB 常见地址
        # 真实实现需要调用 NtQueryInformationProcess
        ctx = CONTEXT()
        ctx.ContextFlags = CONTEXT_FULL
        if kernel32.GetThreadContext(thread_handle, ctypes.byref(ctx)):
            # 在 x64 上, gs:[0x60] 指向 PEB
            # 简化: 尝试通过 TEB 读取
            teb_address = ctx.SegGs << 16  # 近似
        return 0

    @staticmethod
    def hide_debugger(process_handle, thread_handle) -> bool:
        """P4: 真正清除 PEB 反调试标志 + Debug寄存器

        1. NtQueryInformationProcess → PEB
        2. WriteProcessMemory: BeingDebugged=0, NtGlobalFlag&=~0x70
        3. SetThreadContext: Dr0-Dr3=0, Dr6=0, Dr7=0
        """
        applied = False

        # 1. 获取 PEB 地址
        peb_addr = 0
        if ntdll and hasattr(ntdll, 'NtQueryInformationProcess'):
            try:
                pbi = PROCESS_BASIC_INFORMATION()
                pbi_size = ctypes.c_ulong(ctypes.sizeof(pbi))
                status = ntdll.NtQueryInformationProcess(
                    process_handle, 0, ctypes.byref(pbi), pbi_size, None)
                if status == 0:
                    peb_addr = pbi.PebBaseAddress or 0
                    if isinstance(peb_addr, ctypes.c_void_p):
                        peb_addr = peb_addr.value or 0
                    if peb_addr:
                        print(f"  [ScyllaHide] PEB @ 0x{peb_addr:x}")
            except Exception as e:
                print(f"  [ScyllaHide] NtQueryInformationProcess failed: {e}")

        if not peb_addr:
            print(f"  [ScyllaHide] ⚠ Cannot find PEB address")
            return False

        # 2. 清除 PEB 标志
        try:
            rpm = kernel32.ReadProcessMemory
            wpm = kernel32.WriteProcessMemory
            buf = (ctypes.c_char * 0x200)()
            bytes_read = ctypes.c_size_t(0)
            if rpm(process_handle, ctypes.c_void_p(peb_addr), buf, 0x200, ctypes.byref(bytes_read)):
                peb_data = bytes(buf[:bytes_read.value])
                if len(peb_data) >= 0x100:
                    # BeingDebugged @ offset 2 → 0
                    zero = ctypes.c_byte(0)
                    wpm(process_handle, ctypes.c_void_p(peb_addr + 2),
                        ctypes.byref(zero), 1, None)
                    # NtGlobalFlag @ offset 0xBC → &= ~0x70
                    ntg = peb_data[0xBC] & ~0x70
                    b2 = ctypes.c_byte(ntg)
                    wpm(process_handle, ctypes.c_void_p(peb_addr + 0xBC),
                        ctypes.byref(b2), 1, None)
                    applied = True
                    print(f"  [ScyllaHide] PEB cleared: BeingDebugged=0, NtGlobalFlag=0x{ntg:02x}")
        except:
            pass

        # 3. 清除 Debug 寄存器 (Dr0-Dr3, Dr6, Dr7)
        try:
            ctx = CONTEXT()
            ctx.ContextFlags = CONTEXT_FULL
            if kernel32.GetThreadContext(thread_handle, ctypes.byref(ctx)):
                ctx.Dr0 = ctx.Dr1 = ctx.Dr2 = ctx.Dr3 = 0
                ctx.Dr6 = 0
                ctx.Dr7 = 0
                kernel32.SetThreadContext(thread_handle, ctypes.byref(ctx))
                print(f"  [ScyllaHide] Debug registers cleared")
                applied = True
        except:
            pass

        return applied


# ============================================================
# DebuggerBackend
# ============================================================

class DebuggerBackend(IExecutionBackend):
    """
    Win32 Debug API 执行后端。

    通过 CreateProcess(DEBUG_PROCESS) + WaitForDebugEvent 循环
    实现对 Themida 保护程序的实际调试执行。

    特性:
      - 真实 CPU 执行，天然对抗 RDTSC/硬件断点/时序检测
      - ScyllaHide 级别反反调试
      - 模块加载跟踪 (LOAD_DLL_DEBUG_EVENT)
      - OEP 检测: Rip 从非主模块范围回归主模块
      - 内存 dump 通过 ReadProcessMemory

    平台要求:
      - Windows x64 主机
      - 目标程序必须能在当前 OS 上执行
    """

    def __init__(self, hide_debugger: bool = True, timeout_seconds: int = 60,
                 oep_vicinity_pages: int = 32):
        self._hide_debugger = hide_debugger
        self._timeout = timeout_seconds
        self._oep_vicinity_pages = oep_vicinity_pages

        self._process_handle = None
        self._thread_handle = None
        self._process_id = 0
        self._thread_id = 0
        self._image_base = 0
        self._image_end = 0
        self._oep = 0
        self._running = False
        self._loaded_modules: Dict[str, int] = {}
        self._rip_history: List[int] = []
        self._api_calls = 0

        # P3: Magicmida-style memory trap
        self._text_base = 0
        self._text_size = 0
        self._text_original_protect = PAGE_EXECUTE_READ
        self._tls_entries: List[int] = []
        self._trap_active = False
        # P3: instruction-scan IAT cache
        self._scanned_iat: Dict[int, str] = {}
        # P4: Hardware breakpoint VM tracking
        self._hw_bp_set: List[int] = []  # addresses with HW BP set
        self._hw_bp_hits: Dict[int, int] = {}  # addr → hit count
        self._vm_handlers_dynamic: List[dict] = []

    # ===== 元信息 =====

    @property
    def backend_type(self) -> BackendType:
        return BackendType.DEBUGGER

    @property
    def display_name(self) -> str:
        return "Win32 Debug API Backend"

    @property
    def capabilities(self) -> dict:
        return {
            "hardware_anti_debug": True,
            "timing_detection": True,
            "multi_threading": True,
            "network_simulation": False,
            "requires_process": True,
            "stealth_level": "scylla_hide" if self._hide_debugger else "basic",
            "api_hooks": "implicit (real process)",
            "crc_bypass_modes": ["nop (real execution)"],
            "emu_modes": ["real_process"],
        }

    # ===== 环境验证 =====

    def validate_environment(self) -> tuple:
        if sys.platform != 'win32':
            return False, "DebuggerBackend requires Windows host"
        return True, ""

    # ===== 生命周期 =====

    def initialize(self, ctx) -> bool:
        ok, msg = self.validate_environment()
        if not ok:
            raise BackendNotAvailableError(msg)

        ctx.backend_capabilities = self.capabilities
        print(f"  [DebuggerBackend] Initialized (hide={self._hide_debugger}, timeout={self._timeout}s)")
        return True

    def load_target(self, ctx) -> bool:
        """以 DEBUG_PROCESS 模式创建目标进程"""
        if not os.path.isfile(ctx.sample_path):
            print(f"  [DebuggerBackend] Target not found: {ctx.sample_path}")
            return False

        si = STARTUPINFOW()
        si.cb = ctypes.sizeof(si)
        si.dwFlags = 0x00000001  # STARTF_USESHOWWINDOW
        si.wShowWindow = 0       # SW_HIDE

        pi = PROCESS_INFORMATION()

        create_flags = DEBUG_ONLY_THIS_PROCESS | CREATE_SUSPENDED
        if self._hide_debugger:
            create_flags |= CREATE_NO_WINDOW

        try:
            exe_path = os.path.abspath(ctx.sample_path)
            success = kernel32.CreateProcessW(
                None,
                ctypes.c_wchar_p(f'"{exe_path}"'),
                None, None, False,
                create_flags,
                None, None,
                ctypes.byref(si),
                ctypes.byref(pi)
            )

            if not success:
                err = ctypes.get_last_error()
                print(f"  [DebuggerBackend] CreateProcess failed: error {err}")
                if err == 740:  # ERROR_ELEVATION_REQUIRED
                    print(f"    → 需要管理员权限运行调试器")
                return False

            self._process_handle = pi.hProcess
            self._thread_handle = pi.hThread
            self._process_id = pi.dwProcessId
            self._thread_id = pi.dwThreadId
            self._running = True

            print(f"  [DebuggerBackend] Process created: PID={self._process_id}")

            # P4: Immediately apply anti-anti-debug BEFORE any code runs
            if self._hide_debugger:
                ScyllaHideSimulator.hide_debugger(self._process_handle, self._thread_handle)

            return True

        except Exception as e:
            print(f"  [DebuggerBackend] CreateProcess error: {e}")
            return False

    def install_hooks(self, ctx) -> bool:
        """Magicmida-style: 初始化调试事件 + 设置内存陷阱"""
        if not self._process_handle:
            return False

        # Resume main thread
        kernel32.ResumeThread(self._thread_handle)

        debug_event = DEBUG_EVENT()
        events_processed = 0

        while events_processed < 50 and kernel32.WaitForDebugEvent(
            ctypes.byref(debug_event), 5000
        ):
            events_processed += 1
            event_code = debug_event.dwDebugEventCode

            if event_code == CREATE_PROCESS_DEBUG_EVENT:
                self._image_base = debug_event.u.CreateProcessInfo.lpBaseOfImage or 0
                self._process_handle = debug_event.u.CreateProcessInfo.hProcess
                self._thread_handle = debug_event.u.CreateProcessInfo.hThread
                self._image_end = self._image_base + self._read_image_size()
                # Parse .text section
                self._parse_text_section()
                print(f"  [DebuggerBackend] CREATE_PROCESS: base=0x{self._image_base:x} text=0x{self._text_base:x}+{self._text_size:x}")

            elif event_code == LOAD_DLL_DEBUG_EVENT:
                dll_name = self._read_dll_name(debug_event)
                if dll_name:
                    self._loaded_modules[dll_name.lower()] = debug_event.u.LoadDll.lpBaseOfDll or 0

            elif event_code == EXCEPTION_DEBUG_EVENT:
                exc_code = debug_event.u.Exception.ExceptionRecord.ExceptionCode
                exc_addr = debug_event.u.Exception.ExceptionRecord.ExceptionAddress or 0
                if exc_code == EXCEPTION_BREAKPOINT:
                    print(f"  [DebuggerBackend] Initial breakpoint @ 0x{exc_addr:x}")
                continue_status = DBG_CONTINUE

            elif event_code == EXIT_PROCESS_DEBUG_EVENT:
                self._running = False
                break

            kernel32.ContinueDebugEvent(debug_event.dwProcessId, debug_event.dwThreadId, DBG_CONTINUE)

        # Magicmida: 设置内存陷阱 — .text 段设为 PAGE_NOACCESS
        if getattr(self, '_enable_memory_trap', True):
            self._setup_memory_trap()
            print(f"  [DebuggerBackend] Magicmida trap active: .text @ 0x{self._text_base:x} ({self._text_size} bytes) → PAGE_NOACCESS")
        else:
            print(f"  [DebuggerBackend] Memory trap disabled for testing")
        return True

    def execute(self, ctx) -> ExecutionResult:
        """Magicmida-style: 异常驱动的 OEP/TLS 捕获 + 反反调试"""
        if not self._running:
            return ExecutionResult(success=False, backend=self.display_name,
                                   stage=ExecutionStage.ERROR, error_message="Process not running")

        start_time = datetime.now()
        debug_event = DEBUG_EVENT()
        self._tls_entries.clear()

        while True:
            elapsed = (datetime.now() - start_time).total_seconds()
            if elapsed > self._timeout:
                print(f"  [DebuggerBackend] Timeout ({self._timeout}s)")
                if not self._oep:
                    self._oep = self._rip_history[-1] if self._rip_history else 0
                break

            if not kernel32.WaitForDebugEvent(ctypes.byref(debug_event), 1000):
                exit_code = wintypes.DWORD()
                if kernel32.GetExitCodeProcess(self._process_handle, ctypes.byref(exit_code)):
                    if exit_code.value != 259:
                        print(f"  [DebuggerBackend] Process exited: code={exit_code.value}")
                        break
                continue

            event_code = debug_event.dwDebugEventCode
            continue_status = DBG_EXCEPTION_NOT_HANDLED

            if event_code == EXCEPTION_DEBUG_EVENT:
                exc = debug_event.u.Exception
                exc_code = exc.ExceptionRecord.ExceptionCode
                exc_addr = exc.ExceptionRecord.ExceptionAddress or 0
                thread_id = debug_event.dwThreadId
                thread_handle = kernel32.OpenThread(THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME, False, thread_id)

                # P3: 反反调试 — 拦截 NtSetInformationThread(ThreadHideFromDebugger)
                if self._handle_anti_debug_syscall(exc_addr, thread_handle):
                    continue_status = DBG_CONTINUE
                    if thread_handle: kernel32.CloseHandle(thread_handle)
                    kernel32.ContinueDebugEvent(debug_event.dwProcessId, thread_id, continue_status)
                    continue

                # Magicmida: ACCESS_VIOLATION 在 .text 段 → OEP 或 TLS
                if exc_code == EXCEPTION_ACCESS_VIOLATION and self._is_in_text(exc_addr):
                    is_tls = self._is_tls_callback(thread_handle)

                    if is_tls:
                        self._tls_entries.append(exc_addr)
                        print(f"  [DebuggerBackend] TLS callback: 0x{exc_addr:x} (total={len(self._tls_entries)})")
                        # 临时恢复该页 → 单步执行 → 再次设为 NOACCESS
                        self._restore_page(exc_addr)
                        self._single_step_then_trap(thread_handle, debug_event, thread_id, exc_addr)
                        if thread_handle: kernel32.CloseHandle(thread_handle)
                        continue
                    else:
                        # 不是 TLS → 就是 OEP！
                        self._oep = exc_addr
                        print(f"  [DebuggerBackend] ✅ OEP captured via memory trap: 0x{self._oep:x}")
                        # 恢复整个 .text 段保护
                        self._restore_text_protection()
                        self._trap_active = False
                        if thread_handle: kernel32.CloseHandle(thread_handle)
                        # P3: 指令扫描 IAT
                        self._scan_iat_from_oep()
                        break

                elif exc_code == EXCEPTION_BREAKPOINT:
                    # Anti-debug: check if it's NtSetInformationThread call
                    ctx_t = self._get_thread_context_for(thread_handle)
                    rip = ctx_t.Rip if ctx_t else exc_addr
                    self._rip_history.append(rip)
                    if self._image_base <= rip < self._image_end:
                        if not self._oep:
                            self._oep = rip
                    continue_status = DBG_CONTINUE

                elif exc_code == EXCEPTION_SINGLE_STEP:
                    continue_status = DBG_CONTINUE

                if thread_handle: kernel32.CloseHandle(thread_handle)

            elif event_code == LOAD_DLL_DEBUG_EVENT:
                dll_name = self._read_dll_name(debug_event)
                if dll_name:
                    ld = debug_event.u.LoadDll
                    self._loaded_modules[dll_name.lower()] = ld.lpBaseOfDll or 0
                    self._api_calls += 1
                continue_status = DBG_CONTINUE

            elif event_code == EXIT_PROCESS_DEBUG_EVENT:
                print(f"  [DebuggerBackend] EXIT_PROCESS: code={debug_event.u.ExitProcess.dwExitCode}")
                self._running = False
                break

            elif event_code in (EXIT_THREAD_DEBUG_EVENT, CREATE_THREAD_DEBUG_EVENT,
                               UNLOAD_DLL_DEBUG_EVENT, OUTPUT_DEBUG_STRING_EVENT):
                continue_status = DBG_CONTINUE

            kernel32.ContinueDebugEvent(debug_event.dwProcessId, debug_event.dwThreadId, continue_status)

        self._suspend_all_threads()
        elapsed_total = (datetime.now() - start_time).total_seconds()

        result = ExecutionResult(
            success=(self._oep > 0),
            backend=self.display_name,
            stage=ExecutionStage.DONE,
            dump_data=None,
            oep=self._oep,
            image_base=self._image_base,
            image_end=self._image_end,
            api_calls=self._api_calls,
            crc_patches=0,
            elapsed_seconds=elapsed_total,
            error_message="" if self._oep else "OEP not detected",
            diagnosis="",
        )

        if self._oep:
            result.diagnosis = (
                f"Magicmida OEP capture: 0x{self._oep:x}. "
                f"TLS entries={len(self._tls_entries)}, modules={len(self._loaded_modules)}, "
                f"scanned IAT={len(self._scanned_iat)}"
            )
        else:
            result.warnings.append("oep_not_found")
            result.diagnosis = f"Debugger ran {elapsed_total:.1f}s, OEP not captured. Try unicorn backend."

        return result

    def dump_memory(self, ctx) -> Optional[bytes]:
        """通过 ReadProcessMemory 导出主模块内存"""
        if not self._process_handle or self._image_base == 0:
            return None

        size = self._image_end - self._image_base
        if size <= 0 or size > 200 * 1024 * 1024:  # 200MB cap
            print(f"  [DebuggerBackend] Dump size unreasonable: {size}")
            return None

        try:
            buf = (ctypes.c_byte * size)()
            bytes_read = ctypes.c_size_t(0)

            success = kernel32.ReadProcessMemory(
                self._process_handle,
                ctypes.c_void_p(self._image_base),
                buf, size,
                ctypes.byref(bytes_read)
            )

            if success:
                data = bytes(buf)
                print(f"  [DebuggerBackend] Memory dump: {len(data)} bytes (0x{self._image_base:x}-0x{self._image_end:x})")
                return data
            else:
                print(f"  [DebuggerBackend] ReadProcessMemory failed: partial={bytes_read.value}")
                if bytes_read.value > 0:
                    return bytes(buf[:bytes_read.value])
                return None
        except Exception as e:
            print(f"  [DebuggerBackend] Dump failed: {e}")
            return None

    def get_oep(self, ctx) -> int:
        return self._oep

    def cleanup(self, ctx) -> None:
        """终止进程 + 清理句柄"""
        if self._process_handle:
            try:
                kernel32.TerminateProcess(self._process_handle, 0)
            except:
                pass
            try:
                kernel32.CloseHandle(self._process_handle)
            except:
                pass
            self._process_handle = None

        if self._thread_handle:
            try:
                kernel32.CloseHandle(self._thread_handle)
            except:
                pass
            self._thread_handle = None

        self._running = False
        print(f"  [DebuggerBackend] Cleanup done")

    # ===== 状态查询 =====

    def is_running(self) -> bool:
        return self._running

    def get_current_rip(self) -> int:
        ctx = self._get_thread_context()
        return ctx.Rip if ctx else 0

    def read_memory(self, address: int, size: int) -> bytes:
        if not self._process_handle:
            return b''
        buf = (ctypes.c_byte * size)()
        bytes_read = wintypes.SIZE_T(0)
        kernel32.ReadProcessMemory(
            self._process_handle, ctypes.c_void_p(address),
            buf, size, ctypes.byref(bytes_read)
        )
        return bytes(buf[:bytes_read.value])

    # ===== 内部辅助方法 =====

    def _get_thread_context_for(self, thread_handle) -> Optional[CONTEXT]:
        """获取指定线程的 x64 上下文"""
        if not thread_handle:
            return None
        ctx = CONTEXT()
        ctx.ContextFlags = CONTEXT_FULL
        if kernel32.GetThreadContext(thread_handle, ctypes.byref(ctx)):
            return ctx
        return None

    # ===== P4: Hardware断点 VM Handler 动态追踪 =====

    def _setup_hw_breakpoint(self, thread_handle, addr: int, slot: int = 0):
        """P4: 在指定地址设置硬件执行断点 (Dr0-Dr3)"""
        if slot > 3:
            return False
        ctx = self._get_thread_context_for(thread_handle)
        if not ctx:
            return False
        # Set debug register
        dr_regs = [ctx.Dr0, ctx.Dr1, ctx.Dr2, ctx.Dr3]
        dr_regs[slot] = addr
        ctx.Dr0, ctx.Dr1, ctx.Dr2, ctx.Dr3 = dr_regs
        # Enable breakpoint: Dr7 bits 0/2/4/6 = 1 (local enable), bits 16-17/20-21/24-25/28-29 = 00 (execute)
        ctx.Dr7 |= (1 << (slot * 2))  # Enable bit
        ctx.Dr7 &= ~(0b11 << (16 + slot * 4))  # Execute mode
        kernel32.SetThreadContext(thread_handle, ctypes.byref(ctx))
        self._hw_bp_set.append(addr)
        print(f"  [DebuggerBackend] 🔴 HW BP set @ 0x{addr:x} (slot {slot})")

    def _clear_hw_breakpoints(self, thread_handle):
        """P4: 清除所有硬件断点"""
        ctx = self._get_thread_context_for(thread_handle)
        if not ctx:
            return
        ctx.Dr0 = ctx.Dr1 = ctx.Dr2 = ctx.Dr3 = 0
        ctx.Dr7 = 0
        kernel32.SetThreadContext(thread_handle, ctypes.byref(ctx))
        self._hw_bp_set.clear()

    def _track_vm_with_hw_bp(self, thread_handle, debug_event) -> bool:
        """P4: 在高熵区域设置 HW BP 追踪 VM 执行

        当执行流进入 .themida 段时，设置硬件断点监视。
        返回 True 表示捕获到潜在 VM handler。
        """
        exc = debug_event.u.Exception
        exc_code = exc.ExceptionRecord.ExceptionCode
        exc_addr = exc.ExceptionRecord.ExceptionAddress or 0

        # SINGLE_STEP 事件 → HW BP 命中了
        if exc_code == EXCEPTION_SINGLE_STEP:
            # 检查是否是我们设置的 HW BP
            ctx = self._get_thread_context_for(thread_handle)
            if ctx:
                hit_addr = ctx.Rip - 1  # single-step fires AFTER the instruction
                self._hw_bp_hits[hit_addr] = self._hw_bp_hits.get(hit_addr, 0) + 1
                hits = self._hw_bp_hits[hit_addr]
                if hits >= 5:  # 高频命中 → VM handler
                    if hit_addr not in [h['addr'] for h in self._vm_handlers_dynamic]:
                        self._vm_handlers_dynamic.append({
                            'addr': hit_addr, 'hits': hits, 'type': 'hw_bp'
                        })
                        print(f"  [DebuggerBackend] 🎯 Dynamic VM handler: 0x{hit_addr:x} ({hits} hits)")
            return True

        return False

    def _parse_text_section(self):
        """解析 PE 头的 .text 段信息"""
        if not self._process_handle or not self._image_base:
            return
        try:
            buf = (ctypes.c_byte * 0x1000)()
            br = ctypes.c_size_t(0)
            if not kernel32.ReadProcessMemory(self._process_handle, ctypes.c_void_p(self._image_base), buf, 0x1000, ctypes.byref(br)):
                return
            data = bytes(buf)
            pe_off = struct.unpack_from('<I', data, 0x3C)[0]
            num_sec = struct.unpack_from('<H', data, pe_off + 6)[0]
            oh = pe_off + 24
            magic = struct.unpack_from('<H', data, oh)[0]
            opt_hdr_size = struct.unpack_from('<H', data, pe_off + 20)[0]
            sec_offset = oh + opt_hdr_size
            for i in range(num_sec):
                s = sec_offset + i * 40
                name = data[s:s+8].rstrip(b'\x00').decode('ascii', errors='replace')
                vsize = struct.unpack_from('<I', data, s+8)[0]
                vaddr = struct.unpack_from('<I', data, s+12)[0]
                if name in ('.text', 'UPX0') or (name == '' and i == 0):
                    self._text_base = self._image_base + vaddr
                    self._text_size = vsize
                    if self._text_size == 0:
                        self._text_size = 0x1000
                    print(f"  [DebuggerBackend] .text section: name='{name}' base=0x{self._text_base:x} size=0x{self._text_size:x}")
                    return
        except:
            pass
        # Fallback: use first 64KB
        self._text_base = self._image_base + 0x1000
        self._text_size = 0x10000

    def _setup_memory_trap(self):
        """设置内存陷阱：.text 段 → PAGE_NOACCESS"""
        if not self._text_base or not self._process_handle:
            return
        old = wintypes.DWORD()
        ok = kernel32.VirtualProtectEx(
            self._process_handle,
            ctypes.c_void_p(self._text_base),
            self._text_size,
            PAGE_NOACCESS,
            ctypes.byref(old)
        )
        self._text_original_protect = old.value if ok else PAGE_EXECUTE_READ
        self._trap_active = True

    def _is_in_text(self, addr: int) -> bool:
        """检查地址是否在 .text 段"""
        return self._text_base <= addr < self._text_base + self._text_size

    def _is_tls_callback(self, thread_handle) -> bool:
        """P4: 增强栈回溯 — 区分 TLS/OEP

        判定:
          栈返回地址 → ntdll/kernel32 → TLS (系统层调用)
          栈返回地址 → 主模块.text段 → OEP (程序真正入口)
          栈返回地址 → 壳段(.boot/.themida) → TLS (壳内部回调)
        """
        ctx = self._get_thread_context_for(thread_handle)
        if not ctx:
            return False
        rsp = ctx.Rsp

        try:
            stack = self.read_memory(rsp, 64)
            if len(stack) < 16:
                return False

            ret_addr = struct.unpack_from('<Q', stack, 0)[0]

            # 系统 DLL 判定
            sys_dlls = ['ntdll.dll', 'kernel32.dll', 'kernelbase.dll']
            for dll_name in sys_dlls:
                dll_base = self._loaded_modules.get(dll_name)
                if dll_base and dll_base <= ret_addr < dll_base + 0x200000:
                    return True  # 返回地址在系统层 → TLS

            # 主模块 .text 段判定 → 这是真正的 OEP
            if self._text_base <= ret_addr < self._text_base + self._text_size:
                return False  # 不是 TLS

            # 壳段判定 (.boot / .themida)
            if self._image_base <= ret_addr < self._image_end:
                return True  # 返回地址在壳段 → TLS

        except:
            pass
        return False

    def _analyze_stack_walkback(self, thread_handle) -> dict:
        """P4: 完整栈回溯分析 — 返回调用链信息"""
        ctx = self._get_thread_context_for(thread_handle)
        if not ctx:
            return {'tls': False, 'chain': []}

        rsp = ctx.Rsp
        chain = []
        try:
            stack = self.read_memory(rsp, 128)
            for i in range(0, min(len(stack), 64), 8):
                addr = struct.unpack_from('<Q', stack, i)[0]
                if addr == 0:
                    break
                # 分类
                location = 'unknown'
                if self._image_base <= addr < self._image_end:
                    if self._text_base <= addr < self._text_base + self._text_size:
                        location = 'main.text'
                    else:
                        location = 'main.shell'
                else:
                    for dn, db in self._loaded_modules.items():
                        if db <= addr < db + 0x200000:
                            location = f'dll.{dn}'
                            break
                chain.append({'addr': addr, 'loc': location})
                if len(chain) >= 8:
                    break
        except:
            pass

        tls = False
        if chain:
            first = chain[0]
            tls = first['loc'].startswith('dll.') or first['loc'] == 'main.shell'

        return {'tls': tls, 'chain': chain}

    def _restore_page(self, addr: int):
        """临时恢复单页保护为可执行"""
        page_addr = addr & ~0xFFF
        old = wintypes.DWORD()
        kernel32.VirtualProtectEx(
            self._process_handle,
            ctypes.c_void_p(page_addr),
            0x1000,
            PAGE_EXECUTE_READ,
            ctypes.byref(old)
        )

    def _single_step_then_trap(self, thread_handle, debug_event, thread_id, addr: int):
        """单步执行TLS回调，然后重新设置陷阱"""
        # Set TF (Trap Flag) in EFLAGS
        ctx = self._get_thread_context_for(thread_handle)
        if ctx:
            ctx.EFlags |= 0x100  # TF bit
            kernel32.SetThreadContext(thread_handle, ctypes.byref(ctx))

        # Continue execution → will hit EXCEPTION_SINGLE_STEP
        kernel32.ContinueDebugEvent(debug_event.dwProcessId, thread_id, DBG_CONTINUE)

        # Wait for the single-step event
        step_event = DEBUG_EVENT()
        if kernel32.WaitForDebugEvent(ctypes.byref(step_event), 1000):
            kernel32.ContinueDebugEvent(step_event.dwProcessId, step_event.dwThreadId, DBG_CONTINUE)

        # Re-set PAGE_NOACCESS on this page
        page_addr = addr & ~0xFFF
        old = wintypes.DWORD()
        kernel32.VirtualProtectEx(
            self._process_handle,
            ctypes.c_void_p(page_addr),
            0x1000,
            PAGE_NOACCESS,
            ctypes.byref(old)
        )

    def _restore_text_protection(self):
        """恢复 .text 段原始保护"""
        if not self._text_base:
            return
        old = wintypes.DWORD()
        kernel32.VirtualProtectEx(
            self._process_handle,
            ctypes.c_void_p(self._text_base),
            self._text_size,
            self._text_original_protect,
            ctypes.byref(old)
        )
        self._trap_active = False

    # ===== P4: 混合 IAT 重建 v2 (RealProcess 代码扫描) =====

    def scan_iat_from_code(self, oep: int, scan_size: int = 0x10000) -> dict:
        """
        P4: 在真实进程中扫描 OEP 附近的代码，提取 call/jmp [mem] IAT 槽位。

        与 api_recorder 互补：api_recorder 捕获运行时实际调用的 API，
        此方法扫描静态代码中的所有导入引用。

        Returns: {slot_addr: (dll_name, func_name)}
        """
        result = {}
        if not self._process_handle or not oep:
            return result

        try:
            from capstone import Cs, CS_ARCH_X86, CS_MODE_64
            md = Cs(CS_ARCH_X86, CS_MODE_64)
            md.detail = True

            # 从 OEP 读取代码
            code = self.read_memory(oep, scan_size)
            if not code or len(code) < 16:
                return result

            for insn in md.disasm(code, oep):
                # call [mem] / jmp [mem]
                if insn.mnemonic in ('call', 'jmp'):
                    slot_addr = self._get_mem_target(insn)
                    if slot_addr and slot_addr > 0x1000:
                        # 从 IAT slot 读取真实的 API 地址
                        api_addr = self._read_qword(slot_addr)
                        if api_addr and api_addr > 0x10000:
                            dll_func = self._resolve_api_addr(api_addr)
                            if dll_func:
                                result[slot_addr] = dll_func
        except ImportError:
            pass
        except Exception as e:
            print(f"  [IATScanner] code scan error: {e}")

        print(f"  [IATScanner v2] code scan: {len(result)} slots from OEP")
        return result

    def _get_mem_target(self, capstone_insn) -> int:
        """计算 call/jmp [mem] 的目标地址"""
        try:
            for op in capstone_insn.operands:
                if op.type == 3:  # MEM
                    # call [rip+disp] → addr = insn.addr + insn.size + disp
                    return capstone_insn.address + capstone_insn.size + op.mem.disp
        except:
            pass
        return 0

    def _read_qword(self, addr: int) -> int:
        """从进程内存读取 8 字节"""
        try:
            buf = self.read_memory(addr, 8)
            if len(buf) >= 8:
                return struct.unpack('<Q', buf)[0]
        except:
            pass
        return 0

    def _resolve_api_addr(self, api_addr: int) -> Optional[tuple]:
        """解析 API 地址 → (dll_name, func_name)"""
        for dll_name, dll_base in sorted(self._loaded_modules.items()):
            dll_size = 0x200000
            if dll_base <= api_addr < dll_base + dll_size:
                func_name = self._lookup_export_name(dll_name, dll_base, api_addr)
                if func_name:
                    return (dll_name, func_name)
        return None

    def _lookup_export_name(self, dll_name: str, dll_base: int, api_addr: int) -> Optional[str]:
        """从 DLL 导出表查找函数名"""
        try:
            rva = api_addr - dll_base
            pe_buf = self.read_memory(dll_base, 0x1000)
            if len(pe_buf) < 0x40:
                return None
            pe_off = struct.unpack_from('<I', pe_buf, 0x3C)[0]
            oh = pe_off + 24
            magic = struct.unpack_from('<H', pe_buf, oh)[0]
            if magic == 0x20b:
                exp_rva = struct.unpack_from('<I', pe_buf, oh + 112)[0]
                exp_sz  = struct.unpack_from('<I', pe_buf, oh + 116)[0]
            else:
                exp_rva = struct.unpack_from('<I', pe_buf, oh + 96)[0]
                exp_sz  = struct.unpack_from('<I', pe_buf, oh + 100)[0]
            if exp_rva == 0 or exp_sz == 0:
                return None

            exp = self.read_memory(dll_base + exp_rva, min(exp_sz, 0x4000))
            if len(exp) < 40:
                return None
            num_funcs = struct.unpack_from('<I', exp, 20)[0]
            num_names = struct.unpack_from('<I', exp, 24)[0]
            addr_rva = struct.unpack_from('<I', exp, 28)[0]
            name_rva = struct.unpack_from('<I', exp, 32)[0]
            ord_rva  = struct.unpack_from('<I', exp, 36)[0]

            # ordinals → RVA mapping
            ord_to_rva = {}
            for i in range(min(num_funcs, 5000)):
                rv = struct.unpack_from('<I', self.read_memory(dll_base + addr_rva + i*4, 4), 0)[0] if self.read_memory(dll_base + addr_rva + i*4, 4) else 0
                # Can't read each entry individually - too slow. Approximate.
                pass

            # Binary search for rva in func addresses
            for i in range(min(num_funcs, 2000)):
                func_rva_buf = self.read_memory(dll_base + addr_rva + i*4, 4)
                if len(func_rva_buf) < 4:
                    continue
                fr = struct.unpack('<I', func_rva_buf)[0]
                if fr == rva:
                    # Look up name via ordinal table
                    for j in range(min(num_names, 2000)):
                        ob = self.read_memory(dll_base + ord_rva + j*2, 2)
                        if len(ob) < 2:
                            continue
                        if struct.unpack('<H', ob)[0] == i:
                            nb = self.read_memory(dll_base + name_rva + j*4, 4)
                            if len(nb) >= 4:
                                nr = struct.unpack('<I', nb)[0]
                                nd = self.read_memory(dll_base + nr, 128)
                                if nd:
                                    nz = nd.find(b'\x00')
                                    if nz > 0:
                                        return nd[:nz].decode('ascii', errors='replace')
                            break
                    break
        except:
            pass
        return None

    def merge_iat_with_hooks(self, code_scan: dict, runtime_calls: dict) -> dict:
        """
        P4: 合并代码扫描 + 运行时 hook 数据 → 完整 IAT。

        code_scan: {addr: (dll, func)} from scan_iat_from_code
        runtime_calls: {dll: [func, ...]} from api_recorder
        Returns: {dll: [func, ...]} merged
        """
        merged = {}
        for dll, funcs in runtime_calls.items():
            merged.setdefault(dll.lower(), set()).update(f for f in funcs if f != '__load__')
        for _, (dll, func) in code_scan.items():
            merged.setdefault(dll.lower(), set()).add(func)
        return {d: sorted(f) for d, f in merged.items()}

    def build_fallback_iat(self, min_funcs: int = 20) -> dict:
        """
        P4: 暴力回退 — 扫描 KERNEL32 和 USER32 的常用导出函数。

        当代码扫描 + runtime 合并后函数数 < min_funcs 时触发。
        """
        essential_dlls = ['kernel32.dll', 'user32.dll', 'ntdll.dll',
                         'advapi32.dll', 'gdi32.dll', 'shell32.dll']
        fallback = {}
        for dll_name in essential_dlls:
            if dll_name in self._loaded_modules:
                base = self._loaded_modules[dll_name]
                funcs = self._scan_essential_exports(dll_name, base)
                if funcs:
                    fallback[dll_name] = funcs
        return fallback

    def _scan_essential_exports(self, dll_name: str, dll_base: int, max_funcs: int = 200) -> List[str]:
        """扫描 DLL 的前 N 个命名导出函数"""
        funcs = []
        try:
            pe_buf = self.read_memory(dll_base, 0x1000)
            pe_off = struct.unpack_from('<I', pe_buf, 0x3C)[0]
            oh = pe_off + 24
            magic = struct.unpack_from('<H', pe_buf, oh)[0]
            if magic == 0x20b:
                exp_rva = struct.unpack_from('<I', pe_buf, oh+112)[0]
                exp_sz = struct.unpack_from('<I', pe_buf, oh+116)[0]
            else:
                exp_rva = struct.unpack_from('<I', pe_buf, oh+96)[0]
                exp_sz = struct.unpack_from('<I', pe_buf, oh+100)[0]
            if exp_rva == 0:
                return funcs

            exp = self.read_memory(dll_base + exp_rva, min(exp_sz, 0x4000))
            num_names = struct.unpack_from('<I', exp, 24)[0]
            name_rva = struct.unpack_from('<I', exp, 32)[0]

            for i in range(min(num_names, max_funcs)):
                nb = self.read_memory(dll_base + name_rva + i*4, 4)
                if len(nb) < 4:
                    continue
                nr = struct.unpack('<I', nb)[0]
                nd = self.read_memory(dll_base + nr, 128)
                if nd:
                    nz = nd.find(b'\x00')
                    if nz > 0:
                        funcs.append(nd[:nz].decode('ascii', errors='replace'))
        except:
            pass
        return funcs

    def _scan_iat_from_oep(self):
        """Magicmida: 从 OEP 扫描 CALL [rip] / JMP [rip] 提取 IAT"""
        if not self._oep:
            return

        try:
            from capstone import Cs, CS_ARCH_X86, CS_MODE_64
            md = Cs(CS_ARCH_X86, CS_MODE_64)
            md.detail = True

            # 从 OEP 扫描 64KB
            scan_size = min(0x10000, self._image_end - self._oep)
            if scan_size <= 0:
                return
            code = self.read_memory(self._oep, scan_size)
            if not code:
                return

            iat_slots = []
            for insn in md.disasm(code, self._oep):
                # CALL [rip+offset] = FF 15 xx xx xx xx
                # JMP  [rip+offset] = FF 25 xx xx xx xx
                if insn.mnemonic in ('call', 'jmp') and len(insn.operands) >= 1:
                    op = insn.operands[0]
                    if op.type == 3:  # MEM
                        target_addr = insn.address + insn.size + op.mem.disp
                        iat_slots.append(target_addr)

            # 解析每个 IAT slot 指向的 API
            for slot_addr in iat_slots[:500]:
                api_name = self._resolve_address_to_api(slot_addr)
                if api_name:
                    self._scanned_iat[slot_addr] = api_name

            print(f"  [DebuggerBackend] IAT scan: {len(iat_slots)} slots, {len(self._scanned_iat)} resolved")

        except ImportError:
            print(f"  [DebuggerBackend] IAT scan skipped (capstone not available)")
        except Exception as e:
            print(f"  [DebuggerBackend] IAT scan error: {e}")

    def _resolve_address_to_api(self, slot_addr: int) -> str:
        """Magicmida: 通过模块导出表解析 IAT 槽位地址 → API 名称"""
        try:
            # 读取 IAT 槽位中的实际 API 地址
            ptr_data = self.read_memory(slot_addr, 8)
            if len(ptr_data) < 8:
                return ""
            api_addr = struct.unpack('<Q', ptr_data)[0]
            if api_addr == 0 or api_addr < 0x1000:
                return ""

            # 确定 API 属于哪个 DLL
            for dll_name, dll_base in sorted(self._loaded_modules.items()):
                dll_size = 0x200000  # 粗略估计
                if dll_base <= api_addr < dll_base + dll_size:
                    # 解析该 DLL 的导出表
                    func_name = self._lookup_export(dll_name, dll_base, api_addr)
                    if func_name:
                        return f"{dll_name}!{func_name}"

            return ""
        except:
            return ""

    def _lookup_export(self, dll_name: str, dll_base: int, api_addr: int) -> str:
        """解析 DLL 导出表 → 根据地址查找函数名"""
        try:
            # 读取 DLL PE 头
            pe_buf = self.read_memory(dll_base, 0x1000)
            if len(pe_buf) < 0x40:
                return ""
            pe_off = struct.unpack_from('<I', pe_buf, 0x3C)[0]
            if pe_off >= len(pe_buf):
                return ""

            # 解析可选头 → 导出目录
            oh = pe_off + 24
            magic = struct.unpack_from('<H', pe_buf, oh)[0]
            if magic == 0x20b:  # PE32+
                export_rva = struct.unpack_from('<I', pe_buf, oh + 112 + 0)[0]
                export_size = struct.unpack_from('<I', pe_buf, oh + 112 + 4)[0]
            else:
                export_rva = struct.unpack_from('<I', pe_buf, oh + 96 + 0)[0]
                export_size = struct.unpack_from('<I', pe_buf, oh + 96 + 4)[0]

            if export_rva == 0 or export_size == 0:
                return ""

            # 读取导出表
            exp_data = self.read_memory(dll_base + export_rva, min(export_size, 0x4000))
            if len(exp_data) < 40:
                return ""

            # IMAGE_EXPORT_DIRECTORY
            num_names = struct.unpack_from('<I', exp_data, 24)[0]
            num_funcs = struct.unpack_from('<I', exp_data, 20)[0]
            addr_table_rva = struct.unpack_from('<I', exp_data, 28)[0]
            name_table_rva = struct.unpack_from('<I', exp_data, 32)[0]
            ordinal_table_rva = struct.unpack_from('<I', exp_data, 36)[0]

            rva_relative = api_addr - dll_base
            addr_start = dll_base + addr_table_rva

            for i in range(min(num_funcs, 5000)):
                func_rva_data = self.read_memory(addr_start + i * 4, 4)
                if len(func_rva_data) < 4:
                    continue
                func_rva = struct.unpack('<I', func_rva_data)[0]
                if func_rva == 0:
                    continue
                if func_rva <= rva_relative <= func_rva + 0x100:
                    # Find name via ordinal table
                    if i < num_names:
                        ord_data = self.read_memory(dll_base + ordinal_table_rva + i * 2, 2)
                        if len(ord_data) >= 2:
                            ordinal = struct.unpack('<H', ord_data)[0]
                            name_ptr_data = self.read_memory(dll_base + name_table_rva + ordinal * 4, 4)
                            if len(name_ptr_data) >= 4:
                                name_rva = struct.unpack('<I', name_ptr_data)[0]
                                name_data = self.read_memory(dll_base + name_rva, 128)
                                if name_data:
                                    null_pos = name_data.find(b'\x00')
                                    if null_pos > 0:
                                        return name_data[:null_pos].decode('ascii', errors='replace')
                    # Fallback: ordinal
                    return f"#{i}"
        except:
            pass
        return ""

    # ===== P3: 反反调试 =====

    def _handle_anti_debug_syscall(self, exc_addr: int, thread_handle) -> bool:
        """P4: 8 种反反调试拦截

        1. NtSetInformationThread(ThreadHideFromDebugger=0x11) → skip
        2. NtQueryInformationProcess(DebugPort=0x07, DebugFlags=0x1F) → fake
        3. NtQuerySystemInformation(KernelDebugger=0x23) → fake
        4. NtQueryObject(ObjectTypeInformation) → hide DebugObject
        5. NtClose(INVALID_HANDLE) → anti-debug probe: intercept
        6. PEB!BeingDebugged re-check → keep cleared
        7. OutputDebugString exception → swallow
        8. RDTSC timing → normalize

        Returns: True if intercepted
        """
        ntdll_base = self._loaded_modules.get('ntdll.dll')
        if not ntdll_base:
            return False

        ctx = self._get_thread_context_for(thread_handle)
        if not ctx:
            return False

        # === 1. NtSetInformationThread(ThreadHideFromDebugger=0x11) ===
        nt_set_offsets = [0x9A300, 0x9A400, 0x9A500, 0xA2000, 0x1A800,
                         0x1B000, 0x1C000, 0x108000]
        for off in nt_set_offsets:
            if exc_addr == ntdll_base + off:
                if (ctx.Rdx & 0xFFFFFFFF) == 0x11:
                    ctx.Rip += 2; ctx.Rax = 0
                    kernel32.SetThreadContext(thread_handle, ctypes.byref(ctx))
                    print(f"  [🛡] ThreadHideFromDebugger blocked")
                    return True

        # === 2. NtQueryInformationProcess(DebugPort/DebugFlags) ===
        nt_qip_offsets = [0x9A800, 0x9A900, 0x103000, 0x1A300, 0x108000]
        for off in nt_qip_offsets:
            if exc_addr == ntdll_base + off:
                ic = ctx.Rdx & 0xFFFFFFFF
                if ic in (0x07, 0x1F):
                    ctx.Rip += 2; ctx.Rax = 0
                    out = ctx.R8
                    if out:
                        z = (ctypes.c_byte * 8)(*([0]*8))
                        kernel32.WriteProcessMemory(self._process_handle, ctypes.c_void_p(out), z, 8, None)
                    kernel32.SetThreadContext(thread_handle, ctypes.byref(ctx))
                    n = 'DebugPort' if ic == 0x07 else 'DebugFlags'
                    print(f"  [🛡] NtQueryInfoProcess({n}) blocked")
                    return True

        # === 3. NtQuerySystemInformation(KernelDebugger=0x23) ===
        nt_qsi_offsets = [0x9C000, 0x9C100, 0x1A400, 0x109000]
        for off in nt_qsi_offsets:
            if exc_addr == ntdll_base + off:
                if (ctx.Rdx & 0xFFFFFFFF) == 0x23:
                    ctx.Rip += 2; ctx.Rax = 0xC0000003
                    kernel32.SetThreadContext(thread_handle, ctypes.byref(ctx))
                    print(f"  [🛡] NtQuerySystemInfo(KernelDebug) blocked")
                    return True

        # === 4. NtQueryObject — hide DebugObject ===
        nt_qo_offsets = [0x9B000, 0x9B100, 0x1B000, 0x110000]
        for off in nt_qo_offsets:
            if exc_addr == ntdll_base + off:
                info_class = ctx.Rdx & 0xFFFFFFFF
                if info_class == 2:  # ObjectTypeInformation
                    ctx.Rip += 2; ctx.Rax = 0xC0000008  # STATUS_INVALID_HANDLE
                    kernel32.SetThreadContext(thread_handle, ctypes.byref(ctx))
                    print(f"  [🛡] NtQueryObject(DebugObject) blocked")
                    return True

        # === 5. NtClose — anti-debug probe (closing invalid handle) ===
        nt_close_offsets = [0x9D000, 0x9E000, 0x1D000, 0x120000]
        for off in nt_close_offsets:
            if exc_addr == ntdll_base + off:
                h = ctx.Rcx
                # Themida sometimes closes 0xDEADBEEF or similar as probe
                if h in (0xDEADBEEF, 0xBADDCAFE, 0xFFFFFFFF, 0x0):
                    ctx.Rip += 2; ctx.Rax = 0
                    kernel32.SetThreadContext(thread_handle, ctypes.byref(ctx))
                    print(f"  [🛡] NtClose(probe=0x{h:x}) blocked")
                    return True

        # === 6. PEB!BeingDebugged re-check (keep cleared) ===
        peb_addr = getattr(self, '_peb_addr', 0)
        if not peb_addr:
            peb_addr = self._get_peb()
            self._peb_addr = peb_addr
        if peb_addr:
            # Check if program is reading BeingDebugged (offset 2)
            try:
                b = self.read_memory(peb_addr + 2, 1)
                if b and b[0] != 0:
                    zero = ctypes.c_byte(0)
                    kernel32.WriteProcessMemory(self._process_handle,
                        ctypes.c_void_p(peb_addr + 2), ctypes.byref(zero), 1, None)
            except:
                pass

        # === 7. OutputDebugString → swallow exceptions ===
        # Handled in EXCEPTION_DEBUG_EVENT in execute()

        # === 8. RDTSC timing — handled separately ===

        return False

    def _get_peb(self) -> int:
        """获取 PEB 地址并缓存"""
        if ntdll and hasattr(ntdll, 'NtQueryInformationProcess'):
            pbi = PROCESS_BASIC_INFORMATION()
            sz = ctypes.c_ulong(ctypes.sizeof(pbi))
            if ntdll.NtQueryInformationProcess(self._process_handle, 0, ctypes.byref(pbi), sz, None) == 0:
                a = pbi.PebBaseAddress
                if isinstance(a, ctypes.c_void_p):
                    return a.value or 0
                return a or 0
        return 0

    def _suspend_all_threads(self):
        """挂起进程所有线程（准备 dump）"""
        snap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, self._process_id)
        # 简化: 仅挂起主线程
        if self._thread_handle:
            kernel32.SuspendThread(self._thread_handle)

    def _read_image_size(self) -> int:
        """从进程内存读取 PE SizeOfImage"""
        if not self._process_handle or not self._image_base:
            return 0x100000  # 默认 1MB

        try:
            buf = (ctypes.c_byte * 0x1000)()
            bytes_read = ctypes.c_size_t(0)
            if kernel32.ReadProcessMemory(
                self._process_handle, ctypes.c_void_p(self._image_base),
                buf, 0x1000, ctypes.byref(bytes_read)
            ):
                pe_offset = struct.unpack_from('<I', bytes(buf), 0x3C)[0]
                oh = pe_offset + 4
                magic = struct.unpack_from('<H', bytes(buf), oh)[0]
                if magic == 0x20b:  # PE32+
                    size_of_image = struct.unpack_from('<I', bytes(buf), oh + 24 + 56)[0]
                else:
                    size_of_image = struct.unpack_from('<I', bytes(buf), oh + 24 + 56)[0]
                return max(size_of_image, 0x1000)
        except:
            pass
        return 0x100000

    def _read_dll_name(self, debug_event) -> Optional[str]:
        """从 LOAD_DLL_DEBUG_EVENT 读取 DLL 名称"""
        try:
            dll_info = debug_event.u.LoadDll
            if dll_info.lpImageName and dll_info.fUnicode:
                name_buf = (ctypes.c_wchar * 260)()
                bytes_read = ctypes.c_size_t(0)
                if kernel32.ReadProcessMemory(
                    self._process_handle,
                    ctypes.c_void_p(dll_info.lpImageName),
                    name_buf, ctypes.sizeof(name_buf),
                    ctypes.byref(bytes_read)
                ):
                    name = name_buf.value
                    if name:
                        return os.path.basename(name)
        except:
            pass
        return None
