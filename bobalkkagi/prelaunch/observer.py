"""
Environment Observation Layer — V5: 反反调试决策链观察器
===========================================================
Bobalkkagi V5.0 — 先观测，后绕过。

核心问题：
  进程在 CREATE_PROCESS_DEBUG_EVENT 之前就退出
  → 检测发生在 Windows Loader 初始化阶段
  → 传统调试器看不到任何事件

解决方案：
  CREATE_SUSPENDED → 快照环境 → 设置 HW BP → Resume → 记录一切

观察点:
  1. PEB 快照 (BeingDebugged, NtGlobalFlag, ProcessHeap, Ldr)
  2. Entry Point 是否被命中 (HW BP @ OEP)
  3. 进程退出码 (0 = 主动退出, 非0 = 崩溃)
  4. 中间异常事件
"""

import ctypes
import ctypes.wintypes as wintypes
import struct
import time
from typing import Dict, List, Optional, Tuple


class EnvironmentObserver:
    """
    环境观察器 — 记录进程启动阶段的完整反调试检测链。

    用法:
      observer = EnvironmentObserver("sample.exe")
      report = observer.observe()
      → report 包含完整决策链
    """

    def __init__(self, exe_path: str):
        self.exe_path = exe_path
        self._k32 = ctypes.windll.kernel32
        self._nt = ctypes.windll.ntdll

        # Observation log
        self._timeline: List[dict] = []
        self._peb_snapshot: dict = {}
        self._hproc = None
        self._hthread = None
        self._pid = 0
        self._image_base = 0
        self._oep = 0

    def _log(self, phase: str, event: str, data: dict = None):
        entry = {
            "timestamp": time.time(),
            "phase": phase,
            "event": event,
            "data": data or {}
        }
        self._timeline.append(entry)
        print(f"  [Observe|{phase}] {event}")

    def _read_mem(self, addr, size: int) -> bytes:
        buf = (ctypes.c_char * size)()
        rd = ctypes.c_size_t(0)
        if self._k32.ReadProcessMemory(self._hproc, ctypes.c_void_p(addr),
                                        buf, size, ctypes.byref(rd)):
            return bytes(buf[:rd.value])
        return b''

    def _write_mem(self, addr, data: bytes):
        self._k32.WriteProcessMemory(self._hproc, ctypes.c_void_p(addr),
                                      data, len(data), None)

    def observe(self) -> dict:
        """
        启动进程 → 快照环境 → 设置BP → Resume → 记录 → 报告

        Returns: 完整观察报告
        """
        self._log("init", "Starting observation")

        # Step 1: Create SUSPENDED
        if not self._create_suspended():
            return {"error": "Failed to create process"}

        # Step 2: Snapshot PEB
        self._snapshot_peb()

        # Step 3: Read PE headers for OEP
        self._read_oep()

        # Step 4: Set HW BP at OEP
        self._set_hw_bp_at_oep()

        # Step 5: Resume and observe
        self._resume_and_observe()

        # Step 6: Report
        return self._build_report()

    def _create_suspended(self) -> bool:
        """CREATE_SUSPENDED 启动进程"""
        si = STARTUPINFOW()
        pi = PROCESS_INFORMATION()

        ok = self._k32.CreateProcessW(
            None, self.exe_path, None, None, False,
            0x00000004,  # CREATE_SUSPENDED
            None, None, ctypes.byref(si), ctypes.byref(pi))

        if not ok:
            self._log("error", f"CreateProcess failed: {ctypes.get_last_error()}")
            return False

        self._hproc = pi.hProcess
        self._hthread = pi.hThread
        self._pid = pi.dwProcessId
        self._log("init", f"Process created: PID={self._pid}, SUSPENDED")
        return True

    def _snapshot_peb(self):
        """快照 PEB 初始状态"""
        peb = self._get_peb_addr()
        if not peb:
            self._log("peb", "PEB not accessible")
            return

        data = self._read_mem(peb, 0x200)
        if len(data) < 0x100:
            return

        snapshot = {
            "peb_addr": peb,
            "being_debugged": data[2],
            "nt_global_flag": data[0xBC],
            "image_base": struct.unpack_from("<Q", data, 0x10)[0],
            "ldr": struct.unpack_from("<Q", data, 0x18)[0],
            "process_heap": struct.unpack_from("<Q", data, 0x30)[0],
        }

        # Heap flags
        heap = snapshot["process_heap"]
        if heap and heap > 0x10000:
            hd = self._read_mem(heap, 0x20)
            if len(hd) >= 0x18:
                snapshot["heap_flags"] = struct.unpack_from("<I", hd, 0x14)[0]
                snapshot["heap_force_flags"] = struct.unpack_from("<I", hd, 0x18)[0]

        # KUSER
        kuser = self._read_mem(0x7FFE0000, 0x300)
        if len(kuser) >= 0x300:
            snapshot["kd_debugger_enabled"] = kuser[0x2F4]
            snapshot["kd_debugger_not_present"] = kuser[0x2F8]

        self._peb_snapshot = snapshot
        self._image_base = snapshot["image_base"]
        self._log("peb", "Snapshot captured",
                  {"BeingDebugged": snapshot["being_debugged"],
                   "NtGlobalFlag": f"0x{snapshot['nt_global_flag']:02x}",
                   "HeapFlags": f"0x{snapshot.get('heap_flags',0):08x}",
                   "KdDebugEnabled": snapshot.get("kd_debugger_enabled", "?")})

    def _read_oep(self):
        """从 PE 头读取 Entry Point"""
        if not self._image_base:
            return
        pe_buf = self._read_mem(self._image_base, 0x1000)
        if len(pe_buf) < 0x200:
            return
        pe_off = struct.unpack_from("<I", pe_buf, 0x3C)[0]
        oh = pe_off + 24
        self._oep = self._image_base + struct.unpack_from("<I", pe_buf, oh + 16)[0]
        self._log("pe", f"OEP = 0x{self._oep:x}")

    def _set_hw_bp_at_oep(self):
        """在 OEP 设置硬件执行断点"""
        if not self._oep or not self._hthread:
            return

        ctx = CONTEXT()
        ctx.ContextFlags = 0x10007
        if not self._k32.GetThreadContext(self._hthread, ctypes.byref(ctx)):
            self._log("hwbp", "GetThreadContext failed")
            return

        ctx.Dr0 = self._oep
        ctx.Dr7 = (ctx.Dr7 & ~0xFF) | 0x01  # Enable Dr0, local, execute
        self._k32.SetThreadContext(self._hthread, ctypes.byref(ctx))
        self._log("hwbp", f"Hardware BP set @ 0x{self._oep:x} (Dr0)")

    def _resume_and_observe(self):
        """Resume 进程 → WaitForDebugEvent → 记录直到退出"""
        self._k32.ResumeThread(self._hthread)
        self._log("exec", "Process resumed — observing...")

        start = time.time()
        timeout = 30  # 30 second timeout

        while True:
            if time.time() - start > timeout:
                self._log("timeout", "Observation timeout")
                break

            de = DEBUG_EVENT()
            if not self._k32.WaitForDebugEvent(ctypes.byref(de), 100):
                continue

            tid = de.dwThreadId
            code = de.dwDebugEventCode

            if code == 1:  # EXCEPTION
                exc = de.u.Exception
                exc_code = exc.ExceptionRecord.ExceptionCode
                exc_addr = exc.ExceptionRecord.ExceptionAddress or 0

                if exc_code == 0x80000004:  # SINGLE_STEP (HW BP hit)
                    self._log("trap", f"HW BP HIT @ 0x{exc_addr:x}! OEP reached!",
                              {"oep": hex(exc_addr), "type": "hardware_breakpoint"})

                elif exc_code == 0x80000003:  # BREAKPOINT (initial)
                    self._log("init", f"Initial breakpoint @ 0x{exc_addr:x}")

                elif exc_code == 0xC0000005:  # ACCESS_VIOLATION
                    self._log("trap", f"ACCESS_VIOLATION @ 0x{exc_addr:x}")

                else:
                    self._log("exception", f"0x{exc_code:08x} @ 0x{exc_addr:x}")

            elif code == 2:  # CREATE_THREAD
                self._log("thread", "Thread created")

            elif code == 3:  # CREATE_PROCESS
                self._log("init", "CREATE_PROCESS_DEBUG_EVENT")

            elif code == 5:  # EXIT_PROCESS
                exit_code = de.u.ExitProcess.dwExitCode
                self._log("exit", f"ExitProcess({exit_code})",
                          {"code": exit_code,
                           "type": "clean_exit" if exit_code == 0 else "crash"})

            elif code == 6:  # LOAD_DLL
                dll_name = self._read_dll_name(de)
                if dll_name:
                    base = de.u.LoadDll.lpBaseOfDll or 0
                    if "ntdll" in dll_name.lower():
                        self._log("dll", f"ntdll loaded @ 0x{base:x}")
                    elif "kernel32" in dll_name.lower():
                        self._log("dll", f"kernel32 loaded @ 0x{base:x}")

            self._k32.ContinueDebugEvent(de.dwProcessId, tid, 0x00010002)  # DBG_CONTINUE

            if code == 5:  # EXIT_PROCESS
                break

        elapsed = time.time() - start
        self._log("done", f"Observation complete ({elapsed:.2f}s)")

    def _read_dll_name(self, de) -> Optional[str]:
        """从 LOAD_DLL 事件读取 DLL 名称"""
        try:
            ld = de.u.LoadDll
            if ld.lpImageName:
                buf = (ctypes.c_char * 512)()
                rd = ctypes.c_size_t(0)
                if self._k32.ReadProcessMemory(self._hproc,
                        ctypes.c_void_p(ld.lpImageName), buf, 512, ctypes.byref(rd)):
                    raw = bytes(buf[:rd.value])
                    if raw:
                        return raw.decode("utf-16-le", errors="replace").rstrip("\x00")
        except:
            pass
        return None

    def _get_peb_addr(self) -> int:
        """NtQueryInformationProcess → PEB"""
        pbi = PROCESS_BASIC_INFO()
        sz = ctypes.c_ulong(ctypes.sizeof(pbi))
        if self._nt.NtQueryInformationProcess(self._hproc, 0, ctypes.byref(pbi), sz, None) == 0:
            a = pbi.PebBaseAddress
            return a.value if isinstance(a, ctypes.c_void_p) else (a or 0)
        return 0

    def _build_report(self) -> dict:
        """构建完整观察报告"""
        events = [e["event"] for e in self._timeline]
        exit_events = [e for e in self._timeline if e["event"].startswith("Exit")]

        reached_oep = any("OEP reached" in e["event"] for e in self._timeline)
        clean_exit = any("clean_exit" in e.get("data", {}).get("type", "")
                        for e in self._timeline if e["event"].startswith("Exit"))

        decision_chain = []
        for e in self._timeline:
            decision_chain.append(f"[{e['phase']}] {e['event']}")

        return {
            "pid": self._pid,
            "oep": hex(self._oep) if self._oep else "unknown",
            "events_count": len(self._timeline),
            "reached_oep": reached_oep,
            "exit_type": "clean" if clean_exit else "crash",
            "peb_snapshot": self._peb_snapshot,
            "decision_chain": "\n".join(decision_chain),
            "conclusion": self._analyze_conclusion(reached_oep, clean_exit),
        }

    def _analyze_conclusion(self, reached_oep: bool, clean_exit: bool) -> str:
        """分析结论"""
        if not reached_oep and clean_exit:
            return ("结论: 进程在到达 OEP 之前主动退出 (ExitCode=0)。\n"
                    "检测发生在 TLS 回调或 Loader 初始化阶段。\n"
                    "触发因素: 最可能是 PEB.BeingDebugged (Snapshot值为 "
                    f"{self._peb_snapshot.get('being_debugged','?')}) 或 "
                    "DebugPort 内核对象。")
        elif reached_oep:
            return "结论: OEP 可达! 检测发生在 OEP 之后的代码中。"
        return f"结论: {self._timeline[-1].get('event','unknown') if self._timeline else 'unknown'}"


# Supporting types
class STARTUPINFOW(ctypes.Structure):
    _fields_ = [("cb", wintypes.DWORD)] + [(f"r{i}", wintypes.BYTE) for i in range(100)]
    def __init__(self):
        super().__init__()
        self.cb = ctypes.sizeof(self)

class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [("hProcess", wintypes.HANDLE), ("hThread", wintypes.HANDLE),
                ("dwProcessId", wintypes.DWORD), ("dwThreadId", wintypes.DWORD)]

class PROCESS_BASIC_INFO(ctypes.Structure):
    _fields_ = [("ExitStatus", wintypes.LONG), ("PebBaseAddress", ctypes.c_void_p),
                ("AffinityMask", ctypes.c_ulonglong), ("BasePriority", wintypes.LONG),
                ("UniqueProcessId", ctypes.c_ulonglong),
                ("InheritedFromUniqueProcessId", ctypes.c_ulonglong)]

class CONTEXT(ctypes.Structure):
    _fields_ = [
        ("P1Home", ctypes.c_ulonglong), ("P2Home", ctypes.c_ulonglong),
        ("P3Home", ctypes.c_ulonglong), ("P4Home", ctypes.c_ulonglong),
        ("P5Home", ctypes.c_ulonglong), ("P6Home", ctypes.c_ulonglong),
        ("ContextFlags", wintypes.DWORD), ("MxCsr", wintypes.DWORD),
        ("SegCs", wintypes.WORD), ("SegDs", wintypes.WORD), ("SegEs", wintypes.WORD),
        ("SegFs", wintypes.WORD), ("SegGs", wintypes.WORD), ("SegSs", wintypes.WORD),
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
    ]

class EXCEPTION_RECORD(ctypes.Structure):
    pass
EXCEPTION_RECORD._fields_ = [
    ("ExceptionCode", wintypes.DWORD), ("ExceptionFlags", wintypes.DWORD),
    ("ExceptionRecord", ctypes.POINTER(EXCEPTION_RECORD)),
    ("ExceptionAddress", ctypes.c_void_p), ("NumberParameters", wintypes.DWORD),
    ("ExceptionInformation", ctypes.c_ulonglong * 15),
]

class EXCEPTION_DEBUG_INFO(ctypes.Structure):
    _fields_ = [("ExceptionRecord", EXCEPTION_RECORD),
                ("dwFirstChance", wintypes.DWORD)]

class LOAD_DLL_DEBUG_INFO(ctypes.Structure):
    _fields_ = [("hFile", wintypes.HANDLE), ("lpBaseOfDll", ctypes.c_void_p),
                ("dwDebugInfoFileOffset", wintypes.DWORD),
                ("cbDebugInfo", wintypes.DWORD), ("lpImageName", ctypes.c_void_p),
                ("fUnicode", wintypes.WORD)]

class EXIT_PROCESS_DEBUG_INFO(ctypes.Structure):
    _fields_ = [("dwExitCode", wintypes.DWORD)]

class DEBUG_EVENT_U(ctypes.Union):
    _fields_ = [("Exception", EXCEPTION_DEBUG_INFO),
                ("CreateProcessInfo", ctypes.c_byte * 200),
                ("CreateThread", ctypes.c_byte * 200),
                ("ExitProcess", EXIT_PROCESS_DEBUG_INFO),
                ("ExitThread", ctypes.c_byte * 200),
                ("LoadDll", LOAD_DLL_DEBUG_INFO),
                ("UnloadDll", ctypes.c_byte * 200)]

class DEBUG_EVENT(ctypes.Structure):
    _fields_ = [("dwDebugEventCode", wintypes.DWORD), ("dwProcessId", wintypes.DWORD),
                ("dwThreadId", wintypes.DWORD), ("u", DEBUG_EVENT_U)]
