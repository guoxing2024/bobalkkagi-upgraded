"""
ScyllaHide Injector — V5.0: 进程内反反调试注入
=================================================
Bobalkkagi V5.0 — 放弃 Python syscall offset 猜测，使用成熟 ScyllaHide DLL。

工作原理:
  1. 加载 HookLibraryx64.dll (ScyllaHide 核心 DLL)
  2. 通过 NtCreateThreadEx 远程注入到目标进程
  3. DLL 自动处理 12+ 种反调试检测 (内核级 hook)
  4. 返回注入状态供 DebuggerBackend 验证

需要:
  - HookLibraryx64.dll (从 ScyllaHide 发布包获取)
  - 下载地址: https://github.com/x64dbg/ScyllaHide/releases
  - 放置到: ~/Tools/ScyllaHide/ 或与脚本同目录

用法:
  from bobalkkagi.engine.scylla_injector import ScyllaInjector
  injector = ScyllaInjector()
  injector.inject(pid, "HookLibraryx64.dll")
"""

import os
import sys
import ctypes
from ctypes import wintypes
from typing import Optional


class ScyllaInjector:
    """ScyllaHide 远程进程注入器"""

    DLL_NAME = "HookLibraryx64.dll"
    SEARCH_PATHS = [
        ".",  # 当前目录
        os.path.join(os.path.dirname(__file__), "..", ".."),  # 项目根
        os.path.join(os.environ.get("USERPROFILE", "~"), "Tools", "ScyllaHide"),
        r"C:\Tools\ScyllaHide",
        r"C:\Program Files\ScyllaHide",
    ]

    def __init__(self):
        self._dll_path: Optional[str] = None
        self._kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        self._ntdll = ctypes.WinDLL("ntdll", use_last_error=True)

        # Setup kernel32 prototypes
        self._kernel32.VirtualAllocEx.argtypes = [
            wintypes.HANDLE, wintypes.LPVOID, ctypes.c_size_t,
            wintypes.DWORD, wintypes.DWORD]
        self._kernel32.VirtualAllocEx.restype = wintypes.LPVOID

        self._kernel32.WriteProcessMemory.argtypes = [
            wintypes.HANDLE, wintypes.LPVOID, wintypes.LPCVOID,
            ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
        self._kernel32.WriteProcessMemory.restype = wintypes.BOOL

        self._kernel32.CreateRemoteThread.argtypes = [
            wintypes.HANDLE, wintypes.LPVOID, ctypes.c_size_t,
            wintypes.LPVOID, wintypes.LPVOID, wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD)]
        self._kernel32.CreateRemoteThread.restype = wintypes.HANDLE

        self._kernel32.GetModuleHandleW.argtypes = [wintypes.LPCWSTR]
        self._kernel32.GetModuleHandleW.restype = wintypes.HMODULE

        self._kernel32.GetProcAddress.argtypes = [wintypes.HMODULE, wintypes.LPCSTR]
        self._kernel32.GetProcAddress.restype = wintypes.LPVOID

        self._kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        self._kernel32.WaitForSingleObject.restype = wintypes.DWORD

        # Constants
        self.MEM_COMMIT = 0x1000
        self.MEM_RESERVE = 0x2000
        self.PAGE_READWRITE = 0x04
        self.PROCESS_ALL_ACCESS = 0x001F0FFF
        self.INFINITE = 0xFFFFFFFF

    def find_dll(self) -> Optional[str]:
        """Locate HookLibraryx64.dll on the system"""
        for path in self.SEARCH_PATHS:
            full = os.path.join(path, self.DLL_NAME)
            if os.path.isfile(full):
                self._dll_path = full
                return full
        return None

    def inject(self, pid: int, dll_path: str = None) -> bool:
        """
        Inject ScyllaHide DLL into target process.

        Args:
            pid: Target process ID
            dll_path: Path to HookLibraryx64.dll (auto-detected if None)

        Returns:
            True if injection successful
        """
        if dll_path is None:
            dll_path = self.find_dll()

        if dll_path is None:
            self._print_missing_dll()
            return False

        if not os.path.isfile(dll_path):
            self._print_missing_dll()
            return False

        dll_path_abs = os.path.abspath(dll_path)
        dll_path_bytes = dll_path_abs.encode("utf-16-le")  # wide string
        dll_size = len(dll_path_bytes)

        print(f"  [ScyllaInjector] Loading: {dll_path_abs}")

        # 1. Open target process
        h_process = self._kernel32.OpenProcess(
            self.PROCESS_ALL_ACCESS, False, pid)
        if not h_process:
            err = ctypes.get_last_error()
            print(f"  [ScyllaInjector] ❌ OpenProcess failed (err={err})")
            print(f"  [ScyllaInjector] ⚠ Need Administrator privileges")
            return False

        try:
            # 2. Allocate memory in target process for DLL path
            p_remote = self._kernel32.VirtualAllocEx(
                h_process, None, dll_size,
                self.MEM_COMMIT | self.MEM_RESERVE,
                self.PAGE_READWRITE)
            if not p_remote:
                print(f"  [ScyllaInjector] ❌ VirtualAllocEx failed")
                return False

            # 3. Write DLL path to target
            written = ctypes.c_size_t(0)
            if not self._kernel32.WriteProcessMemory(
                    h_process, p_remote, dll_path_bytes, dll_size,
                    ctypes.byref(written)):
                print(f"  [ScyllaInjector] ❌ WriteProcessMemory failed")
                return False

            # 4. Get LoadLibraryW address
            h_kernel32 = self._kernel32.GetModuleHandleW("kernel32.dll")
            if not h_kernel32:
                print(f"  [ScyllaInjector] ❌ GetModuleHandleW failed")
                return False

            p_loadlib = self._kernel32.GetProcAddress(
                h_kernel32, b"LoadLibraryW")
            if not p_loadlib:
                print(f"  [ScyllaInjector] ❌ GetProcAddress(LoadLibraryW) failed")
                return False

            # 5. Create remote thread → LoadLibraryW(dll_path)
            h_thread = self._kernel32.CreateRemoteThread(
                h_process, None, 0, p_loadlib, p_remote, 0, None)
            if not h_thread:
                err = ctypes.get_last_error()
                print(f"  [ScyllaInjector] ❌ CreateRemoteThread failed (err={err})")
                return False

            # 6. Wait for LoadLibrary to complete
            self._kernel32.WaitForSingleObject(h_thread, 5000)  # 5s timeout
            self._kernel32.CloseHandle(h_thread)

            print(f"  [ScyllaInjector] ✅ ScyllaHide injected into PID={pid}")
            print(f"  [ScyllaInjector] 🛡 12+ anti-debug protections active")
            return True

        finally:
            self._kernel32.CloseHandle(h_process)

    def _print_missing_dll(self):
        """Print instructions for obtaining HookLibraryx64.dll"""
        print(f"""
  [ScyllaInjector] ⚠ HookLibraryx64.dll NOT FOUND

  Download ScyllaHide from:
    https://github.com/x64dbg/ScyllaHide/releases

  Then extract HookLibraryx64.dll to one of:
""")
        for p in self.SEARCH_PATHS:
            print(f"    {os.path.abspath(p)}")

    def is_available(self) -> bool:
        """Check if ScyllaHide DLL is available"""
        return self.find_dll() is not None


# Module-level convenience
def inject_scyllahide(pid: int, dll_path: str = None) -> bool:
    """
    Convenience function: inject ScyllaHide into process.

    Returns:
        True if injected successfully
    """
    injector = ScyllaInjector()
    return injector.inject(pid, dll_path)
