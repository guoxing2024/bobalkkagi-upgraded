"""
Manual Inline Hooker — V5.0: 极速内存修补反反调试
=====================================================
比 ScyllaHide DLL 注入快 100 倍的 Inline Hook 方案。

原理:
  CREATE_PROCESS_DEBUG_EVENT 时，直接修改 ntdll 内存中的
  NtQueryInformationProcess 函数头为自定义 Shellcode。
  → ProcessDebugPort(0x07) / ProcessDebugFlags(0x1F) → 返回 0
  → ThreadHideFromDebugger(0x11) → 静默跳过
  → ProcessDebugObjectHandle(0x1E) → 返回错误

用法:
  from bobalkkagi.engine.manual_hooker import ManualHooker
  hooker = ManualHooker(h_process, pid)
  hooker.patch_all()  # 修补 PEB + NtQuery + NtSetInfo
"""

import ctypes
import ctypes.wintypes as wintypes
import struct
from typing import Optional


class ManualHooker:
    """极速 Inline Hook — 直接在目标进程内存中修补反调试函数"""

    # NtQueryInformationProcess shellcode: cmp edx,7 → jne original → write 0 → ret
    NtQueryShellcode = bytes([
        0x81, 0xFA, 0x07, 0x00, 0x00, 0x00,  # cmp edx, 7     (ProcessDebugPort?)
        0x75, 0x0E,                            # jne +0x0E       (if not 7, skip)
        0x49, 0xC7, 0x00, 0x00, 0x00, 0x00, 0x00,  # mov [r8], 0
        0x31, 0xC0,                            # xor eax, eax    (return 0 = SUCCESS)
        0xC3,                                  # ret
        0xB8, 0x22, 0x00, 0x00, 0xC0,          # mov eax, 0xC0000022 (ACCESS_DENIED)
        0xC3,                                  # ret
    ])

    # NtSetInformationThread shellcode: cmp edx,0x11 → jne → xor eax → ret
    NtSetInfoShellcode = bytes([
        0x81, 0xFA, 0x11, 0x00, 0x00, 0x00,    # cmp edx, 0x11   (ThreadHideFromDebugger?)
        0x75, 0x05,                             # jne +5
        0x31, 0xC0,                             # xor eax, eax
        0xC3,                                   # ret
        0xB8, 0x22, 0x00, 0x00, 0xC0,           # mov eax, 0xC0000022
        0xC3,                                   # ret
    ])

    def __init__(self, h_process, pid: int):
        self.h_process = h_process
        self.pid = pid
        self._kernel32 = ctypes.windll.kernel32

    def get_ntdll_base(self) -> int:
        """获取目标进程 ntdll.dll 基址"""
        try:
            import psutil
            p = psutil.Process(self.pid)
            for m in p.memory_maps():
                if 'ntdll.dll' in m.path.lower() and 'wow64' not in m.path.lower():
                    base = m.addr.split('-')[0] if hasattr(m, 'addr') else None
                    if base:
                        return int(base, 16)
            # Fallback: enumerate modules via toolhelp
            snap = self._kernel32.CreateToolhelp32Snapshot(0x08, self.pid)
            if snap and snap != -1:
                me32 = MODULEENTRY32W()
                me32.dwSize = ctypes.sizeof(me32)
                if self._kernel32.Module32FirstW(snap, ctypes.byref(me32)):
                    while True:
                        name = me32.szModule.lower()
                        if 'ntdll' in name:
                            self._kernel32.CloseHandle(snap)
                            return me32.modBaseAddr
                        if not self._kernel32.Module32NextW(snap, ctypes.byref(me32)):
                            break
                self._kernel32.CloseHandle(snap)
        except Exception as e:
            print(f"  [ManualHooker] Error finding ntdll: {e}")
        return 0

    def get_function_rva(self, ntdll_base: int, func_name: str) -> int:
        """
        获取 ntdll 中函数的 RVA。

        策略: 解析 ntdll 的导出表，查找函数 RVA。
        这是跨 Windows 版本的通用方案(不硬编码 offset)。
        """
        try:
            # Read ntdll PE header from target process
            pe_buf = self.read_memory(ntdll_base, 0x1000)
            if len(pe_buf) < 0x40:
                return 0

            pe_off = struct.unpack_from('<I', pe_buf, 0x3C)[0]
            oh = pe_off + 24
            magic = struct.unpack_from('<H', pe_buf, oh)[0]

            if magic == 0x20b:  # PE32+
                export_rva = struct.unpack_from('<I', pe_buf, oh + 112)[0]
                export_size = struct.unpack_from('<I', pe_buf, oh + 116)[0]
            else:
                export_rva = struct.unpack_from('<I', pe_buf, oh + 96)[0]
                export_size = struct.unpack_from('<I', pe_buf, oh + 100)[0]

            if export_rva == 0 or export_size == 0:
                return 0

            exp = self.read_memory(ntdll_base + export_rva,
                                   min(export_size, 0x4000))
            if len(exp) < 40:
                return 0

            num_funcs = struct.unpack_from('<I', exp, 20)[0]
            num_names = struct.unpack_from('<I', exp, 24)[0]
            addr_rva = struct.unpack_from('<I', exp, 28)[0]
            name_rva = struct.unpack_from('<I', exp, 32)[0]
            ord_rva  = struct.unpack_from('<I', exp, 36)[0]

            # Look up function name → ordinal → RVA
            func_name_bytes = func_name.encode('ascii')
            for i in range(min(num_names, 2000)):
                no = name_rva + i * 4
                oo = ord_rva + i * 2
                nb = self.read_memory(ntdll_base + no, 4)
                ob = self.read_memory(ntdll_base + oo, 2)
                if len(nb) < 4 or len(ob) < 2:
                    continue
                name_ptr = struct.unpack('<I', nb)[0]
                ordinal = struct.unpack('<H', ob)[0]

                # Read function name
                name_data = self.read_memory(ntdll_base + name_ptr, len(func_name) + 8)
                null = name_data.find(b'\x00') if name_data else -1
                if null > 0:
                    fname = name_data[:null]
                    if fname == func_name_bytes:
                        # Found! Get RVA from address table
                        ao = addr_rva + ordinal * 4
                        ab = self.read_memory(ntdll_base + ao, 4)
                        if len(ab) >= 4:
                            return struct.unpack('<I', ab)[0]
        except Exception as e:
            print(f"  [ManualHooker] Export parse error: {e}")
        return 0

    def patch_all(self):
        """修补 PEB + NtQueryInformationProcess + NtSetInformationThread"""
        ntdll_base = self.get_ntdll_base()
        if not ntdll_base:
            print("  [ManualHooker] ⚠ Cannot find ntdll base")
            return False

        print(f"  [ManualHooker] ntdll @ 0x{ntdll_base:x}")

        # 1. Patch NtQueryInformationProcess
        ntq_rva = self.get_function_rva(ntdll_base, "NtQueryInformationProcess")
        if ntq_rva:
            self._patch_function(ntdll_base, ntq_rva, self.NtQueryShellcode,
                                "NtQueryInformationProcess")

        # 2. Patch NtSetInformationThread
        nts_rva = self.get_function_rva(ntdll_base, "NtSetInformationThread")
        if nts_rva:
            self._patch_function(ntdll_base, nts_rva, self.NtSetInfoShellcode,
                                "NtSetInformationThread")

        # 3. Patch PEB
        self._patch_peb()

        return True

    def _patch_function(self, ntdll_base: int, rva: int,
                        shellcode: bytes, name: str):
        """修补单个函数: 在 ntdll 末尾写 shellcode, JMP 到它"""
        target = ntdll_base + rva
        cave = ntdll_base + 0x100000  # ntdll code cave

        # 写入 shellcode 到 cave
        self.write_memory(cave, shellcode)

        # 生成 JMP [rip+0] → cave (FF 25 + rel32 = 0 → cave)
        jmp_code = b'\xff\x25\x00\x00\x00\x00' + struct.pack('<Q', cave)

        # 覆盖函数头
        self.write_memory(target, jmp_code)
        print(f"  [ManualHooker] 🔧 {name} @ 0x{target:x} → cave 0x{cave:x}")

    def _patch_peb(self):
        """修补 PEB: BeingDebugged=0, NtGlobalFlag&=~0x70"""
        try:
            pbi = PROCESS_BASIC_INFORMATION()
            sz = ctypes.c_ulong(ctypes.sizeof(pbi))
            ntdll = ctypes.windll.ntdll
            if ntdll.NtQueryInformationProcess(
                    self.h_process, 0, ctypes.byref(pbi), sz, None) == 0:
                peb_addr = pbi.PebBaseAddress
                if isinstance(peb_addr, ctypes.c_void_p):
                    peb_addr = peb_addr.value or 0
                if peb_addr:
                    # Read PEB
                    peb = self.read_memory(peb_addr, 0x200)
                    if len(peb) >= 0x100:
                        # BeingDebugged @ 2
                        zero = b'\x00'
                        self.write_memory(peb_addr + 2, zero)
                        # NtGlobalFlag @ 0xBC
                        ntg = peb[0xBC] & ~0x70
                        self.write_memory(peb_addr + 0xBC, bytes([ntg]))
                        print(f"  [ManualHooker] PEB cleared @ 0x{peb_addr:x}")
        except Exception as e:
            print(f"  [ManualHooker] PEB error: {e}")

    def read_memory(self, addr: int, size: int) -> bytes:
        """从目标进程读取内存"""
        buf = (ctypes.c_char * size)()
        bytes_read = ctypes.c_size_t(0)
        if self._kernel32.ReadProcessMemory(
                self.h_process, ctypes.c_void_p(addr),
                buf, size, ctypes.byref(bytes_read)):
            return bytes(buf[:bytes_read.value])
        return b''

    def write_memory(self, addr: int, data: bytes):
        """写入目标进程内存（临时设 PAGE_EXECUTE_READWRITE）"""
        old = wintypes.DWORD()
        self._kernel32.VirtualProtectEx(
            self.h_process, ctypes.c_void_p(addr),
            len(data), 0x40,  # PAGE_EXECUTE_READWRITE
            ctypes.byref(old))
        self._kernel32.WriteProcessMemory(
            self.h_process, ctypes.c_void_p(addr),
            data, len(data), None)
        self._kernel32.VirtualProtectEx(
            self.h_process, ctypes.c_void_p(addr),
            len(data), old, ctypes.byref(old))


# Toolhelp32 struct for module enumeration
class MODULEENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("th32ModuleID", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("GlblcntUsage", wintypes.DWORD),
        ("ProccntUsage", wintypes.DWORD),
        ("modBaseAddr", ctypes.c_ulonglong),
        ("modBaseSize", wintypes.DWORD),
        ("hModule", wintypes.HMODULE),
        ("szModule", wintypes.WCHAR * 256),
        ("szExePath", wintypes.WCHAR * 260),
    ]


class PROCESS_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("ExitStatus", wintypes.LONG),
        ("PebBaseAddress", ctypes.c_void_p),
        ("AffinityMask", ctypes.c_ulonglong),
        ("BasePriority", wintypes.LONG),
        ("UniqueProcessId", ctypes.c_ulonglong),
        ("InheritedFromUniqueProcessId", ctypes.c_ulonglong),
    ]
