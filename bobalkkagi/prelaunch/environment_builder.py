"""
Prelaunch Environment Sanitizer — V5.0: 进程启动前环境消毒
=============================================================
Bobalkkagi V5.0 — 在 CREATE_SUSPENDED 阶段，构建无调试器痕迹的干净环境。

修复了我们之前只清除 BeingDebugged 的问题。完整消毒包括:

  1. PEB: BeingDebugged=0, NtGlobalFlag&=~0x70
  2. ProcessHeap: Flags&=~0x6000007F, ForceFlags=0
  3. KUSER_SHARED_DATA: KdDebuggerEnabled=0, KdDebuggerNotPresent=1
  4. Debug 寄存器: Dr0-Dr7=0

所有操作在进程恢复执行前完成 → TLS 回调看到的是干净环境。

用法:
  from bobalkkagi.prelaunch import sanitize_process
  sanitize_process(h_process, h_thread, pid)
"""

import ctypes
import ctypes.wintypes as wintypes
import struct
from typing import Optional


class ProcessSanitizer:
    """进程启动前环境消毒器 — 在 CREATE_SUSPENDED 时调用"""

    def __init__(self, h_process, h_thread, pid: int):
        self.h_process = h_process
        self.h_thread = h_thread
        self.pid = pid
        self._kernel32 = ctypes.windll.kernel32
        self._ntdll = ctypes.windll.ntdll
        self._applied = []

    def read_memory(self, addr: int, size: int) -> bytes:
        buf = (ctypes.c_char * size)()
        read = ctypes.c_size_t(0)
        if self._kernel32.ReadProcessMemory(
                self.h_process, ctypes.c_void_p(addr),
                buf, size, ctypes.byref(read)):
            return bytes(buf[:read.value])
        return b''

    def write_memory(self, addr: int, data: bytes):
        self._kernel32.WriteProcessMemory(
            self.h_process, ctypes.c_void_p(addr),
            data, len(data), None)

    def get_peb_addr(self) -> int:
        """通过 NtQueryInformationProcess 获取 PEB 地址"""
        pbi = PROCESS_BASIC_INFORMATION()
        sz = ctypes.c_ulong(ctypes.sizeof(pbi))
        if self._ntdll.NtQueryInformationProcess(
                self.h_process, 0, ctypes.byref(pbi), sz, None) == 0:
            addr = pbi.PebBaseAddress
            if isinstance(addr, ctypes.c_void_p):
                return addr.value or 0
            return addr or 0
        return 0

    def sanitize_peb(self) -> bool:
        """消毒 PEB: BeingDebugged + NtGlobalFlag + ProcessHeap"""
        peb = self.get_peb_addr()
        if not peb:
            print(f"  [Sanitizer] ⚠ PEB not found")
            return False

        data = self.read_memory(peb, 0x200)
        if len(data) < 0x100:
            return False

        # BeingDebugged @ +2 → 0
        self.write_memory(peb + 2, b'\x00')

        # NtGlobalFlag @ +0xBC → &= ~0x70
        ntg = data[0xBC] & ~0x70
        self.write_memory(peb + 0xBC, bytes([ntg]))

        # ProcessHeap @ +0x30 (x64)
        heap_ptr = struct.unpack_from('<Q', data, 0x30)[0]
        if heap_ptr and heap_ptr > 0x10000:
            heap_data = self.read_memory(heap_ptr, 0x20)
            if len(heap_data) >= 0x18:
                # Flags @ +0x14 → &= ~(HEAP_GROWABLE | HEAP_TAIL_CHECK | ...)
                flags = struct.unpack_from('<I', heap_data, 0x14)[0]
                flags &= ~(0x6000007F)  # clear debug flags
                self.write_memory(heap_ptr + 0x14, struct.pack('<I', flags))
                # ForceFlags @ +0x18 → 0
                self.write_memory(heap_ptr + 0x18, struct.pack('<I', 0))
                print(f"  [Sanitizer] Heap @ 0x{heap_ptr:x}: Flags=0x{flags:08x}")

        print(f"  [Sanitizer] PEB @ 0x{peb:x}: BeingDebugged=0, NtGlobalFlag=0x{ntg:02x}")
        self._applied.append("peb")
        return True

    def sanitize_kuser_shared_data(self) -> bool:
        """消毒 KUSER_SHARED_DATA: 清除内核调试器标志

        KUSER_SHARED_DATA @ 0x7FFE0000 (x64)
          +0x2F4: KdDebuggerEnabled → 0
          +0x2F8: KdDebuggerNotPresent → 1
        """
        kuser = 0x7FFE0000  # Always mapped at this address
        data = self.read_memory(kuser, 0x300)
        if len(data) < 0x300:
            return False

        # KdDebuggerEnabled @ +0x2F4
        kd = struct.unpack_from('<B', data, 0x2F4)[0]
        if kd != 0:
            self.write_memory(kuser + 0x2F4, b'\x00')

        # KdDebuggerNotPresent @ +0x2F8  
        knp = struct.unpack_from('<B', data, 0x2F8)[0]
        if knp != 1:
            self.write_memory(kuser + 0x2F8, b'\x01')

        print(f"  [Sanitizer] KUSER: KdDebuggerEnabled=0, KdDebuggerNotPresent=1")
        self._applied.append("kuser")
        return True

    def sanitize_debug_registers(self) -> bool:
        """清除硬件调试寄存器 Dr0-Dr3, Dr6, Dr7"""
        ctx = CONTEXT()
        ctx.ContextFlags = 0x10007  # CONTEXT_ALL
        if not self._kernel32.GetThreadContext(
                self.h_thread, ctypes.byref(ctx)):
            return False

        ctx.Dr0 = ctx.Dr1 = ctx.Dr2 = ctx.Dr3 = 0
        ctx.Dr6 = 0
        ctx.Dr7 = 0
        self._kernel32.SetThreadContext(
            self.h_thread, ctypes.byref(ctx))

        print(f"  [Sanitizer] Debug registers: Dr0-Dr7=0")
        self._applied.append("debug_regs")
        return True

    def sanitize_all(self) -> bool:
        """执行全部消毒 + ntdll Inline Hook"""
        print(f"  [Sanitizer] Pre-launch sanitization for PID={self.pid}")

        self.sanitize_peb()
        self.sanitize_kuser_shared_data()
        self.sanitize_debug_registers()

        # V5 Critical: 在恢复执行前 hook ntdll
        # DebugPort 是内核级查询，用户态 PEB 清除无效
        # 必须在 TLS 回调之前拦截 NtQueryInformationProcess
        self._hook_ntdll_before_resume()

        if len(self._applied) >= 2:
            print(f"  [Sanitizer] ✅ Process environment sanitized: {self._applied}")
            return True
        return False

    def _hook_ntdll_before_resume(self):
        """V5: 在 CREATE_SUSPENDED 时通过 PEB Ldr 找 ntdll → Inline Hook

        关键: 此时 ntdll 已加载但未在 Toolhelp32 列表中。
        通过 PEB → Ldr → InLoadOrderModuleList 遍历找到它。
        """
        peb = self.get_peb_addr()
        if not peb:
            return

        # PEB+0x18 = Ldr (PEB_LDR_DATA*)
        peb_data = self.read_memory(peb, 0x200)
        if len(peb_data) < 0x100:
            return

        ldr = struct.unpack_from('<Q', peb_data, 0x18)[0]
        if not ldr or ldr < 0x1000:
            return

        # InLoadOrderModuleList is at LDR+0x10
        # LIST_ENTRY: Flink @ +0, Blink @ +8
        head = ldr + 0x10
        entry = struct.unpack_from('<Q', self.read_memory(head, 8))[0]
        if not entry:
            return

        ntdll_base = 0
        for _ in range(4):
            if entry == head:
                break
            # LDR_DATA_TABLE_ENTRY: DllBase @ +0x30 (x64)
            dll_base = struct.unpack_from('<Q', self.read_memory(entry + 0x30, 8))[0]
            # BaseDllName @ +0x58 → UNICODE_STRING
            name_buf = struct.unpack_from('<Q', self.read_memory(entry + 0x58 + 8, 8))[0]
            name_len = struct.unpack_from('<H', self.read_memory(entry + 0x58, 2))[0]
            if name_buf and name_len:
                name_data = self.read_memory(name_buf, min(name_len, 64))
                try:
                    dll_name = name_data.decode('utf-16-le', errors='replace').lower()
                    if 'ntdll' in dll_name:
                        ntdll_base = dll_base
                        print(f"  [Sanitizer] Found ntdll @ 0x{ntdll_base:x} via PEB Ldr")
                        break
                except:
                    pass
            next_entry = struct.unpack_from('<Q', self.read_memory(entry, 8))[0]
            entry = next_entry

        if not ntdll_base:
            return

        # NtQueryInformationProcess RVA → resolve from ntdll export table
        ntq_rva = self._resolve_export(ntdll_base, "NtQueryInformationProcess")
        if not ntq_rva:
            print(f"  [Sanitizer] ⚠ Cannot find NtQueryInformationProcess export")
            return

        # Shellcode
        sc = bytes([
            0x81, 0xFA, 0x07, 0x00, 0x00, 0x00,  # cmp edx, 7
            0x75, 0x0E,                              # jne +0x0E
            0x49, 0xC7, 0x00, 0x00, 0x00, 0x00, 0x00,  # mov [r8], 0
            0x31, 0xC0,                              # xor eax, eax
            0xC3,                                    # ret
            0xB8, 0x22, 0x00, 0x00, 0xC0,            # mov eax, 0xC0000022
            0xC3,                                    # ret
        ])

        cave = ntdll_base + 0x100000
        target = ntdll_base + ntq_rva
        jmp_code = b'\xff\x25\x00\x00\x00\x00' + struct.pack('<Q', cave)

        self.write_memory(cave, sc)
        self.write_memory(target, jmp_code)
        print(f"  [Sanitizer] 🔧 NtQueryInformationProcess @ 0x{target:x} → cave 0x{cave:x}")
        self._applied.append("ntdll_hook")

    def _resolve_export(self, dll_base: int, func_name: str) -> int:
        """从 DLL 导出表解析函数 RVA"""
        pe_buf = self.read_memory(dll_base, 0x1000)
        pe_off = struct.unpack_from('<I', pe_buf, 0x3C)[0] if len(pe_buf) > 0x40 else 0
        if not pe_off:
            return 0
        oh = pe_off + 24
        exp_rva = struct.unpack_from('<I', pe_buf, oh + 112)[0]
        if not exp_rva:
            return 0
        exp = self.read_memory(dll_base + exp_rva, 0x4000)
        if len(exp) < 40:
            return 0
        num_names = struct.unpack_from('<I', exp, 24)[0]
        addr_rva = struct.unpack_from('<I', exp, 28)[0]
        name_rva = struct.unpack_from('<I', exp, 32)[0]
        ord_rva  = struct.unpack_from('<I', exp, 36)[0]
        target = func_name.encode('ascii')
        for i in range(min(num_names, 2000)):
            np = struct.unpack_from('<I', self.read_memory(dll_base + name_rva + i*4, 4))[0]
            nd = self.read_memory(dll_base + np, len(target) + 8)
            if nd and nd.find(target) == 0 and nd[len(target):len(target)+1] == b'\x00':
                ordinal = struct.unpack_from('<H', self.read_memory(dll_base + ord_rva + i*2, 2))[0]
                return struct.unpack_from('<I', self.read_memory(dll_base + addr_rva + ordinal*4, 4))[0]
        return 0


def sanitize_process(h_process, h_thread, pid: int) -> bool:
    """便捷函数: 完整消毒进程环境"""
    s = ProcessSanitizer(h_process, h_thread, pid)
    return s.sanitize_all()


# ===== Supporting Types =====

class PROCESS_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("ExitStatus", wintypes.LONG),
        ("PebBaseAddress", ctypes.c_void_p),
        ("AffinityMask", ctypes.c_ulonglong),
        ("BasePriority", wintypes.LONG),
        ("UniqueProcessId", ctypes.c_ulonglong),
        ("InheritedFromUniqueProcessId", ctypes.c_ulonglong),
    ]


class CONTEXT(ctypes.Structure):
    """x64 CONTEXT (minimal for debug register access)"""
    _fields_ = [
        ("P1Home", ctypes.c_ulonglong),
        ("P2Home", ctypes.c_ulonglong),
        ("P3Home", ctypes.c_ulonglong),
        ("P4Home", ctypes.c_ulonglong),
        ("P5Home", ctypes.c_ulonglong),
        ("P6Home", ctypes.c_ulonglong),
        ("ContextFlags", wintypes.DWORD),
        ("MxCsr", wintypes.DWORD),
        ("SegCs", wintypes.WORD),
        ("SegDs", wintypes.WORD),
        ("SegEs", wintypes.WORD),
        ("SegFs", wintypes.WORD),
        ("SegGs", wintypes.WORD),
        ("SegSs", wintypes.WORD),
        ("EFlags", wintypes.DWORD),
        ("Dr0", ctypes.c_ulonglong),
        ("Dr1", ctypes.c_ulonglong),
        ("Dr2", ctypes.c_ulonglong),
        ("Dr3", ctypes.c_ulonglong),
        ("Dr6", ctypes.c_ulonglong),
        ("Dr7", ctypes.c_ulonglong),
        ("Rax", ctypes.c_ulonglong),
        ("Rcx", ctypes.c_ulonglong),
        ("Rdx", ctypes.c_ulonglong),
        ("Rbx", ctypes.c_ulonglong),
        ("Rsp", ctypes.c_ulonglong),
        ("Rbp", ctypes.c_ulonglong),
        ("Rsi", ctypes.c_ulonglong),
        ("Rdi", ctypes.c_ulonglong),
        ("R8", ctypes.c_ulonglong),
        ("R9", ctypes.c_ulonglong),
        ("R10", ctypes.c_ulonglong),
        ("R11", ctypes.c_ulonglong),
        ("R12", ctypes.c_ulonglong),
        ("R13", ctypes.c_ulonglong),
        ("R14", ctypes.c_ulonglong),
        ("R15", ctypes.c_ulonglong),
        ("Rip", ctypes.c_ulonglong),
        ("FltSave", (wintypes.BYTE * 512)),
        ("VectorRegister", (wintypes.BYTE * 416)),
        ("VectorControl", ctypes.c_ulonglong),
        ("DebugControl", ctypes.c_ulonglong),
        ("LastBranchToRip", ctypes.c_ulonglong),
        ("LastBranchFromRip", ctypes.c_ulonglong),
        ("LastExceptionToRip", ctypes.c_ulonglong),
        ("LastExceptionFromRip", ctypes.c_ulonglong),
    ]
