"""
Early NTDLL Hook — V5: CRT_PROC event -> PEB Ldr -> hook NtQueryInformationProcess
===================================================================================
在第一个 CRT_PROC 事件后, 通过 PEB Ldr 找到 ntdll 并安装 Shellcode,
抢在 TLS 回调之前拦截 NtQueryInformationProcess(ProcessDebugPort=0x07).

时机: 8个事件后 Ldr 初始化完成, TLS 尚未执行.
"""
import ctypes, struct
from ctypes import wintypes
from .environment_builder import PROCESS_BASIC_INFORMATION

k32 = ctypes.windll.kernel32
nt = ctypes.windll.ntdll

def hook_nt_query_info(h_process, h_thread, pid, de_buf=None):
    if de_buf is None:
        de_buf = (ctypes.c_byte * 200)()

    # Flush events to let Ldr initialize
    for _ in range(10):
        if k32.WaitForDebugEvent(de_buf, 100):
            raw = bytearray(de_buf[:12])
            db = bytes(raw)
            k32.ContinueDebugEvent(
                struct.unpack_from('<I', db, 4)[0],
                struct.unpack_from('<I', db, 8)[0],
                0x00010002)

    # PEB -> Ldr
    pbi = PROCESS_BASIC_INFORMATION()
    nt.NtQueryInformationProcess(h_process, 0, ctypes.byref(pbi),
                                  ctypes.c_ulong(ctypes.sizeof(pbi)), None)
    peb = pbi.PebBaseAddress or 0
    if isinstance(peb, ctypes.c_void_p):
        peb = peb.value or 0
    if not peb:
        return False

    buf = (ctypes.c_char * 0x200)()
    k32.ReadProcessMemory(h_process, ctypes.c_void_p(peb), buf, 0x200, ctypes.byref(rd))
    ldr = struct.unpack_from('<Q', bytes(buf), 0x18)[0]
    if not ldr:
        return False

    # Walk InLoadOrderModuleList
    lb = (ctypes.c_char * 0x200)()
    k32.ReadProcessMemory(h_process, ctypes.c_void_p(ldr), lb, 0x200, ctypes.byref(rd))
    flink = struct.unpack_from('<Q', bytes(lb), 0x10)[0]
    ntdll_base = 0
    entry = flink
    for _ in range(8):
        if entry == ldr + 0x10:
            break
        eb = (ctypes.c_char * 0x200)()
        k32.ReadProcessMemory(h_process, ctypes.c_void_p(entry), eb, 0x200, ctypes.byref(rd))
        ed = bytes(eb)
        base = struct.unpack_from('<Q', ed, 0x30)[0]
        nb = struct.unpack_from('<Q', ed, 0x60)[0]
        nl = struct.unpack_from('<H', ed, 0x58)[0]
        if nb and nl:
            nm = (ctypes.c_char * 64)()
            k32.ReadProcessMemory(h_process, ctypes.c_void_p(nb), nm, 64, ctypes.byref(rd))
            name = nm[:min(nl, 60)].decode('utf-16-le', errors='replace')
            if 'ntdll' in name.lower() and 'wow64' not in name:
                ntdll_base = base
                break
        entry = struct.unpack_from('<Q', ed, 0)[0]

    if not ntdll_base:
        return False

    print(f"  [EarlyHook] ntdll @ 0x{ntdll_base:x}")

    # Export lookup
    ebuf = (ctypes.c_char * 0x8000)()
    k32.ReadProcessMemory(h_process, ctypes.c_void_p(ntdll_base), ebuf, 0x8000, ctypes.byref(rd))
    pe_data = bytes(ebuf[:rd.value])
    if len(pe_data) < 0x200:
        return False
    pe_off = struct.unpack_from('<I', pe_data, 0x3C)[0]
    oh = pe_off + 24
    exp_rva = struct.unpack_from('<I', pe_data, oh + 112)[0]
    exp_size = struct.unpack_from('<I', pe_data, oh + 116)[0]
    if exp_rva == 0 or exp_rva + exp_size > len(pe_data):
        return False

    exp = pe_data[exp_rva:exp_rva + min(exp_size, 0x4000)]
    num_names = struct.unpack_from('<I', exp, 24)[0]
    addr_rva = struct.unpack_from('<I', exp, 28)[0]
    name_rva = struct.unpack_from('<I', exp, 32)[0]
    ord_rva = struct.unpack_from('<I', exp, 36)[0]

    target = b'NtQueryInformationProcess'
    func_rva = 0
    for i in range(min(num_names, 2000)):
        np = struct.unpack_from('<I', pe_data, name_rva + i * 4)[0]
        if np + len(target) < len(pe_data) and \
           pe_data[np:np + len(target)] == target and \
           pe_data[np + len(target)] == 0:
            oi = struct.unpack_from('<H', pe_data, ord_rva + i * 2)[0]
            func_rva = struct.unpack_from('<I', pe_data, addr_rva + oi * 4)[0]
            break

    if not func_rva:
        print(f"  [EarlyHook] NtQueryInformationProcess not found in export table")
        return False

    # Shellcode
    sc = bytes([0x81, 0xFA, 0x07, 0x00, 0x00, 0x00, 0x75, 0x0E,
                0x49, 0xC7, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x31, 0xC0, 0xC3,
                0xB8, 0x22, 0x00, 0x00, 0xC0, 0xC3])
    cave = ntdll_base + 0x100000
    target_addr = ntdll_base + func_rva
    jmp_code = b'\xff\x25\x00\x00\x00\x00' + struct.pack('<Q', cave)

    old = ctypes.c_uint32()
    k32.VirtualProtectEx(h_process, ctypes.c_void_p(cave), len(sc), 0x40, ctypes.byref(old))
    k32.WriteProcessMemory(h_process, ctypes.c_void_p(cave), sc, len(sc), None)
    k32.VirtualProtectEx(h_process, ctypes.c_void_p(target_addr), len(jmp_code), 0x40, ctypes.byref(old))
    k32.WriteProcessMemory(h_process, ctypes.c_void_p(target_addr), jmp_code, len(jmp_code), None)

    print(f"  [EarlyHook] Hooked: 0x{target_addr:x} -> cave 0x{cave:x}")
    return True
