"""
Early NTDLL Hook — V5: CRT_PROC -> PEB Ldr -> inline hook NtQueryInformationProcess
====================================================================================
Handles DebugPort(7), DebugFlags(0x1F), DebugObjectHandle(0x1E).
Passthrough for other queries via saved original bytes + tail jmp.
"""
import ctypes, struct
from ctypes import wintypes
from .environment_builder import PROCESS_BASIC_INFORMATION

k32 = ctypes.windll.kernel32
nt = ctypes.windll.ntdll


def hook_nt_query_info(h_process, h_thread, pid, de_buf=None):
    if de_buf is None:
        de_buf = (ctypes.c_byte * 200)()
    rd = ctypes.c_size_t(0)

    # Flush events to let Ldr initialize
    for _ in range(10):
        if k32.WaitForDebugEvent(de_buf, 100):
            class _DE(ctypes.Structure):
                _fields_ = [("code", ctypes.c_uint32), ("pid", ctypes.c_uint32), ("tid", ctypes.c_uint32)]
            ev = ctypes.cast(de_buf, ctypes.POINTER(_DE)).contents
            k32.ContinueDebugEvent(ev.pid, ev.tid, 0x00010002)

    # PEB -> Ldr -> ntdll
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
        nb_val = struct.unpack_from('<Q', ed, 0x60)[0]
        nl_val = struct.unpack_from('<H', ed, 0x58)[0]
        if nb_val and nl_val:
            nm = (ctypes.c_char * 64)()
            k32.ReadProcessMemory(h_process, ctypes.c_void_p(nb_val), nm, 64, ctypes.byref(rd))
            name = nm[:min(nl_val, 60)].decode('utf-16-le', errors='replace')
            if 'ntdll' in name.lower() and 'wow64' not in name:
                ntdll_base = base
                break
        entry = struct.unpack_from('<Q', ed, 0)[0]
    if not ntdll_base:
        return False

    print(f"  [EarlyHook] ntdll @ 0x{ntdll_base:x}")

    # PE header -> export
    pe_buf = (ctypes.c_char * 0x2000)()
    k32.ReadProcessMemory(h_process, ctypes.c_void_p(ntdll_base), pe_buf, 0x2000, ctypes.byref(rd))
    pe_data = bytes(pe_buf[:rd.value])
    pe_off = struct.unpack_from('<I', pe_data, 0x3C)[0]
    oh = pe_off + 24
    exp_rva = struct.unpack_from('<I', pe_data, oh + 112)[0]
    exp_size = struct.unpack_from('<I', pe_data, oh + 116)[0]
    if not exp_rva:
        return False

    rd = ctypes.c_size_t(0)
    exp_buf = (ctypes.c_char * min(exp_size, 0x20000))()
    k32.ReadProcessMemory(h_process, ctypes.c_void_p(ntdll_base + exp_rva),
                          exp_buf, min(exp_size, 0x20000), ctypes.byref(rd))
    exp = bytes(exp_buf[:rd.value])
    if len(exp) < 40:
        return False

    num_names = struct.unpack_from('<I', exp, 24)[0]
    addr_rva = struct.unpack_from('<I', exp, 28)[0]
    name_rva = struct.unpack_from('<I', exp, 32)[0]
    ord_rva = struct.unpack_from('<I', exp, 36)[0]
    name_off = name_rva - exp_rva
    ord_off = ord_rva - exp_rva
    addr_off = addr_rva - exp_rva

    target = b'NtQueryInformationProcess'
    func_rva = 0
    for i in range(min(num_names, 2000)):
        np = struct.unpack_from('<I', exp, name_off + i * 4)[0]
        name_buf = (ctypes.c_char * 128)()
        rd2 = ctypes.c_size_t(0)
        if k32.ReadProcessMemory(h_process, ctypes.c_void_p(ntdll_base + np),
                                 name_buf, 128, ctypes.byref(rd2)):
            n = bytes(name_buf[:64])
            if n[:len(target)] == target and n[len(target)] == 0:
                oi = struct.unpack_from('<H', exp, ord_off + i * 2)[0]
                func_rva = struct.unpack_from('<I', exp, addr_off + oi * 4)[0]
                break

    if not func_rva:
        print(f"  [EarlyHook] Not found")
        return False

    target_addr = ntdll_base + func_rva
    cave = ntdll_base + 0x100000

    # Save original first 14 bytes
    orig_buf = (ctypes.c_char * 14)()
    k32.ReadProcessMemory(h_process, ctypes.c_void_p(target_addr), orig_buf, 14, ctypes.byref(rd))
    orig_14 = bytes(orig_buf)

    # Build shellcode using bytearray
    sc = bytearray()
    # Layout: [filter24] [jmp_back14] [handle07_10] [handle1f_10] [handle1e_6]
    # Filter: cmp edx, 7 / 0x1F / 0x1E -> je -> handler -> jmp_back -> target+14
    sc += bytes([
        0x81, 0xFA, 0x07, 0x00, 0x00, 0x00,  # 0-5: cmp edx, 7
        0x74, 0x1E,                           # 6-7: je +30 -> handle_07 (byte 38)
        0x81, 0xFA, 0x1F, 0x00, 0x00, 0x00,  # 8-13: cmp edx, 0x1F
        0x74, 0x20,                           # 14-15: je +32 -> handle_1f (byte 48)
        0x81, 0xFA, 0x1E, 0x00, 0x00, 0x00,  # 16-21: cmp edx, 0x1E
        0x74, 0x22,                           # 22-23: je +34 -> handle_1e (byte 58)
    ])
    # 5-byte JMP at function entry → passthrough jumps to target_addr+5
    jmp_back_addr = target_addr + 5
    # jmp [rip+0] -> target_addr+5 (bytes 24-37)
    sc += b'\xff\x25\x00\x00\x00\x00'
    sc += struct.pack('<Q', jmp_back_addr)
    # handle_07 @ byte 38-47
    sc += bytes([0x49, 0xC7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x31, 0xC0, 0xC3])
    # handle_1f @ byte 48-57
    sc += bytes([0x49, 0xC7, 0x00, 0x01, 0x00, 0x00, 0x00, 0x31, 0xC0, 0xC3])
    # handle_1e @ byte 58-63
    sc += bytes([0xB8, 0x53, 0x03, 0x00, 0xC0, 0xC3])

    # Write shellcode
    old_prot = ctypes.c_uint32()
    k32.VirtualProtectEx(h_process, ctypes.c_void_p(cave), len(sc) + 0x100, 0x40, ctypes.byref(old_prot))
    k32.WriteProcessMemory(h_process, ctypes.c_void_p(cave), bytes(sc), len(sc), None)

    # 5-byte relative JMP (xa: E9 rel32) — ntdll syscall wrapper is only ~8 bytes
    rel32 = (cave - (target_addr + 5)) & 0xFFFFFFFF
    jmp_code = b'\\xe9' + struct.pack('<I', rel32)
    k32.VirtualProtectEx(h_process, ctypes.c_void_p(target_addr), 5, 0x40, ctypes.byref(old_prot))
    k32.WriteProcessMemory(h_process, ctypes.c_void_p(target_addr), jmp_code, 5, None)

    print(f"  [EarlyHook] Hooked: 0x{target_addr:x} -> cave 0x{cave:x}")
    return True
