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
    rd = ctypes.c_size_t(0)
    for _ in range(10):
        if k32.WaitForDebugEvent(de_buf, 100):
            # Use ctypes cast to avoid bytearray range issue
            class _DE(ctypes.Structure):
                _fields_ = [("code", ctypes.c_uint32), ("pid", ctypes.c_uint32), ("tid", ctypes.c_uint32)]
            ev = ctypes.cast(de_buf, ctypes.POINTER(_DE)).contents
            k32.ContinueDebugEvent(ev.pid, ev.tid, 0x00010002)

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

    # Read PE header for export directory info
    pe_buf = (ctypes.c_char * 0x2000)()
    k32.ReadProcessMemory(h_process, ctypes.c_void_p(ntdll_base), pe_buf, 0x2000, ctypes.byref(rd))
    pe_data = bytes(pe_buf[:rd.value])
    pe_off = struct.unpack_from('<I', pe_data, 0x3C)[0]
    oh = pe_off + 24
    exp_rva = struct.unpack_from('<I', pe_data, oh + 112)[0]
    exp_size = struct.unpack_from('<I', pe_data, oh + 116)[0]
    if exp_rva == 0:
        return False

    # Read export section DIRECTLY at ntdll_base + exp_rva
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

    # All export RVAs are IMAGE-RELATIVE — convert to buffer offsets
    name_off = name_rva - exp_rva
    ord_off = ord_rva - exp_rva
    addr_off = addr_rva - exp_rva

    target = b'NtQueryInformationProcess'
    func_rva = 0
    for i in range(min(num_names, 2000)):
        np = struct.unpack_from('<I', exp, name_off + i * 4)[0]
        # np is RVA; read name string from process memory
        name_buf = (ctypes.c_char * 128)()
        rd = ctypes.c_size_t(0)
        if k32.ReadProcessMemory(h_process, ctypes.c_void_p(ntdll_base + np),
                                 name_buf, 128, ctypes.byref(rd)):
            name = bytes(name_buf[:64])
            if name[:len(target)] == target and name[len(target)] == 0:
                oi = struct.unpack_from('<H', exp, ord_off + i * 2)[0]
                func_rva = struct.unpack_from('<I', exp, addr_off + oi * 4)[0]
                break

    if not func_rva:
        print(f"  [EarlyHook] NtQueryInformationProcess not found in export table")
        return False

    # Save original bytes and install detour
    cave = ntdll_base + 0x100000
    target_addr = ntdll_base + func_rva
    orig_buf = (ctypes.c_char * 30)()
    rd = ctypes.c_size_t(0)
    k32.ReadProcessMemory(h_process, ctypes.c_void_p(target_addr), orig_buf, 30, ctypes.byref(rd))
    orig_bytes = bytes(orig_buf[:30])
    # Save to cave area
    k32.WriteProcessMemory(h_process, ctypes.c_void_p(cave + 0x400), orig_bytes, 30, None)

    # Shellcode: check edx for debug classes, pass through if not
    # Structure: [filter] [handle_07] [handle_1f] [handle_1e] [pass_through: orig + jmp back]
    sc = bytes([
        # Filter section
        0x81, 0xFA, 0x07, 0x00, 0x00, 0x00,
        0x74, 0x10,
        0x81, 0xFA, 0x1F, 0x00, 0x00, 0x00,
        0x74, 0x18,
        0x81, 0xFA, 0x1E, 0x00, 0x00, 0x00,
        0x74, 0x20,
        # Passthrough: jmp [rip+0] -> saved_instrs
        0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,
    ]) + struct.pack('<Q', cave + 0x400) + bytes([
        # handle_07: DebugPort -> write 0, return SUCCESS
        0x49, 0xC7, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x31, 0xC0,
        0xC3,
        # handle_1f: DebugFlags -> write 1, return SUCCESS
        0x49, 0xC7, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x31, 0xC0,
        0xC3,
        # handle_1e: DebugObjectHandle -> STATUS_PORT_NOT_SET
        0xB8, 0x53, 0x03, 0x00, 0xC0,
        0xC3,
    ])

    old = ctypes.c_uint32()
    k32.VirtualProtectEx(h_process, ctypes.c_void_p(cave), len(sc) + 0x800, 0x40, ctypes.byref(old))
    k32.WriteProcessMemory(h_process, ctypes.c_void_p(cave), sc, len(sc), None)

    # JMP [cave] at function entry
    jmp_code = b'\xff\x25\x00\x00\x00\x00' + struct.pack('<Q', cave)
    k32.VirtualProtectEx(h_process, ctypes.c_void_p(target_addr), 14, 0x40, ctypes.byref(old))
    k32.WriteProcessMemory(h_process, ctypes.c_void_p(target_addr), jmp_code, 14, None)

    print(f"  [EarlyHook] Hooked: 0x{target_addr:x} -> cave 0x{cave:x}")
    return True
