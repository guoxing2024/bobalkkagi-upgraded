import ctypes, struct
from ctypes import wintypes

k32 = ctypes.windll.kernel32
nt = ctypes.windll.ntdll

class SI(ctypes.Structure):
    _fields = [("cb", wintypes.DWORD)] + [(f"_{i}", wintypes.BYTE) for i in range(100)]
    def __init__(self): self.cb = ctypes.sizeof(self)
class PI(ctypes.Structure):
    _fields_ = [("hP", wintypes.HANDLE), ("hT", wintypes.HANDLE), ("pid", wintypes.DWORD), ("tid", wintypes.DWORD)]

si = SI()
pi = PI()
exe = "D:\\Tools\\RE\\dumps\\temp\\伦伦软件.exe"
ok = k32.CreateProcessW(None, exe, None, None, False, 0x4, None, None, ctypes.byref(si), ctypes.byref(pi))
print("Created:", ok, "PID:", pi.pid)

class PBI(ctypes.Structure):
    _fields_ = [("Exit", wintypes.LONG), ("Peb", ctypes.c_void_p),
        ("x", ctypes.c_ulonglong), ("y", wintypes.LONG), ("z1", ctypes.c_ulonglong), ("z2", ctypes.c_ulonglong)]
pbi = PBI()
sz = ctypes.c_ulong(ctypes.sizeof(pbi))
nt.NtQueryInformationProcess(pi.hP, 0, ctypes.byref(pbi), sz, None)
peb = pbi.Peb or 0
print("PEB =", hex(peb))

buf = (ctypes.c_char * 0x200)()
rd = ctypes.c_size_t(0)
k32.ReadProcessMemory(pi.hP, peb, buf, 0x200, ctypes.byref(rd))
peb_data = bytes(buf)
ldr = struct.unpack_from("<Q", peb_data, 0x18)[0]
print("Ldr =", hex(ldr))

if ldr:
    lb = (ctypes.c_char * 0x200)()
    k32.ReadProcessMemory(pi.hP, ldr, lb, 0x200, ctypes.byref(rd))
    ld = bytes(lb)
    flink = struct.unpack_from("<Q", ld, 0x10)[0]
    print("InLoadOrder Flink =", hex(flink), "head =", hex(ldr + 0x10))

    entry = flink
    for n in range(5):
        if entry == ldr + 0x10 or entry == 0:
            break
        eb = (ctypes.c_char * 0x200)()
        k32.ReadProcessMemory(pi.hP, entry, eb, 0x200, ctypes.byref(rd))
        ed = bytes(eb)
        dllbase = struct.unpack_from("<Q", ed, 0x30)[0]
        nb = struct.unpack_from("<Q", ed, 0x60)[0]
        nl = struct.unpack_from("<H", ed, 0x58)[0]
        line = "  [%d] base=%s nameLen=%d" % (n, hex(dllbase), nl)
        if nb and nl > 0:
            nm = (ctypes.c_char * 64)()
            k32.ReadProcessMemory(pi.hP, nb, nm, 64, ctypes.byref(rd))
            raw = nm.raw[: min(nl, 60)]
            name = raw.decode("utf-16-le", errors="replace")
            line += " name=" + name
        print(line)
        next_flink = struct.unpack_from("<Q", ed, 0)[0]
        entry = next_flink

k32.TerminateProcess(pi.hP, 0)
k32.CloseHandle(pi.hP)
k32.CloseHandle(pi.hT)
print("Done")
