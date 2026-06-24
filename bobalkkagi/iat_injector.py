"""
IAT Injector v2 — Clean PE import table rebuild
==================================================
"""

import struct, os

def inject(exe: str, iat_txt: str = None, out: str = None):
    """从 .iat.txt 注入导入表"""
    if iat_txt is None:
        iat_txt = exe + '.iat.txt'
    if not os.path.isfile(iat_txt):
        iat_txt = exe.replace('.exe', '.iat.txt')
    if not os.path.isfile(iat_txt):
        print(f"  [IAT] No .iat.txt at {iat_txt}")
        return exe

    # Parse manifest
    imports = {}
    with open(iat_txt) as f:
        for line in f:
            line = line.strip()
            if '!' not in line: continue
            dll, func = line.split('!', 1)
            imports.setdefault(dll, []).append(func)

    dlls = sorted(imports.keys())
    n_total = sum(len(v) for v in imports.values())

    # Read PE
    with open(exe, 'rb') as f:
        data = bytearray(f.read())

    pe = struct.unpack_from('<I', data, 0x3C)[0]
    oh = pe + 24
    magic = struct.unpack_from('<H', data, oh)[0]
    ns = struct.unpack_from('<H', data, pe + 6)[0]
    osz = struct.unpack_from('<H', data, pe + 20)[0]
    so = oh + osz

    # Find last section for placement
    last = so + (ns - 1) * 40
    lr = struct.unpack_from('<I', data, last + 20)[0]
    lrs = struct.unpack_from('<I', data, last + 16)[0]
    lv = struct.unpack_from('<I', data, last + 12)[0]
    lvs = struct.unpack_from('<I', data, last + 8)[0]

    raw_base = (lr + lrs + 0xFFF) & ~0xFFF
    va_base = (lv + lvs + 0xFFF) & ~0xFFF

    # Build section content
    sec = bytearray()
    # Layout: [names] [hint/name] [thunks] [descriptors]

    # 1. DLL name strings
    name_off = {}
    for d in dlls:
        name_off[d] = len(sec)
        sec += d.encode('ascii') + b'\x00'

    # 2. Hint/name entries
    hn_off = {}
    for d in dlls:
        for f in imports[d]:
            hn_off[(d, f)] = len(sec)
            sec += struct.pack('<H', 0)  # hint
            sec += f.encode('ascii') + b'\x00'

    # 3. Thunk tables (8 bytes per entry, null-terminated)
    thunk_off = {}
    for d in dlls:
        thunk_off[d] = len(sec)
        for f in imports[d]:
            rva = va_base + hn_off[(d, f)]
            sec += struct.pack('<Q', (1 << 63) | rva)
        sec += struct.pack('<Q', 0)  # null terminator

    # 4. Import descriptors (20 bytes each)
    desc_off = len(sec)
    for d in dlls:
        sec += struct.pack('<I', va_base + thunk_off[d])  # OriginalFirstThunk
        sec += struct.pack('<I', 0)   # TimeDateStamp
        sec += struct.pack('<I', 0)   # ForwarderChain
        sec += struct.pack('<I', va_base + name_off[d])  # Name
        sec += struct.pack('<I', va_base + thunk_off[d])  # FirstThunk
    # Null terminator
    sec += b'\x00' * 20

    # Align
    while len(sec) % 16: sec += b'\x00'

    # Write section data
    needed = raw_base + len(sec)
    while len(data) < needed: data += b'\x00'
    data[raw_base:raw_base + len(sec)] = bytes(sec)

    # New section header
    sh = last + 40
    data[sh:sh + 8] = b'.idata\x00\x00'
    struct.pack_into('<I', data, sh + 8, len(sec))
    struct.pack_into('<I', data, sh + 12, va_base)
    struct.pack_into('<I', data, sh + 16, len(sec))
    struct.pack_into('<I', data, sh + 20, raw_base)
    struct.pack_into('<I', data, sh + 36, 0xC0000040)

    # Update PE header
    struct.pack_into('<H', data, pe + 6, ns + 1)
    struct.pack_into('<I', data, oh + 56, va_base + ((len(sec) + 0xFFF) & ~0xFFF))

    # Import directory (2nd data dir entry)
    # PE32: oh + 96 + 8 = oh + 104
    # PE32+: oh + 112 + 8 = oh + 120
    id_off = oh + (120 if magic == 0x20b else 104)
    struct.pack_into('<I', data, id_off, va_base + desc_off)
    struct.pack_into('<I', data, id_off + 4, len(sec) - desc_off)

    # Write output
    outpath = out or exe.replace('.exe', '_injected.exe')
    with open(outpath, 'wb') as f:
        f.write(data)

    print(f"  [IAT] {len(dlls)} DLLs, {n_total} imports → {outpath}")
    return outpath
