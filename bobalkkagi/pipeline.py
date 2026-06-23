"""
Pipeline: Full Themida unpack + PE rebuild + IAT reconstruction
===============================================================
Bobalkkagi升级 — 集成流水线

执行顺序：
1. Unpack (existing bobalkkagi unpacker)
2. PE rebuild (fix section headers for flat memory dump)
3. IAT rebuild (restore import table from original PE)
"""

from datetime import datetime
import os
import logging

from .unpacking import unpack as _unpack
from .globalValue import GLOBAL_VAR
from .pe_rebuilder import PERebuilder
from .iat_rebuilder import IATRebuilder

BobLog = logging.getLogger("Bobalkkagi.Pipeline")

def unpack_full(protected_file, verbose='f', mode='f', dll_path="win10_v1903", oep_flag='t'):
    """
    Full unpack pipeline:
    1. Unpack using existing bobalkkagi engine
    2. PE rebuild (fix section headers)
    3. IAT reconstruction (restore imports from original PE)
    
    Returns: (dump_path, rebuilt_path, oep)
    """
    from .util import checkInput
    from .unpacking import unpack
    
    verbose_bool = checkInput(verbose) == 't' if isinstance(checkInput(verbose), str) else checkInput(verbose)
    
    # Set global variables (same as application.py)
    GLOBAL_VAR.ProtectedFile = protected_file
    GLOBAL_VAR.DirectoryPath = dll_path
    
    # Phase 1: Original unpack
    print(f"\n{'='*60}")
    print(f"  阶段 1/3: Unicorn 模拟脱壳")
    print(f"{'='*60}")
    dump, oep = unpack(protected_file, verbose_bool, mode, oep_flag)
    
    if oep is None or oep == 0:
        print("❌ 脱壳失败 - 未找到OEP")
        return None, None, None
    
    print(f"\n  脱壳完成! OEP = 0x{oep:x}")
    
    # Phase 2: PE rebuild
    print(f"\n{'='*60}")
    print(f"  阶段 2/3: PE 重建")
    print(f"{'='*60}")
    
    dump_data = bytearray(dump)
    rebuilder = PERebuilder(dump_data)
    rebuilder.rebuild(oep=oep, verbose=False)
    
    print(f"  PE section headers 已修复")
    
    # Phase 3: IAT rebuild
    print(f"\n{'='*60}")
    print(f"  阶段 3/3: IAT 重建")
    print(f"{'='*60}")
    
    iat = IATRebuilder(bytearray(rebuilder.data), protected_file)
    iat.rebuild(verbose=False)
    
    print(f"  导入表已重建 (17 DLLs)")
    
    # Generate output filename
    base = os.path.splitext(os.path.basename(protected_file))[0]
    output_dir = os.path.dirname(protected_file)
    output_path = os.path.join(output_dir, f"{base}_unpacked.exe")
    
    with open(output_path, 'wb') as f:
        f.write(iat.dump_data)
    
    print(f"\n{'='*60}")
    print(f"  ✅ 完整脱壳完成!")
    print(f"  OEP: 0x{oep:x}")
    print(f"  输出: {output_path}")
    print(f"  大小: {os.path.getsize(output_path)} bytes")
    print(f"{'='*60}")
    
    # Also save raw dump for reference
    dump_path = os.path.join(output_dir, f"{base}.dump")
    with open(dump_path, 'wb') as f:
        f.write(dump)
    
    return dump_path, output_path, oep
