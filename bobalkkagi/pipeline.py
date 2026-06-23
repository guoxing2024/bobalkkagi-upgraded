"""
Pipeline: Full Themida unpack + PE rebuild + IAT reconstruction
===============================================================
Bobalkkagi升级 — 集成流水线

执行顺序：
1. Unpack (existing bobalkkagi unpacker)
2. PE rebuild (fix section headers for flat memory dump)
3. IAT rebuild (restore import table from original PE)

注意：非线程安全 — 使用全局状态(GLOBAL_VAR)，单进程一次只处理一个样本。
"""

import traceback
from datetime import datetime
import os
import logging

from .unpacking import unpack
from .globalValue import GLOBAL_VAR
from .pe_rebuilder import PERebuilder
from .iat_rebuilder import IATRebuilder
from .util import checkInput
from . import api_recorder

BobLog = logging.getLogger("Bobalkkagi.Pipeline")

class PipelineResult:
    """结构化流水线结果"""
    def __init__(self, status="ok", stage="", message="", dump_path=None, output_path=None, oep=None):
        self.status = status          # "ok" | "error"
        self.stage = stage            # 出错的阶段: "unpack" | "pe_rebuild" | "iat_rebuild"
        self.message = message        # 错误信息
        self.dump_path = dump_path    # 原始内存dump路径
        self.output_path = output_path  # 重建后PE路径
        self.oep = oep                # 检测到的OEP
    
    def __bool__(self):
        return self.status == "ok"
    
    def __repr__(self):
        if self.status == "ok":
            return f"<PipelineResult OK oep=0x{self.oep:x}>"
        else:
            return f"<PipelineResult ERROR stage={self.stage} msg={self.message}>"


def unpack_full(protected_file, verbose='f', mode='f', dll_path="win10_v1903", oep_flag='t'):
    """
    Full unpack pipeline with structured error handling.
    
    Args:
        protected_file: Path to Themida-protected PE
        verbose: 't' or 'f' - verbose logging
        mode: 'f'(fast), 'c'(hook_code), 'b'(hook_block)
        dll_path: Directory containing Windows DLLs
        oep_flag: 't' to find OEP, 'f' to skip
    
    Returns:
        PipelineResult with status/stage/message/dump_path/output_path/oep
    """
    base = ""
    output_dir = ""
    
    try:
        verbose_bool = checkInput(verbose) == 't' if isinstance(checkInput(verbose), str) else checkInput(verbose)
        
        # Set global variables (same as application.py)
        GLOBAL_VAR.ProtectedFile = protected_file
        GLOBAL_VAR.DirectoryPath = dll_path
        
        base = os.path.splitext(os.path.basename(protected_file))[0]
        output_dir = os.path.dirname(protected_file)
        
        # ===== Phase 1: Unpack =====
        print(f"\n{'='*60}")
        print(f"  阶段 1/3: Unicorn 模拟脱壳")
        print(f"{'='*60}")
        
        # 初始化运行时API记录器
        api_recorder.clear()
        
        dump, oep = unpack(protected_file, verbose_bool, mode, oep_flag)
        
        if not dump or len(dump) == 0:
            return PipelineResult("error", "unpack", "dump数据为空")
        
        if oep is None or oep == 0:
            return PipelineResult("error", "unpack", "未找到OEP")
        
        print(f"\n  脱壳完成! OEP = 0x{oep:x}")
        
        # Save raw dump
        dump_path = os.path.join(output_dir, f"{base}.dump")
        with open(dump_path, 'wb') as f:
            f.write(dump)
        
        # ===== Phase 2: PE rebuild =====
        print(f"\n{'='*60}")
        print(f"  阶段 2/3: PE 重建")
        print(f"{'='*60}")
        
        dump_data = bytearray(dump)
        rebuilder = PERebuilder(dump_data)
        rebuilder.rebuild(oep=oep, verbose=False)
        
        print(f"  PE section headers 已修复")
        
        # ===== Phase 3: IAT rebuild =====
        print(f"\n{'='*60}")
        print(f"  阶段 3/3: IAT 重建")
        print(f"{'='*60}")
        
        # 获取运行时API记录，补充IAT
        runtime_calls = api_recorder.get_calls_by_dll()
        runtime_count = sum(len(v) for v in runtime_calls.values())
        if runtime_calls:
            print(f"  运行时API调用记录: {runtime_count}个函数, {len(runtime_calls)}个DLL")
            # 打印重要DLL的调用
            for dll in sorted(runtime_calls.keys()):
                funcs = runtime_calls[dll]
                if len(funcs) <= 5:
                    print(f"    {dll}: {', '.join(funcs)}")
                else:
                    print(f"    {dll}: {', '.join(funcs[:5])} ...({len(funcs)})")
        
        iat = IATRebuilder(bytearray(rebuilder.data), protected_file, runtime_calls=runtime_calls)
        iat_success = iat.rebuild(verbose=False)
        
        if not iat_success:
            print("  ⚠ IAT重建失败，跳过导入表修复")
            # Use PE-rebuilt data without IAT fix
            output_path = os.path.join(output_dir, f"{base}_unpacked.exe")
            with open(output_path, 'wb') as f:
                f.write(rebuilder.data)
            
            print(f"\n{'='*60}")
            print(f"  ⚠ 脱壳完成(无IAT)")
            print(f"  OEP: 0x{oep:x}")
            print(f"  输出: {output_path}")
            print(f"  大小: {os.path.getsize(output_path)} bytes")
            print(f"{'='*60}")
            
            return PipelineResult("ok", "", "", dump_path, output_path, oep)
        
        print(f"  导入表已重建")
        
        # Write final output
        output_path = os.path.join(output_dir, f"{base}_unpacked.exe")
        with open(output_path, 'wb') as f:
            f.write(iat.dump_data)
        
        print(f"\n{'='*60}")
        print(f"  ✅ 完整脱壳完成!")
        print(f"  OEP: 0x{oep:x}")
        print(f"  输出: {output_path}")
        print(f"  大小: {os.path.getsize(output_path)} bytes")
        print(f"{'='*60}")
        
        return PipelineResult("ok", "", "", dump_path, output_path, oep)
    
    except FileNotFoundError as e:
        msg = f"文件未找到: {e}"
        print(f"❌ {msg}")
        return PipelineResult("error", "unpack", msg)
    
    except ImportError as e:
        msg = f"缺少依赖: {e}"
        print(f"❌ {msg}")
        return PipelineResult("error", f"dependency_{e.name}", msg)
    
    except Exception as e:
        stage = "unknown"
        tb = traceback.format_exc()
        msg = f"{e}"
        
        if "unpack" in str(e).lower() or "emu_start" in str(e).lower():
            stage = "unpack"
        elif "rebuild" in str(type(e).__name__).lower() or "section" in str(e).lower():
            stage = "pe_rebuild"
        elif "iat" in str(type(e).__name__).lower() or "import" in str(e).lower():
            stage = "iat_rebuild"
        
        print(f"❌ [{stage}] 流水线异常: {e}")
        if output_dir:
            log_path = os.path.join(output_dir, f"{base}_error.log")
            with open(log_path, 'w') as f:
                f.write(f"Stage: {stage}\nError: {e}\n\nTraceback:\n{tb}")
            print(f"   详细日志: {log_path}")
        
        return PipelineResult("error", stage, msg)
