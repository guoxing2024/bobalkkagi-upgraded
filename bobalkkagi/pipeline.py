"""
Pipeline v2.0 — 纯调度器
=========================
Bobalkkagi v2.0 — P0: 仅负责调度，不包含业务逻辑

架构设计原则:
  - pipeline 仅编排模块执行顺序
  - 所有业务逻辑在各自的 tracker/detector/rebuild 模块中
  - 模块通过 EventBus 解耦
  - 状态在 UnpackContext 中流转
"""

import os
import traceback
from datetime import datetime

from .core.context import UnpackContext
from .core.events import EventType
from .core.plugin import EventBus
from .globalValue import set_context, get_context, DLL_SETTING, HEAP_HANDLE
from .tracker.memory_tracker_v2 import MemoryTrackerV2
from .detector.oep_detector import OEPDetector
from .detector.memory_analyzer import RegionClassifier


class PipelineResult:
    """结构化流水线结果"""
    def __init__(self, status="ok", stage="", message="", dump_path=None, output_path=None, oep=None):
        self.status = status
        self.stage = stage
        self.message = message
        self.dump_path = dump_path
        self.output_path = output_path
        self.oep = oep


class Pipeline:
    """
    自动脱壳流水线 (纯调度器)。
    
    使用方式:
        pipe = Pipeline("path/to/sample.exe", dll_path="win10_v1903")
        result = pipe.run()
        print(f"OEP: 0x{result.oep:x}")
    """
    
    def __init__(self, sample_path: str, dll_path: str = "win10_v1903",
                 force_runtime_iat: bool = False, crc_mode: str = "safe"):
        self.sample_path = sample_path
        self.dll_path = dll_path
        self.ctx = UnpackContext(sample_path)
        self.event_bus = EventBus()
        self.force_runtime_iat = force_runtime_iat
        self.crc_mode = crc_mode
    
    def run(self) -> PipelineResult:
        """运行完整流水线"""
        try:
            # 绑定上下文（兼容旧代码）
            set_context(self.ctx)
            self.ctx.sample_path = self.sample_path
            self.ctx.directory_path = self.dll_path
            
            # 阶段1: 加载
            self._stage_load()
            
            # 阶段2: 模拟
            self._stage_emulate()
            
            # 阶段3: 分析
            self._stage_analyze()
            
            # 阶段4: 检测
            self._stage_detect()
            
            # 阶段5: 重建
            self._stage_rebuild()
            
            return PipelineResult(
                "ok", "", "",
                dump_path=self.ctx.dump_path,
                output_path=self.ctx.output_path,
                oep=self.ctx.oep
            )
        
        except Exception as e:
            tb = traceback.format_exc()
            log_path = os.path.join(os.path.dirname(self.sample_path),
                                   f"{self.ctx.sample_name}_error.log")
            with open(log_path, 'w') as f:
                f.write(f"Error: {e}\n\n{tb}")
            
            return PipelineResult("error", "unknown", str(e))
        
        finally:
            set_context(None)
    
    def _stage_load(self):
        """阶段1: 加载 PE 和 DLL"""
        print(f"\n{'='*60}")
        print(f"  阶段 1/5: 加载 PE + DLL")
        print(f"{'='*60}")
        
        from .unpacking import unpack
        
        # 初始化记录器
        from . import api_recorder
        api_recorder.clear()
        
        # 重置 DLL 状态
        DLL_SETTING.DllFuncs = {}
        DLL_SETTING.LoadedDll = {}
        DLL_SETTING.InverseDllFuncs = {}
        DLL_SETTING.InverseLoadedDll = {}
        HEAP_HANDLE.HeapHandle = [0x000001E9E3850000]
        HEAP_HANDLE.HeapHandleSize = 1
        self.ctx.image_base = 0x140000000
        self.ctx.image_end = 0x140000000
        self.ctx.dll_end = 0x7FF000000000
        self.ctx.allocate_chunk_end = 0x0000020000000000
        self.ctx.section_info = []
        self.ctx.inverse_hook_funcs = {}
        self.ctx.log_queue = []
        self.ctx.text_section = []
        self.ctx.themida_section = []
        self.ctx.boot_section = []
        
        # 执行 Unicorn 模拟
        verbose = False
        mode = 'f'
        oep_flag = 't'
        
        dump, oep = unpack(self.sample_path, verbose, mode, oep_flag)
        
        if not dump or len(dump) == 0:
            raise ValueError("dump数据为空")
        
        if oep is None or oep == 0:
            # 使用备用OEP检测
            oep = self.ctx.entry_point or self.ctx.image_base
        
        self.ctx.dump_path = os.path.join(
            os.path.dirname(self.sample_path),
            f"{self.ctx.sample_name}.dump"
        )
        with open(self.ctx.dump_path, 'wb') as f:
            f.write(dump)
        
        print(f"  加载完成! OEP = 0x{oep:x}")
        
        # Store OEP in context
        self.ctx.oep = oep
    
    def _stage_emulate(self):
        """阶段2: 安装追踪器 (EventBus模式)"""
        print(f"\n{'='*60}")
        print(f"  阶段 2/5: 安装追踪器 + 事件总线")
        print(f"{'='*60}")
        
        # 注意：追踪器需要在 Unicorn 模拟ON EXEC中安装
        # 此处在模拟后安装分析器
        self.ctx.memory_image = bytearray(
            open(self.ctx.dump_path, 'rb').read()
        )
        print(f"  Memory image: {len(self.ctx.memory_image)} bytes")
    
    def _stage_analyze(self):
        """阶段3: 分析 Dump"""
        print(f"\n{'='*60}")
        print(f"  阶段 3/5: 导入扫描 + 区域分析")
        print(f"{'='*60}")
        
        # Import scanning
        from .tracker.import_scanner import scan_and_reconstruct_iat
        if os.path.isdir(self.dll_path):
            scanner_iat = scan_and_reconstruct_iat(
                self.ctx.memory_image, self.ctx.image_base,
                self.dll_path, verbose=True
            )
            # Merge into context
            for dll, funcs in scanner_iat.items():
                if dll not in self.ctx.imports:
                    self.ctx.imports[dll] = []
                for f in funcs:
                    if f not in self.ctx.imports[dll]:
                        self.ctx.imports[dll].append(f)
        
        # Runtime API calls
        from . import api_recorder
        runtime = api_recorder.get_calls_by_dll()
        for dll, funcs in runtime.items():
            # Populate ctx.imports (display dict)
            if dll not in self.ctx.imports:
                self.ctx.imports[dll] = []
            for f in funcs:
                if f not in self.ctx.imports[dll]:
                    self.ctx.imports[dll].append(f)
                # ALSO populates ctx.runtime_api_calls (used by IATRebuilder)
                # This was the ROOT CAUSE of "Low Import Count": the pipe was broken.
                self.ctx.runtime_api_calls.add((dll, f))
    
    def _stage_detect(self):
        """阶段4: OEP 检测 + Memory 分析"""
        print(f"\n{'='*60}")
        print(f"  阶段 4/5: OEP检测 + 区域分析")
        print(f"{'='*60}")
        
        # Memory Analyzer
        from .tracker.memory_tracker import MemoryTracker
        tracker = MemoryTracker()
        
        # Try classifying regions from dump
        if self.ctx.memory_image:
            # Scan executable pages from the dump using capstone
            # Start from first code section, not PE header
            try:
                from capstone import Cs, CS_ARCH_X86, CS_MODE_64
                md = Cs(CS_ARCH_X86, CS_MODE_64)
                exec_count = 0
                # Scan from 0x1000 (skip PE header) 
                scan_start = max(0x1000, self.ctx.oep & 0xFFF) if self.ctx.oep else 0x1000
                scan_size = min(0x100000, len(self.ctx.memory_image) - scan_start)
                for insn in md.disasm(self.ctx.memory_image[scan_start:scan_start+scan_size], 
                                      self.ctx.image_base + scan_start):
                    exec_count += 1
                    if exec_count > 50000:
                        break
                print(f"  Code scan: ~{exec_count} instructions starting at +0x{scan_start:x}")
            except:
                pass
        
        # OEP detection via MemoryTracker
        if self.ctx.oep == 0:
            candidates = tracker.find_oep_candidates()
            if candidates:
                best = candidates[0]
                self.ctx.oep = best['address']
                print(f"  OEP detected: 0x{self.ctx.oep:x} (score={best['score']})")
    
    def _stage_rebuild(self):
        """阶段5: PE + IAT + TLS 重建"""
        print(f"\n{'='*60}")
        print(f"  阶段 5/5: PE + IAT + TLS 重建")
        print(f"{'='*60}")
        
        if not self.ctx.memory_image:
            print("  ❌ 无内存镜像，跳过重建")
            return
        
        # PE rebuild
        from .pe_rebuilder import PERebuilder
        rebuilder = PERebuilder(bytearray(self.ctx.memory_image))
        oep = self.ctx.oep or 0x140000000
        rebuilder.rebuild(oep=oep, verbose=False)
        print(f"  PE section headers 已修复")
        
        # TLS rebuild
        from .rebuild.tls_rebuilder import rebuild_tls
        import pefile
        try:
            orig = pefile.PE(self.sample_path, fast_load=True)
            if rebuild_tls(rebuilder.data, orig, self.ctx.image_base):
                print(f"  TLS 目录已恢复")
        except:
            print(f"  TLS 恢复跳过")
        
        # IAT rebuild
        from .iat_rebuilder import IATRebuilder
        iat = IATRebuilder(
            bytearray(rebuilder.data), self.sample_path,
            runtime_calls=self.ctx.get_runtime_imports(),
            force_runtime_only=self.force_runtime_iat
        )
        iat_success = iat.rebuild(verbose=False)
        
        if iat_success:
            output_path = os.path.join(
                os.path.dirname(self.sample_path),
                f"{os.path.splitext(self.ctx.sample_name)[0]}_unpacked.exe"
            )
            with open(output_path, 'wb') as f:
                f.write(iat.dump_data)
            self.ctx.output_path = output_path
            print(f"  ✅ 重建完成: {output_path}")
        else:
            # Use PE-rebuilt data without IAT
            output_path = os.path.join(
                os.path.dirname(self.sample_path),
                f"{os.path.splitext(self.ctx.sample_name)[0]}_unpacked.exe"
            )
            with open(output_path, 'wb') as f:
                f.write(rebuilder.data)
            self.ctx.output_path = output_path
            print(f"  ⚠ IAT跳过，输出: {output_path}")


def unpack_full(sample_path: str, dll_path: str = "win10_v1903",
                mode: str = 'f', verbose: bool = False) -> PipelineResult:
    """便捷入口函数"""
    pipe = Pipeline(sample_path, dll_path)
    return pipe.run()
