"""
Pipeline v3.0 — 多后端调度器
=============================
Bobalkkagi v3.0 — P2: 支持 Unicorn / Debugger 双后端，通过统一接口调度。

架构设计原则:
  - pipeline 仅编排模块执行顺序，不依赖具体后端
  - 所有后端通过 IExecutionBackend 接口接入
  - 失败时自动降级 (debugger → unicorn)
  - 状态在 UnpackContext 中流转
"""

import os
import traceback
from datetime import datetime

from .core.context import UnpackContext
from .core.events import EventType
from .core.plugin import EventBus
from .core.backend import IExecutionBackend, BackendType, BackendExecutionError
from .globalValue import set_context, get_context, DLL_SETTING, HEAP_HANDLE
from .tracker.memory_tracker_v2 import MemoryTrackerV2
from .detector.oep_detector import OEPDetector
from .detector.memory_analyzer import RegionClassifier
from .engine import create_backend


class PipelineResult:
    """结构化流水线结果"""
    def __init__(self, status="ok", stage="", message="", dump_path=None, output_path=None, oep=None,
                 backend_used="", vm_analysis=None):
        self.status = status
        self.stage = stage
        self.message = message
        self.dump_path = dump_path
        self.output_path = output_path
        self.oep = oep
        self.backend_used = backend_used
        self.vm_analysis = vm_analysis or {}  # P3: VM分析结果


class Pipeline:
    """
    自动脱壳流水线 (多后端调度器)。

    使用方式:
        pipe = Pipeline("protected.exe", dll_path="win10_v1903")
        result = pipe.run()
        print(f"OEP: 0x{result.oep:x}")

        pipe_debug = Pipeline("protected.exe", backend="debugger")
        result = pipe_debug.run()
    """

    def __init__(self, sample_path: str, dll_path: str = "win10_v1903",
                 force_runtime_iat: bool = False, crc_mode: str = "safe",
                 backend: str = "unicorn",
                 vm_mode: str = "off",
                 vtil_target: str = "auto",
                 **backend_kwargs):
        self.sample_path = sample_path
        self.dll_path = dll_path
        self.ctx = UnpackContext(sample_path)
        self.event_bus = EventBus()
        self.force_runtime_iat = force_runtime_iat
        self.crc_mode = crc_mode

        # P2: 执行后端
        self._backend_type = backend
        self._backend_kwargs = backend_kwargs
        self._backend_kwargs.setdefault('crc_mode', crc_mode)
        self._backend: IExecutionBackend = None

        # P3: VM 分析
        self._vm_mode = vm_mode           # off / detect / lift / devirt
        self._vtil_target = vtil_target   # auto / themida / vmprotect

        # P3: VM 分析结果
        self._vm_analysis_result: dict = {}

    def run(self) -> PipelineResult:
        """运行完整流水线"""
        try:
            # 绑定上下文（兼容旧代码）
            set_context(self.ctx)
            self.ctx.sample_path = self.sample_path
            self.ctx.directory_path = self.dll_path

            # 阶段1: 创建后端 + 加载
            self._stage_load()

            # 阶段2: 模拟
            self._stage_emulate()

            # 阶段3: 分析
            self._stage_analyze()

            # 阶段3b: VM 分析 (P3)
            if self._vm_mode != "off":
                self._stage_vm_analyze()

            # 阶段4: 检测
            self._stage_detect()

            # 阶段5: 重建
            self._stage_rebuild()

            return PipelineResult(
                "ok", "", "",
                dump_path=self.ctx.dump_path,
                output_path=self.ctx.output_path,
                oep=self.ctx.oep,
                backend_used=self._backend_type,
                vm_analysis=self._vm_analysis_result,
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
        """阶段1: 创建执行后端 + 加载 PE 和 DLL + 执行"""
        print(f"\n{'='*60}")
        print(f"  阶段 1/5: 加载 PE + DLL [后端: {self._backend_type}]")
        print(f"{'='*60}")

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

        # P2: 创建执行后端
        self._backend = create_backend(self._backend_type, **self._backend_kwargs)

        # 1. 初始化后端
        if not self._backend.initialize(self.ctx):
            if self._backend_type == "debugger":
                print(f"  ⚠ Debugger backend failed, falling back to unicorn")
                self._backend_type = "unicorn"
                self._backend = create_backend("unicorn", crc_mode=self.crc_mode)
                if not self._backend.initialize(self.ctx):
                    raise RuntimeError("Unicorn backend init failed")
            else:
                raise RuntimeError(f"{self._backend.display_name} init failed")

        # 2. 加载目标
        if not self._backend.load_target(self.ctx):
            raise RuntimeError(f"{self._backend.display_name} failed to load target")

        # 3. 安装钩子
        if not self._backend.install_hooks(self.ctx):
            raise RuntimeError(f"{self._backend.display_name} failed to install hooks")

        # 4. 执行
        print(f"\n  [{self._backend.display_name}] Starting execution...")
        exec_result = self._backend.execute(self.ctx)

        if not exec_result.success and not exec_result.dump_data:
            raise RuntimeError(
                f"{self._backend.display_name} execution failed: {exec_result.error_message}"
            )

        # 5. 导出 dump
        dump = self._backend.dump_memory(self.ctx)
        if not dump or len(dump) == 0:
            raise ValueError("dump数据为空")

        oep = exec_result.oep or self._backend.get_oep(self.ctx)
        if oep is None or oep == 0:
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

        # P3: 从执行结果提取运行时VM入口
        if exec_result.extra.get("vm_entries"):
            self._vm_analysis_result["detected"] = True
            self._vm_analysis_result["engine"] = "themida"
            self._vm_analysis_result["entry_points"] = [f"0x{e:x}" for e in exec_result.extra["vm_entries"]]
            print(f"  🎯 Runtime VM entries: {len(exec_result.extra['vm_entries'])} captured")

        # 6. 清理后端
        self._backend.cleanup(self.ctx)

    def _stage_emulate(self):
        """阶段2: 安装追踪器 (EventBus模式)"""
        print(f"\n{'='*60}")
        print(f"  阶段 2/5: 安装追踪器 + 事件总线")
        print(f"{'='*60}")

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
            if dll not in self.ctx.imports:
                self.ctx.imports[dll] = []
            for f in funcs:
                if f not in self.ctx.imports[dll]:
                    self.ctx.imports[dll].append(f)
                self.ctx.runtime_api_calls.add((dll, f))

    def _stage_vm_analyze(self):
        """阶段3b: VM 分析 (P3) — 入口检测 + Handler提取 + stub扫描"""
        print(f"\n{'='*60}")
        print(f"  阶段 3b/5: VM 分析 [mode={self._vm_mode}, target={self._vtil_target}]")
        print(f"{'='*60}")

        result = {"detected": False, "engine": "auto"}

        if not self.ctx.memory_image:
            print("  ❌ 无内存镜像，跳过 VM 分析")
            self._vm_analysis_result = result
            return

        from .vm.analyzer import VMAnalyzer
        from .vtil.lift_engine import VTILLiftEngine

        lift_engine = VTILLiftEngine()
        vm = VMAnalyzer(self.ctx, lift_engine)

        # 分析（文件扫描 + .boot 回退）
        result = vm.analyze(self.ctx.memory_image, self.ctx.image_base)

        # 合并运行时VM入口（从UnicornBackend执行阶段捕获）
        if self._vm_analysis_result.get("detected") and self._vm_analysis_result.get("entry_points"):
            if not result.get("detected"):
                result["detected"] = True
                result["engine"] = self._vm_analysis_result.get("engine", "themida")
            existing = set(result.get("entry_points", []))
            for ep in self._vm_analysis_result["entry_points"]:
                if ep not in existing:
                    result["entry_points"].append(ep)
            print(f"  🔗 Merged {len(self._vm_analysis_result['entry_points'])} runtime VM entries")

        # 如果文件扫描没找到，尝试从 .boot 段扫描 (bootstrap代码在这里跳转到VM)
        if not result["detected"] and self.ctx.memory_image:
            boot = getattr(self.ctx, 'boot_section', None)
            if boot and len(boot) >= 3:
                boot_va = boot[1]
                entries = vm.detect_vm_entry_runtime(boot_va, self.ctx.memory_image, self.ctx.image_base)
                if entries:
                    result["detected"] = True
                    result["engine"] = "themida"
                    result["entry_points"] = [f"0x{e:x}" for e in entries]
                    print(f"  ✅ Runtime VM entry detected via .boot section scan")

        if result["detected"]:
            print(f"  ✅ VM detected: {result['engine']}")
            print(f"     entries: {result['entry_points']}")
            print(f"     handlers: {result['handler_count']}")
            print(f"     bytecode: {result['bytecode_size']} bytes")
        else:
            print(f"  ℹ No VM entry detected")

        # lift 模式: 提升且简化 handler
        if self._vm_mode == "lift" and result["detected"]:
            print(f"  [LIFT] VTIL summary: {result['vtil_summary']}")

        self._vm_analysis_result = result

        # Stub 扫描 (Phase 3)
        if self._vm_mode in ("lift", "devirt"):
            from .iat.runtime_scanner import RuntimeIATScanner
            scanner = RuntimeIATScanner(lift_engine)
            stubs = scanner.scan_stubs(self.ctx, target=self._vtil_target)
            if stubs:
                print(f"  [IATScanner] {len(stubs)} import stubs identified")
                result["stub_count"] = len(stubs)
                self._scanned_stubs = stubs

    def _stage_detect(self):
        """阶段4: OEP 检测 + Memory 分析"""
        print(f"\n{'='*60}")
        print(f"  阶段 4/5: OEP检测 + 区域分析")
        print(f"{'='*60}")

        from .tracker.memory_tracker import MemoryTracker
        tracker = MemoryTracker()

        if self.ctx.memory_image:
            try:
                from capstone import Cs, CS_ARCH_X86, CS_MODE_64
                md = Cs(CS_ARCH_X86, CS_MODE_64)
                exec_count = 0
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

        from .pe_rebuilder import PERebuilder
        rebuilder = PERebuilder(bytearray(self.ctx.memory_image))
        oep = self.ctx.oep or 0x140000000
        rebuilder.rebuild(oep=oep, verbose=False)
        print(f"  PE section headers 已修复")

        from .rebuild.tls_rebuilder import rebuild_tls
        import pefile
        try:
            orig = pefile.PE(self.sample_path, fast_load=True)
            if rebuild_tls(rebuilder.data, orig, self.ctx.image_base):
                print(f"  TLS 目录已恢复")
        except:
            print(f"  TLS 恢复跳过")

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
            output_path = os.path.join(
                os.path.dirname(self.sample_path),
                f"{os.path.splitext(self.ctx.sample_name)[0]}_unpacked.exe"
            )
            with open(output_path, 'wb') as f:
                f.write(rebuilder.data)
            self.ctx.output_path = output_path
            print(f"  ⚠ IAT跳过，输出: {output_path}")


def unpack_full(sample_path: str, dll_path: str = "win10_v1903",
                mode: str = 'f', verbose: bool = False,
                backend: str = "unicorn") -> PipelineResult:
    """便捷入口函数"""
    pipe = Pipeline(sample_path, dll_path,
                    backend=backend, emu_mode=mode, verbose=verbose)
    return pipe.run()
