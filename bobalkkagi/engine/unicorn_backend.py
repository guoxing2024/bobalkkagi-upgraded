"""
Unicorn Backend — 纯模拟执行引擎
===================================
Bobalkkagi v3.0 — P2: 将现有 unpacking.py 封装为标准 IExecutionBackend 接口。

底层仍然是 Unicorn CPU Emulator，但现在通过统一接口暴露：
  - initialize  → 创建 Unicorn 引擎
  - load_target → PE_Loader + setUpStructure
  - install_hooks → InsertHookFlag + CRC bypass + hook code/block/api
  - execute     → uc.emu_start() → 捕获 UcError → 读取 OEP
  - dump_memory → uc.mem_read()
  - cleanup     → 释放引擎

优势:
  1. 与 DebuggerBackend 共享统一接口，Pipeline 无需区分
  2. 现有 unpacking.py 仍可独立使用（向后兼容）
  3. 日志和错误处理更规范
"""

import os
import struct
import logging
from datetime import datetime
from typing import Optional

# Unicorn imports — 现有代码依赖
from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UcError
from unicorn.x86_const import UC_X86_REG_RAX, UC_X86_REG_RBX, UC_X86_REG_RCX
from unicorn.x86_const import UC_X86_REG_RDX, UC_X86_REG_RDI, UC_X86_REG_RSI
from unicorn.x86_const import UC_X86_REG_RSP, UC_X86_REG_RBP, UC_X86_REG_RIP
from unicorn.x86_const import UC_X86_REG_R8, UC_X86_REG_R9, UC_X86_REG_R10
from unicorn.x86_const import UC_X86_REG_R11, UC_X86_REG_R12, UC_X86_REG_R13
from unicorn.x86_const import UC_X86_REG_R14, UC_X86_REG_R15, UC_X86_REG_EFLAGS
from unicorn.x86_const import UC_X86_REG_CS, UC_X86_REG_GS_BASE

from ..core.backend import (
    IExecutionBackend, BackendType, ExecutionStage,
    ExecutionResult, BackendExecutionError
)

BobLog = logging.getLogger("Bobalkkagi.UnicornBackend")


class UnicornBackend(IExecutionBackend):
    """
    Unicorn CPU Emulator 执行后端。

    特性:
      - 纯模拟，无操作系统依赖
      - 84个API Hook完整伪装
      - CRC校验绕过（safe/aggressive/off）
      - PEB/TEB/KUSER环境模拟
      - 兼容现有所有 hook 函数

    限制:
      - 无法对抗硬件断点/时序检测
      - 单线程模型
      - 不处理真实系统调用
    """

    def __init__(self, crc_mode: str = "safe", emu_mode: str = 'f', verbose: bool = False):
        self._crc_mode = crc_mode
        self._emu_mode = emu_mode  # 'f'=fast, 'c'=hook_code, 'b'=hook_block
        self._verbose = verbose
        self._uc: Optional[Uc] = None
        self._oep: int = 0
        self._ep: int = 0
        self._running: bool = False
        self._pe = None

        # P3: Runtime VM entry detection
        self._themida_base = 0
        self._themida_end = 0
        self._vm_entry_detected = False
        self._captured_vm_entries: List[int] = []

    # ===== 元信息 =====

    @property
    def backend_type(self) -> BackendType:
        return BackendType.UNICORN

    @property
    def display_name(self) -> str:
        return "Unicorn CPU Emulator"

    @property
    def capabilities(self) -> dict:
        return {
            "hardware_anti_debug": False,
            "timing_detection": False,
            "multi_threading": False,
            "network_simulation": False,
            "requires_process": False,
            "stealth_level": "none",
            "api_hooks": 84,
            "crc_bypass_modes": ["safe", "aggressive", "off"],
            "emu_modes": ["fast", "hook_code", "hook_block"],
        }

    # ===== 生命周期 =====

    def initialize(self, ctx) -> bool:
        """创建 Unicorn 引擎"""
        try:
            import pefile
            self._pe = pefile.PE(ctx.sample_path)
            self._ep = self._pe.OPTIONAL_HEADER.AddressOfEntryPoint
        except Exception as e:
            ctx.status = f"PE parse failed: {e}"
            return False

        try:
            self._uc = Uc(UC_ARCH_X86, UC_MODE_64)
            ctx.backend_capabilities = self.capabilities
            self._running = False
            print(f"  [UnicornBackend] Engine created (mode={self._emu_mode}, crc={self._crc_mode})")
            return True
        except Exception as e:
            ctx.status = f"Unicorn init failed: {e}"
            return False

    def load_target(self, ctx) -> bool:
        """加载 PE + DLL + 栈 + 环境结构"""
        if not self._uc:
            return False

        from ..loader import PE_Loader
        from ..unpacking import setUpStructure
        from ..globalValue import GLOBAL_VAR
        from ..constValue import StackLimit, StackBase

        # Unicorn memory protection constants
        UC_PROT_ALL = 7  # UC_PROT_READ | UC_PROT_WRITE | UC_PROT_EXEC

        # 栈空间
        self._uc.mem_map(StackLimit, StackBase - StackLimit, UC_PROT_ALL)

        try:
            # 用现有的 PE_Loader（依赖 GLOBAL_VAR 代理，已指向 ctx）
            PE_Loader(self._uc, ctx.sample_path, GLOBAL_VAR.image_base, True)
            PE_Loader(self._uc, "user32.dll", GLOBAL_VAR.dll_end, False)
        except Exception as e:
            print(f"  [UnicornBackend] PE load error: {e}")
            return False

        # PEB/TEB/KUSER 环境
        setUpStructure(self._uc)

        # Hook 区域
        self._uc.mem_map(GLOBAL_VAR.hook_region, 0x1000, UC_PROT_ALL)

        print(f"  [UnicornBackend] Target loaded: EP=0x{self._ep:x}")
        return True

    def install_hooks(self, ctx) -> bool:
        """安装钩子系统"""
        if not self._uc:
            return False

        from ..globalValue import GLOBAL_VAR, DLL_SETTING, InvDllDict
        from ..hookFuncs import HookFuncs
        from ..unpacking import (
            InsertHookFlag, hook_code, hook_block, hook_api,
            hook_mem_read_unmapped, InsPatch, setup_logger,
            InvHookFuncDict
        )
        from ..crc_bypass import crc_bypass_post_load

        InvDllDict()
        InsertHookFlag(self._uc)
        InvHookFuncDict()

        # Install Unicorn hooks
        from unicorn import UC_HOOK_MEM_WRITE_PROT, UC_HOOK_CODE, UC_HOOK_BLOCK

        self._uc.hook_add(UC_HOOK_MEM_WRITE_PROT, hook_mem_read_unmapped)

        # InsPatch hook (ntdll + kernelbase range)
        if "ntdll.dll" in DLL_SETTING.LoadedDll and "kernelbase.dll" in DLL_SETTING.LoadedDll:
            self._uc.hook_add(UC_HOOK_CODE, InsPatch, None,
                             DLL_SETTING.LoadedDll["ntdll.dll"],
                             DLL_SETTING.LoadedDll["kernelbase.dll"])

        # 执行模式
        if self._emu_mode == 'c':
            self._uc.hook_add(UC_HOOK_CODE, hook_code)
            self._verbose = True
        elif self._emu_mode == 'b':
            GLOBAL_VAR.debug_option = False
            self._verbose = True
            self._uc.hook_add(UC_HOOK_BLOCK, hook_block)
        elif self._emu_mode == 'f':
            self._uc.hook_add(UC_HOOK_BLOCK, hook_api, None,
                             GLOBAL_VAR.hook_region,
                             GLOBAL_VAR.hook_region + 0x1000)

        setup_logger(self._uc, BobLog, self._verbose)

        # CRC bypass
        crc_patches = 0
        if self._crc_mode != "off":
            if GLOBAL_VAR.themida_section and GLOBAL_VAR.boot_section:
                crc_patches = crc_bypass_post_load(
                    self._uc, GLOBAL_VAR.themida_section,
                    GLOBAL_VAR.boot_section, GLOBAL_VAR.image_base,
                    mode=self._crc_mode
                )

        print(f"  [UnicornBackend] Hooks installed (mode={self._emu_mode}, crc={self._crc_mode}, crc_patches={crc_patches})")

        # P3: 运行时VM入口检测 — 监控RIP首次进入.themida段
        from unicorn import UC_HOOK_CODE as UC_CODE
        self._vm_entry_detected = False
        self._captured_vm_entries = []
        self._themida_base = 0
        self._themida_end = 0
        if GLOBAL_VAR.themida_section and len(GLOBAL_VAR.themida_section) >= 3:
            self._themida_base = GLOBAL_VAR.themida_section[1]
            self._themida_end = self._themida_base + GLOBAL_VAR.themida_section[2]
            self._uc.hook_add(UC_CODE, self._on_themida_entry, None, self._themida_base, self._themida_end)
            print(f"  [UnicornBackend] VM entry hook: 0x{self._themida_base:x}-0x{self._themida_end:x}")

        return True

    def _on_themida_entry(self, uc, address, size, user_data):
        """P3: RIP进入.themida段时触发 — 捕获VM入口签名"""
        if self._vm_entry_detected:
            return  # 只触发一次
        self._vm_entry_detected = True

        try:
            code = uc.mem_read(address, 256)
            bytecode = bytes(code)
            # 保存入口地址
            self._captured_vm_entries.append(address)
            print(f"  [UnicornBackend] 🎯 VM entry detected at RIP=0x{address:x}")

            # 尝试匹配VM入口签名
            from ..vm.analyzer import VMAnalyzer, THEMIDA_VM_SIGNATURES
            vm = VMAnalyzer.__new__(VMAnalyzer)  # 轻量实例，不需要ctx
            try:
                from capstone import Cs, CS_ARCH_X86, CS_MODE_64
                vm._capstone = Cs(CS_ARCH_X86, CS_MODE_64)
                for sig in THEMIDA_VM_SIGNATURES:
                    results = vm._match_signature(bytecode, address, sig)
                    if results:
                        self._captured_vm_entries.extend(results)
                        print(f"  [UnicornBackend] VM signature matched: {sig.name}")
                        break
            except ImportError:
                pass
        except Exception as e:
            print(f"  [UnicornBackend] VM entry hook error: {e}")

    def execute(self, ctx) -> ExecutionResult:
        """执行 Unicorn 模拟"""
        if not self._uc:
            return ExecutionResult(success=False, backend=self.display_name,
                                   stage=ExecutionStage.ERROR,
                                   error_message="Engine not initialized")

        from ..globalValue import GLOBAL_VAR, DLL_SETTING
        from ..unpacking import PebBase
        start_time = datetime.now()

        # 设置寄存器（模拟 TLS 回调后的入口状态）
        self._uc.reg_write(UC_X86_REG_RAX, GLOBAL_VAR.image_base + self._ep)
        self._uc.reg_write(UC_X86_REG_RBX, 0x0)
        self._uc.reg_write(UC_X86_REG_RCX, PebBase)
        self._uc.reg_write(UC_X86_REG_RDX, GLOBAL_VAR.image_base + self._ep)
        self._uc.reg_write(UC_X86_REG_R8, PebBase)
        self._uc.reg_write(UC_X86_REG_R9, GLOBAL_VAR.image_base + self._ep)
        self._uc.reg_write(UC_X86_REG_EFLAGS, 0x244)

        self._running = True
        oep = 0
        error_msg = ""

        try:
            self._uc.emu_start(GLOBAL_VAR.image_base + self._ep,
                              GLOBAL_VAR.image_end)
        except UcError as e:
            BobLog.error(f"Unicorn stopped: {e}")
            oep = self._uc.reg_read(UC_X86_REG_RIP)
            BobLog.info(f"Find OEP: {oep:x}")
            error_msg = str(e)

        self._running = False
        elapsed = (datetime.now() - start_time).total_seconds()

        # 收集统计
        from .. import api_recorder
        api_calls = len(api_recorder._api_calls) if hasattr(api_recorder, '_api_calls') else 0
        crc_patches = len(getattr(
            __import__('bobalkkagi.crc_bypass', fromlist=['CRC_PATCH_LOG']),
            'CRC_PATCH_LOG', []
        ))

        result = ExecutionResult(
            success=(oep > 0),
            backend=self.display_name,
            stage=ExecutionStage.DONE,
            dump_data=None,
            oep=oep or self._ep,
            image_base=GLOBAL_VAR.image_base,
            image_end=GLOBAL_VAR.image_end,
            api_calls=api_calls,
            crc_patches=crc_patches,
            elapsed_seconds=elapsed,
            error_message=error_msg if not oep else "",
            diagnosis="",
        )

        if oep == 0:
            result.warnings.append("oep_not_found")
            result.diagnosis = (
                f"Emulation terminated without capturing OEP. RIP at crash: unknown. "
                f"Try hook_code mode for deeper per-instruction tracing."
            )

        # P3: VM entry detection results
        if self._captured_vm_entries:
            result.extra["vm_entries"] = self._captured_vm_entries
            result.diagnosis += (
                f" | VM entries captured: {len(self._captured_vm_entries)}"
            )

        return result

    def dump_memory(self, ctx) -> Optional[bytes]:
        """导出完整内存dump"""
        if not self._uc:
            return None

        from ..globalValue import GLOBAL_VAR
        try:
            size = GLOBAL_VAR.image_end - GLOBAL_VAR.image_base
            if size <= 0:
                return None
            dump = self._uc.mem_read(GLOBAL_VAR.image_base, size)
            print(f"  [UnicornBackend] Memory dump: {len(dump)} bytes (0x{GLOBAL_VAR.image_base:x}-0x{GLOBAL_VAR.image_end:x})")
            return bytes(dump)
        except Exception as e:
            print(f"  [UnicornBackend] Dump failed: {e}")
            return None

    def get_oep(self, ctx) -> int:
        return self._oep if self._oep else 0

    def cleanup(self, ctx) -> None:
        """释放 Unicorn 资源"""
        if self._uc:
            try:
                del self._uc
            except:
                pass
            self._uc = None
            self._running = False
            print(f"  [UnicornBackend] Cleanup done")

    # ===== 状态查询 =====

    def is_running(self) -> bool:
        return self._running

    def get_current_rip(self) -> int:
        if self._uc:
            try:
                return self._uc.reg_read(UC_X86_REG_RIP)
            except:
                return 0
        return 0

    def read_memory(self, address: int, size: int) -> bytes:
        if self._uc:
            try:
                return bytes(self._uc.mem_read(address, size))
            except:
                return b''
        return b''

    # ===== 辅助 =====

    def set_mode(self, mode: str):
        """运行时切换执行模式"""
        if mode in ('f', 'c', 'b'):
            self._emu_mode = mode

    def set_crc_mode(self, crc_mode: str):
        """运行时切换CRC模式"""
        if crc_mode in ('safe', 'aggressive', 'off'):
            self._crc_mode = crc_mode
