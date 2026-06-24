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
from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UcError, UC_HOOK_INSN
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
        self._emu_mode = emu_mode
        self._verbose = verbose
        self._uc: Optional[Uc] = None
        self._oep: int = 0
        self._ep: int = 0
        self._running: bool = False
        self._pe = None
        self._cached_dump: Optional[bytes] = None

        # P3: Magicmida memory trap (Unicorn)
        self._text_base = 0
        self._text_size = 0
        self._tls_entries: List[int] = []
        self._trap_oep: int = 0
        self._trap_active = False

        # P3: Runtime VM entry detection
        self._themida_base = 0
        self._themida_end = 0
        self._vm_entry_detected = False
        self._captured_vm_entries: List[int] = []
        self._oep_suspects: List[dict] = []

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
        """加载 PE + DLL — 委托给 unpack()，此处仅做最小初始化"""
        # P3: unpack() 内部自行处理 PE_Loader，不需要我们重复
        print(f"  [UnicornBackend] load_target: delegating to unpack()")
        return True

    def install_hooks(self, ctx) -> bool:
        """安装钩子 — 委托给 unpack()"""
        print(f"  [UnicornBackend] install_hooks: delegating to unpack()")
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
        """Magicmida-style: 内存陷阱 OEP 捕获 (委托 unpack)"""
        if not self._uc:
            return ExecutionResult(success=False, backend=self.display_name,
                                   stage=ExecutionStage.ERROR,
                                   error_message="Engine not initialized")

        from ..globalValue import GLOBAL_VAR, DLL_SETTING
        from ..unpacking import unpack
        import struct
        start_time = datetime.now()

        # 扩大内存映射
        if GLOBAL_VAR.image_end < GLOBAL_VAR.image_base + 0x2000000:
            try:
                extra = GLOBAL_VAR.image_base + 0x2000000 - GLOBAL_VAR.image_end
                self._uc.mem_map(GLOBAL_VAR.image_end, extra, 7)
                GLOBAL_VAR.image_end += extra
            except:
                pass

        # 转换模式名 (agent_unpack 传 'fast'/'deep', unpack() 需要 'f'/'c'/'b')
        mode_map = {'fast': 'f', 'deep': 'c', 'hook_code': 'c', 'hook_block': 'b'}
        inner_mode = mode_map.get(self._emu_mode, self._emu_mode)
        if len(inner_mode) > 1 and inner_mode not in ('fast','deep'):
            inner_mode = 'f'  # default fallback

        self._running = True
        oep = 0
        error_msg = ""
        dump_data = None
        self._oep_suspects = []  # P3: OEP tracker suspects

        # P3: 注入 OEP 追踪器 — 包装 hook_code 和 hook_api
        import bobalkkagi.unpacking as up_mod
        orig_hook_code = up_mod.hook_code
        orig_hook_api = up_mod.hook_api

        def tracked_hook_code(uc, address, size, user_data):
            result = orig_hook_code(uc, address, size, user_data)
            self._track_oep_escape(uc, address)
            return result

        def tracked_hook_api(uc, address, size, user_data):
            result = orig_hook_api(uc, address, size, user_data)
            self._track_oep_escape(uc, address)
            return result

        up_mod.hook_code = tracked_hook_code
        up_mod.hook_api = tracked_hook_api

        # V6: Syscall interceptor — monkey-patch Uc.emu_start to install hook
        import unicorn as uc_mod
        from unicorn.x86_const import UC_X86_INS_SYSCALL
        from .syscall_interceptor import SyscallInterceptor
        orig_emu_start = uc_mod.Uc.emu_start

        def patched_emu_start(self_uc, *args, **kwargs):
            # Install syscall interceptor on every UC engine
            interceptor = SyscallInterceptor(self_uc, verbose=self._verbose)
            self_uc.hook_add(UC_HOOK_INSN, interceptor._on_syscall,
                           None, 1, 0, UC_X86_INS_SYSCALL)

            # V6 Task 3: Install user-mode anti-debug stubs
            from .user_mode_stubber import install_user_mode_stubs
            stubber = install_user_mode_stubs(self_uc, verbose=self._verbose)
            if self._verbose:
                print(f"  [UnicornBackend] User-mode stubs installed")

            return orig_emu_start(self_uc, *args, **kwargs)

        uc_mod.Uc.emu_start = patched_emu_start
        try:
            dump_data, oep = unpack(ctx.sample_path, self._verbose, inner_mode, 't')
        except Exception as e:
            error_msg = str(e)
            try:
                oep = self._uc.reg_read(UC_X86_REG_RIP)
            except:
                pass

        self._running = False
        # 保存 unpack 产生的 dump 供 dump_memory() 返回
        self._cached_dump = dump_data
        elapsed = (datetime.now() - start_time).total_seconds()

        from .. import api_recorder
        api_calls = len(api_recorder._api_calls) if hasattr(api_recorder, '_api_calls') else 0

        result = ExecutionResult(
            success=(oep > 0),
            backend=self.display_name,
            stage=ExecutionStage.DONE,
            dump_data=None,
            oep=oep or self._ep,
            image_base=GLOBAL_VAR.image_base,
            image_end=GLOBAL_VAR.image_end,
            api_calls=api_calls,
            crc_patches=0,
            elapsed_seconds=elapsed,
            error_message="" if oep else error_msg,
            diagnosis=f"Unicorn unpack: OEP=0x{oep:x}, API calls={api_calls}" if oep else error_msg[:80],
        )

        if oep == 0:
            result.warnings.append("oep_not_found")

        if self._captured_vm_entries:
            result.extra["vm_entries"] = self._captured_vm_entries

        if self._oep_suspects:
            result.extra["oep_suspects"] = self._oep_suspects
            print(f"  [UnicornBackend] OEP tracker: {len(self._oep_suspects)} escape points detected")

        return result

    def _track_oep_escape(self, uc, address):
        """P3: OEP 逃逸追踪 — 监控控制流从主模块跳向外部"""
        try:
            from ..globalValue import GLOBAL_VAR
            image_base = GLOBAL_VAR.image_base
            image_end = GLOBAL_VAR.image_end
            rip = uc.reg_read(UC_X86_REG_RIP)
            # 当前指令在主模块内，但下一条在外部
            if image_base <= address < image_end and not (image_base <= rip < image_end):
                rsp = uc.reg_read(UC_X86_REG_RSP)
                try:
                    stack_val = struct.unpack('<Q', uc.mem_read(rsp, 8))[0]
                except:
                    stack_val = 0
                self._oep_suspects.append({
                    'from_addr': address,
                    'to_addr': rip,
                    'stack_top': stack_val,
                })
        except:
            pass

    # ===== P3: Magicmida 内存陷阱 (Unicorn) =====

    def _setup_text_trap(self):
        """设置 .text 段为 UC_PROT_NONE + FETCH_UNMAPPED hook"""
        if not self._uc:
            return

        from ..globalValue import GLOBAL_VAR
        from unicorn import UC_PROT_NONE, UC_HOOK_MEM_FETCH_UNMAPPED

        # 从 section_info 找到 .text 段
        section_info = GLOBAL_VAR.section_info if hasattr(GLOBAL_VAR, 'section_info') else []
        for sec in section_info:
            if len(sec) >= 4:
                name = sec[0]
                va = sec[1]
                size = sec[2]
                if name in ('.text', 'UPX0', '') or (name == '' and not self._text_base):
                    self._text_base = va
                    self._text_size = max(size, 0x1000)

        if not self._text_base:
            self._text_base = GLOBAL_VAR.image_base + 0x1000
            self._text_size = 0x10000

        # 设置 .text 为不可访问
        try:
            self._uc.mem_protect(self._text_base, self._text_size, UC_PROT_NONE)
            self._uc.hook_add(UC_HOOK_MEM_FETCH_UNMAPPED, self._on_fetch_text,
                             None, self._text_base, self._text_base + self._text_size)
            self._trap_active = True
            print(f"  [UnicornBackend] 🪤 Magicmida trap: .text @ 0x{self._text_base:x} "
                  f"({self._text_size} bytes) → PROT_NONE")
        except Exception as e:
            print(f"  [UnicornBackend] ⚠ Trap setup failed: {e}")

    def _on_fetch_text(self, uc, access, address, size, value, user_data):
        """Magicmida: 执行流尝试进入 .text → OEP 或 TLS"""
        if not self._trap_active:
            return False

        rsp = uc.reg_read(UC_X86_REG_RSP)
        rip = uc.reg_read(UC_X86_REG_RIP)
        is_tls = False

        # TLS 检测: 栈上有异常返回地址 (指向壳段, 非主模块)
        try:
            stack = uc.mem_read(rsp, 24)
            ret_addr = struct.unpack('<Q', stack[0:8])[0]
            # 如果返回地址在主模块范围内但不在 .text 段 → TLS
            from ..globalValue import GLOBAL_VAR
            if GLOBAL_VAR.image_base <= ret_addr < GLOBAL_VAR.image_base + 0x2000000:
                if not (self._text_base <= ret_addr < self._text_base + self._text_size):
                    is_tls = True
            elif ret_addr > 0 and ret_addr < 0x7FFF00000000:
                is_tls = True
        except:
            pass

        if is_tls:
            self._tls_entries.append(address)
            # 临时恢复执行 → 单步 → 重新保护
            uc.mem_protect(address & ~0xFFF, 0x1000, UC_PROT_EXEC | UC_PROT_READ)
            rip_next = rip
            try:
                # 在当前页执行直到离开 (单步模拟)
                page_end = (address & ~0xFFF) + 0x1000
                uc.emu_start(rip, min(page_end, address + 0x1000), count=1)
            except:
                pass
            # 恢复保护
            uc.mem_protect(address & ~0xFFF, 0x1000, UC_PROT_NONE)
            return True  # 继续执行

        # Not TLS → OEP!
        self._trap_oep = address
        self._trap_active = False

        # 恢复整个 .text 段保护
        from unicorn import UC_PROT_ALL
        uc.mem_protect(self._text_base, self._text_size, UC_PROT_ALL)
        print(f"  [UnicornBackend] 🎯 OEP captured @ 0x{address:x} (TLS: {len(self._tls_entries)} skipped)")

        return False  # 让 Unicorn 继续，但 trap 已解除

    def dump_memory(self, ctx) -> Optional[bytes]:
        """导出完整内存dump — 优先返回 execute() 产生的缓存"""
        if self._cached_dump:
            print(f"  [UnicornBackend] Memory dump: {len(self._cached_dump)} bytes (cached)")
            return self._cached_dump

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
