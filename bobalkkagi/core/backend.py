"""
Execution Backend Interface — P2: 执行引擎抽象层
==================================================
Bobalkkagi v3.0 — 将执行引擎从 Pipeline 中解耦，支持多后端切换。

设计原则:
  - IExecutionBackend 定义统一的执行契约
  - 每个后端独立管理自己的生命周期（initialize → execute → cleanup）
  - Pipeline 仅通过接口调用，不依赖具体实现
  - 新增后端只需实现接口，无需修改 Pipeline 代码

后端类型:
  - "unicorn":    纯模拟执行（Unicorn CPU Emulator），对抗无硬件反调试的样本
  - "debugger":   真实进程调试（Win32 Debug API + ScyllaHide），对抗硬件/时序反调试
  - "hybrid":     混合模式（未来）：先模拟到OEP附近，再切真实进程完成解密
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional, Dict, Any, List
from enum import Enum


class BackendType(Enum):
    """执行后端类型枚举"""
    UNICORN = "unicorn"
    DEBUGGER = "debugger"
    HYBRID = "hybrid"


class ExecutionStage(Enum):
    """执行阶段"""
    INIT = "init"
    LOADING = "loading"
    HOOKING = "hooking"
    RUNNING = "running"
    DUMPING = "dumping"
    CLEANUP = "cleanup"
    DONE = "done"
    ERROR = "error"


@dataclass
class ExecutionResult:
    """
    执行结果 — 所有后端统一返回此结构。
    """
    success: bool = False
    backend: str = ""
    stage: ExecutionStage = ExecutionStage.INIT
    dump_data: Optional[bytes] = None         # 内存dump原始字节
    oep: int = 0                              # 原始入口点 (VA)
    image_base: int = 0                        # 映像基址
    image_end: int = 0                         # 映像结束地址
    api_calls: int = 0                         # 记录的API调用数
    crc_patches: int = 0                       # CRC绕过数
    elapsed_seconds: float = 0.0               # 执行耗时
    error_message: str = ""                    # 错误信息
    diagnosis: str = ""                        # 诊断信息
    warnings: List[str] = field(default_factory=list)
    extra: Dict[str, Any] = field(default_factory=dict)  # 后端特有数据

    def to_dict(self) -> dict:
        return {
            "success": self.success,
            "backend": self.backend,
            "stage": self.stage.value,
            "oep": f"0x{self.oep:x}" if self.oep else None,
            "image_base": f"0x{self.image_base:x}",
            "image_end": f"0x{self.image_end:x}",
            "api_calls": self.api_calls,
            "crc_patches": self.crc_patches,
            "elapsed_seconds": round(self.elapsed_seconds, 1),
            "error_message": self.error_message,
            "diagnosis": self.diagnosis,
            "warnings": self.warnings,
        }


class IExecutionBackend(ABC):
    """
    执行引擎抽象接口。

    生命周期:
      1. initialize(ctx)   — 分配资源，验证环境
      2. load_target(ctx)  — 加载PE/DLL，映射内存
      3. install_hooks(ctx) — 安装API钩子、CRC绕过、环境模拟
      4. execute(ctx)      — 运行目标至OEP或终止
      5. dump_memory(ctx)  — 导出完整内存镜像
      6. get_oep(ctx)      — 返回检测到的OEP
      7. cleanup(ctx)      — 释放资源

    子类必须实现全部方法。
    """

    # ===== 元信息 =====

    @property
    @abstractmethod
    def backend_type(self) -> BackendType:
        """返回后端类型标识"""
        ...

    @property
    @abstractmethod
    def display_name(self) -> str:
        """返回后端显示名称"""
        ...

    @property
    @abstractmethod
    def capabilities(self) -> Dict[str, Any]:
        """
        返回后端能力矩阵。
        {
          "hardware_anti_debug": bool,  # 能否对抗硬件反调试
          "timing_detection": bool,     # 能否对抗时序检测
          "multi_threading": bool,      # 支持多线程
          "network_simulation": bool,   # 网络请求模拟
          "requires_process": bool,     # 是否需要真实进程
          "stealth_level": str,         # "none" | "basic" | "scylla_hide"
        }
        """
        ...

    # ===== 生命周期方法 =====

    @abstractmethod
    def initialize(self, ctx) -> bool:
        """
        初始化后端，分配资源。
        在 Pipeline 中首先调用。

        Returns:
            True 表示初始化成功，False 表示失败（Pipeline 应终止）

        Side effects:
            - 创建引擎实例（Unicorn Engine / Debugger Process）
            - 设置 ctx.backend_capabilities
        """
        ...

    @abstractmethod
    def load_target(self, ctx) -> bool:
        """
        加载目标PE和依赖DLL到引擎内存空间。

        Returns:
            True 表示加载成功
        """
        ...

    @abstractmethod
    def install_hooks(self, ctx) -> bool:
        """
        安装执行钩子：
          - API调用拦截（84个钩子）
          - CRC完整性检查绕过
          - 环境模拟（PEB/TEB/KUSER）
          - 异常处理

        Returns:
            True 表示安装成功
        """
        ...

    @abstractmethod
    def execute(self, ctx) -> ExecutionResult:
        """
        运行目标程序直至OEP或终止条件。

        Returns:
            ExecutionResult: 包含OEP、dump数据、API调用统计等信息

        Raises:
            BackendExecutionError: 执行过程中不可恢复的错误
        """
        ...

    @abstractmethod
    def dump_memory(self, ctx) -> Optional[bytes]:
        """
        从引擎内存中导出完整内存镜像。

        Returns:
            bytes: PE映像的完整内存dump，失败返回None
        """
        ...

    @abstractmethod
    def get_oep(self, ctx) -> int:
        """
        返回检测到的OEP (Virtual Address)。

        Returns:
            int: OEP地址，未找到返回0
        """
        ...

    @abstractmethod
    def cleanup(self, ctx) -> None:
        """
        清理资源：释放引擎、关闭进程、清除钩子。
        Pipeline 在 finally 块中调用，保证一定执行。
        """
        ...

    # ===== 状态查询 =====

    @abstractmethod
    def is_running(self) -> bool:
        """引擎是否仍在运行"""
        ...

    @abstractmethod
    def get_current_rip(self) -> int:
        """获取当前指令指针"""
        ...

    @abstractmethod
    def read_memory(self, address: int, size: int) -> bytes:
        """读取引擎内存"""
        ...

    # ===== 辅助方法 (可选覆盖) =====

    def validate_environment(self) -> tuple:
        """
        验证运行环境是否满足后端要求。
        Returns: (ok: bool, message: str)
        """
        return True, ""

    def get_diagnosis(self, result: ExecutionResult, ctx) -> str:
        """
        生成后端特定的诊断信息。
        子类可覆盖以提供更精确的诊断。
        """
        if not result.success:
            return f"[{self.display_name}] Execution failed at stage '{result.stage.value}': {result.error_message}"
        return f"[{self.display_name}] Execution completed. OEP=0x{result.oep:x}, API calls={result.api_calls}"


class BackendExecutionError(Exception):
    """执行后端错误"""
    def __init__(self, backend: str, stage: ExecutionStage, message: str):
        self.backend = backend
        self.stage = stage
        self.message = message
        super().__init__(f"[{backend}] {stage.value}: {message}")


class BackendNotAvailableError(Exception):
    """后端不可用（环境不满足）"""
    pass
