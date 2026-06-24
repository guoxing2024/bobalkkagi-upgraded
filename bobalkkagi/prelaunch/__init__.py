"""
Prelaunch — V5.0: 进程启动前环境构建
=======================================
在 CREATE_SUSPENDED 阶段构建干净运行环境，而非运行后修补。
"""

from .environment_builder import ProcessSanitizer, sanitize_process
