"""
Agent Interface — AI Agent 工具接口
===================================
Phase 1 (AI Ready): JSON输入/输出 + 统一错误码 + 诊断建议

设计原则:
  - 输入: JSON (兼容 OpenAI Function Calling / LangChain Tool)
  - 输出: JSON (status, stage, metrics, diagnosis, suggested_next_step)
  - 错误码: 统一机器可读编码
  - 诊断: 失败时给出原因和建议
"""

import os
import json
import traceback
from datetime import datetime
from typing import Optional, Dict, Any

from .core.context import UnpackContext
from .globalValue import set_context

# ============================================================
# 统一错误码
# ============================================================
class ErrorCode:
    SUCCESS = "success"
    # 加载阶段
    ERR_FILE_NOT_FOUND = "file_not_found"
    ERR_INVALID_PE = "invalid_pe"
    ERR_UNSUPPORTED_ARCH = "unsupported_arch"
    # 模拟阶段
    ERR_EMULATION_CRASH = "emulation_crash"
    ERR_EMULATION_TIMEOUT = "emulation_timeout"
    ERR_UNMAPPED_MEMORY = "unmapped_memory"
    # 检测阶段
    ERR_OEP_NOT_FOUND = "oep_not_found"
    ERR_OEP_UNCERTAIN = "oep_uncertain"
    # 重建阶段
    ERR_IAT_SPACE_FULL = "iat_space_full"
    ERR_IAT_NO_IMPORTS = "iat_no_imports"
    ERR_REBUILD_FAILED = "rebuild_failed"
    # CRC
    ERR_CRC_CRASH = "crc_crash"
    # 通用
    ERR_UNKNOWN = "unknown_error"
    ERR_TIMEOUT = "timeout"
    # 警告
    WARN_LOW_IMPORT_COUNT = "low_import_count"
    WARN_PARTIAL_CRC_SCAN = "partial_crc_scan"

# 错误码 → 人类可读描述
ERROR_DESCRIPTIONS = {
    ErrorCode.SUCCESS: "Operation completed successfully",
    ErrorCode.ERR_FILE_NOT_FOUND: "Target file does not exist",
    ErrorCode.ERR_INVALID_PE: "File is not a valid PE executable",
    ErrorCode.ERR_UNSUPPORTED_ARCH: "Architecture not supported (x64 only)",
    ErrorCode.ERR_EMULATION_CRASH: "Unicorn emulation crashed",
    ErrorCode.ERR_EMULATION_TIMEOUT: "Emulation exceeded time limit",
    ErrorCode.ERR_UNMAPPED_MEMORY: "Unicorn accessed unmapped memory",
    ErrorCode.ERR_OEP_NOT_FOUND: "Could not find original entry point",
    ErrorCode.ERR_OEP_UNCERTAIN: "OEP found but confidence is low",
    ErrorCode.ERR_IAT_SPACE_FULL: "Not enough space in .idata section for IAT",
    ErrorCode.ERR_IAT_NO_IMPORTS: "No import functions found",
    ErrorCode.ERR_REBUILD_FAILED: "PE rebuild failed",
    ErrorCode.ERR_CRC_CRASH: "CRC check bypass caused crash",
    ErrorCode.ERR_UNKNOWN: "Unknown error occurred",
    ErrorCode.ERR_TIMEOUT: "Overall pipeline timed out",
}

# 错误码 → 建议下一步
NEXT_STEP_SUGGESTIONS = {
    ErrorCode.ERR_OEP_NOT_FOUND: "Try aggressive CRC bypass mode (--mode=aggressive)",
    ErrorCode.ERR_IAT_SPACE_FULL: "Increase .idata section size or add a new section",
    ErrorCode.ERR_IAT_NO_IMPORTS: "Use Scylla for manual IAT scan on the dump file",
    ErrorCode.ERR_CRC_CRASH: "Roll back CRC patches and retry with --crc-mode=safe",
    ErrorCode.ERR_EMULATION_CRASH: "Check DLL path. Try different emulation mode (hook_code/hook_block)",
    ErrorCode.ERR_UNMAPPED_MEMORY: "Memory range exceeded. Try reducing ImageBaseEnd",
}


class AgentResponse:
    """
    标准化 Agent 响应。
    
    Example:
    {
      "status": "success",
      "stage": "unpacking",
      "error_code": null,
      "diagnosis": "Detected Themida 3.x with moderate virtualisation",
      "output_path": "/path/to/unpacked.exe",
      "dump_path": "/path/to/unpacked.dump",
      "oep": "0x1404ed393",
      "metrics": {
        "api_calls": 842,
        "crc_patches": 15,
        "dll_count": 17,
        "runtime_apis": 24,
        "elapsed_seconds": 8.5
      },
      "warnings": ["low_import_count"],
      "suggested_next_step": null
    }
    """
    
    def __init__(self):
        self.status = "unknown"
        self.stage = ""
        self.error_code = None
        self.diagnosis = ""
        self.output_path = None
        self.dump_path = None
        self.oep = None
        self.metrics = {}
        self.warnings = []
        self.suggested_next_step = None
    
    def to_dict(self) -> dict:
        """转为JSON可序列化的字典"""
        d = {
            "status": self.status,
            "stage": self.stage,
            "error_code": self.error_code,
            "diagnosis": self.diagnosis,
            "output_path": self.output_path,
            "dump_path": self.dump_path,
            "oep": f"0x{self.oep:x}" if self.oep else None,
            "metrics": self.metrics,
            "warnings": self.warnings,
            "suggested_next_step": self.suggested_next_step,
        }
        return d
    
    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, ensure_ascii=False)
    
    @classmethod
    def from_error(cls, error_code: str, stage: str, diagnosis: str = "",
                   suggestion: str = None) -> 'AgentResponse':
        resp = cls()
        resp.status = "failed"
        resp.stage = stage
        resp.error_code = error_code
        resp.diagnosis = diagnosis or ERROR_DESCRIPTIONS.get(error_code, "")
        resp.suggested_next_step = suggestion or NEXT_STEP_SUGGESTIONS.get(error_code)
        return resp
    
    @classmethod
    def from_success(cls, stage: str = "", output_path: str = None,
                    dump_path: str = None, oep: int = None,
                    metrics: dict = None) -> 'AgentResponse':
        resp = cls()
        resp.status = "success"
        resp.stage = stage
        resp.output_path = output_path
        resp.dump_path = dump_path
        resp.oep = oep
        resp.metrics = metrics or {}
        return resp


def agent_unpack(
    file_path: str,
    mode: str = "fast",
    dll_path: str = "win10_v1903",
    crc_mode: str = "safe",
    timeout: int = 600,
    snapshot_every_stage: bool = False,
) -> str:
    """
    AI Agent 标准工具接口。
    
    Args:
        file_path: Protected binary path
        mode: "fast" | "deep" | "aggressive_crc"
        dll_path: DLL directory path
        crc_mode: "safe" | "aggressive" | "off"
        timeout: Max execution time (seconds)
        snapshot_every_stage: Save context state after each stage
    
    Returns:
        JSON string with AgentResponse
    """
    start_time = datetime.now()
    resp = AgentResponse()
    
    # Input validation
    if not os.path.isfile(file_path):
        resp = AgentResponse.from_error(
            ErrorCode.ERR_FILE_NOT_FOUND, "input",
            f"File not found: {file_path}"
        )
        resp.metrics["elapsed_seconds"] = (datetime.now() - start_time).total_seconds()
        return resp.to_json()
    
    try:
        from .pipeline import Pipeline
        
        # Build pipeline
        pipe = Pipeline(file_path, dll_path)
        
        # Configure based on mode
        if mode in ("aggressive_crc", "aggressive"):
            pipe.crc_mode = "aggressive"
        
        # Execute
        result = pipe.run(timeout=timeout)
        
        elapsed = (datetime.now() - start_time).total_seconds()
        
        # Build metrics
        metrics = {
            "elapsed_seconds": round(elapsed, 1),
        }
        if pipe.ctx:
            ctx = pipe.ctx
            metrics["dll_count"] = len(ctx.modules)
            metrics["runtime_apis"] = len(ctx.runtime_api_calls)
            metrics["api_events"] = len(ctx.api_events)
            metrics["memory_events"] = len(ctx.memory_events)
            metrics["exception_events"] = len(ctx.exception_events)
        
        if result.status == "ok":
            resp = AgentResponse.from_success(
                stage="complete",
                output_path=result.output_path,
                dump_path=result.dump_path,
                oep=result.oep,
                metrics=metrics
            )
            
            # Warnings
            if pipe.ctx:
                import_count = sum(len(v) for v in pipe.ctx.imports.values())
                if import_count < 10:
                    resp.warnings.append(ErrorCode.WARN_LOW_IMPORT_COUNT)
                    resp.suggested_next_step = NEXT_STEP_SUGGESTIONS.get(ErrorCode.WARN_LOW_IMPORT_COUNT,
                        "Use Scylla to manually scan the dump for additional imports")
        else:
            resp = AgentResponse.from_error(
                ErrorCode.ERR_REBUILD_FAILED if "rebuild" in str(result.message).lower()
                else ErrorCode.ERR_UNKNOWN,
                result.stage or "unknown",
                result.message
            )
            resp.metrics = metrics
        
        return resp.to_json()
    
    except Exception as e:
        elapsed = (datetime.now() - start_time).total_seconds()
        error_code = ErrorCode.ERR_UNKNOWN
        
        err_str = str(e).lower()
        if "timeout" in err_str:
            error_code = ErrorCode.ERR_TIMEOUT
        elif "unmapped" in err_str or "uc_err" in err_str:
            error_code = ErrorCode.ERR_UNMAPPED_MEMORY
        elif "crc" in err_str:
            error_code = ErrorCode.ERR_CRC_CRASH
        
        resp = AgentResponse.from_error(
            error_code, "pipeline",
            f"{type(e).__name__}: {e}"
        )
        resp.metrics["elapsed_seconds"] = elapsed
        
        return resp.to_json()
