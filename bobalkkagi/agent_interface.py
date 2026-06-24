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
    ErrorCode.ERR_OEP_NOT_FOUND: "Try aggressive CRC bypass mode (--mode=aggressive) or hook_code mode for deeper analysis",
    ErrorCode.ERR_IAT_SPACE_FULL: "Increase .idata section size or add a new section",
    ErrorCode.ERR_IAT_NO_IMPORTS: "Run with --force-runtime-iat to use runtime API recording instead of original PE imports",
    ErrorCode.ERR_CRC_CRASH: "Roll back CRC patches and retry with --crc-mode=safe",
    ErrorCode.ERR_EMULATION_CRASH: "Check DLL path. Try different emulation mode (hook_code/hook_block)",
    ErrorCode.ERR_UNMAPPED_MEMORY: "Memory range exceeded. Try reducing ImageBaseEnd",
    ErrorCode.WARN_LOW_IMPORT_COUNT: "Run with --force-runtime-iat=True to generate IAT from runtime API recording (800+ observed calls)",
    ErrorCode.WARN_PARTIAL_CRC_SCAN: "CRC scan was incomplete. Try --crc-mode=aggressive for full section scan",
}

# ============================================================
# P1: 自动重试策略引擎
# ============================================================
RETRY_STRATEGIES: Dict[str, list] = {
    "oep_not_found": [
        {"mode": "hook_code", "reason": "Slower per-instruction tracing may reveal hidden OEP"},
        {"crc_mode": "aggressive", "reason": "Aggressive CRC bypass may unblock OEP execution path"},
    ],
    "iat_no_imports": [
        {"force_runtime_iat": True, "reason": "Original PE import table is obfuscated. Switch to runtime recording."},
    ],
    "emulation_crash": [
        {"crc_mode": "off", "reason": "CRC patches may be causing the crash. Disabling bypass."},
        {"mode": "hook_code", "crc_mode": "safe", "reason": "Retry with safe CRC bypass and per-instruction tracing."},
    ],
    "crc_crash": [
        {"crc_mode": "safe", "reason": "Rolling back to safe CRC bypass mode."},
        {"crc_mode": "off", "reason": "Disabling CRC bypass entirely to isolate the crash."},
    ],
    "low_import_count": [
        {"force_runtime_iat": True, "reason": "Low import count detected. Forcing runtime IAT reconstruction."},
    ],
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
    force_runtime_iat: bool = False,
) -> str:
    """
    AI Agent 标准工具接口。
    
    Args:
        file_path: Protected binary path
        mode: "fast" | "deep" (hook_code) | "aggressive_crc"
        dll_path: DLL directory path
        crc_mode: "safe" | "aggressive" | "off"
        timeout: Max execution time (seconds)
        snapshot_every_stage: Save context state after each stage
        force_runtime_iat: If True, ignore original PE imports and use
            only runtime API recording (solves "low import count" issue)
    
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
        pipe = Pipeline(file_path, dll_path,
                       force_runtime_iat=force_runtime_iat,
                       crc_mode=crc_mode)
        
        # Execute
        result = pipe.run()
        
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
                dll_count = len(pipe.ctx.imports)
                avg_per_dll = import_count / dll_count if dll_count > 0 else 0
                
                if import_count < 10 or (avg_per_dll < 2 and dll_count >= 3):
                    resp.warnings.append(ErrorCode.WARN_LOW_IMPORT_COUNT)
                    resp.diagnosis = (
                        f"Detected only {import_count} imports across {dll_count} DLLs "
                        f"(avg {avg_per_dll:.1f} per DLL). "
                        f"Reason: Original IAT obfuscated by Themida. "
                        f"Runtime recording has {len(pipe.ctx.runtime_api_calls)} API calls available. "
                        f"Action: Re-run with force_runtime_iat=True to generate full IAT from runtime calls."
                    )
                    resp.suggested_next_step = NEXT_STEP_SUGGESTIONS.get(ErrorCode.WARN_LOW_IMPORT_COUNT,
                        "Run with force_runtime_iat=True to use full runtime API recording for IAT")
                elif import_count < 20:
                    # Borderline: set diagnosis but don't warn (IAT rebuilt, just small)
                    total_runtime = len(pipe.ctx.runtime_api_calls)
                    if total_runtime > import_count * 3:
                        resp.diagnosis = (
                            f"IAT has {import_count} imports ({dll_count} DLLs). "
                            f"Runtime recording captured {total_runtime} API calls — "
                            f"consider force_runtime_iat=True for more complete IAT."
                        )
                    else:
                        resp.diagnosis = (
                            f"IAT rebuilt with {import_count} imports across {dll_count} DLLs."
                        )
                else:
                    resp.diagnosis = (
                        f"Full IAT rebuilt: {import_count} imports across {dll_count} DLLs. "
                        f"PE headers, TLS, and sections restored."
                    )
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
        
        # ============================================================
        # P1: Auto-retry — 根据错误码自动调整参数并重试
        # ============================================================
        strategies = RETRY_STRATEGIES.get(error_code)
        if not strategies:
            # Map error_code to retry key
            retry_map = {
                ErrorCode.ERR_OEP_NOT_FOUND: "oep_not_found",
                ErrorCode.ERR_IAT_NO_IMPORTS: "iat_no_imports",
                ErrorCode.ERR_EMULATION_CRASH: "emulation_crash",
                ErrorCode.ERR_CRC_CRASH: "crc_crash",
            }
            strategies = RETRY_STRATEGIES.get(retry_map.get(error_code))
        
        if strategies:
            from .pipeline import Pipeline
            last_error = str(e)
            for attempt, strategy in enumerate(strategies, 1):
                try:
                    adjusted_mode = strategy.get("mode", mode)
                    adjusted_crc = strategy.get("crc_mode", crc_mode)
                    adjusted_force_iat = strategy.get("force_runtime_iat", force_runtime_iat)
                    reason = strategy.get("reason", "auto-retry")
                    
                    # Build retry pipeline with adjusted parameters
                    retry_pipe = Pipeline(
                        file_path, dll_path,
                        force_runtime_iat=adjusted_force_iat,
                        crc_mode=adjusted_crc
                    )
                    retry_result = retry_pipe.run()
                    retry_elapsed = (datetime.now() - start_time).total_seconds()
                    
                    if retry_result.status == "ok":
                        # Retry succeeded!
                        retry_metrics = {
                            "elapsed_seconds": round(retry_elapsed, 1),
                            "retry_attempt": attempt,
                            "retry_strategy": strategy,
                            "original_error": error_code,
                        }
                        if retry_pipe.ctx:
                            retry_metrics["dll_count"] = len(retry_pipe.ctx.modules)
                            retry_metrics["runtime_apis"] = len(retry_pipe.ctx.runtime_api_calls)
                        
                        resp = AgentResponse.from_success(
                            stage="complete",
                            output_path=retry_result.output_path,
                            dump_path=retry_result.dump_path,
                            oep=retry_result.oep,
                            metrics=retry_metrics
                        )
                        resp.diagnosis = (
                            f"Auto-retry succeeded on attempt {attempt}/{len(strategies)} "
                            f"(strategy: {reason}). Original error: {last_error}"
                        )
                        return resp.to_json()
                    else:
                        last_error = retry_result.message or "retry failed"
                except Exception as retry_exc:
                    last_error = str(retry_exc)
                    continue
            
            # All retries exhausted — append retry info to response
            resp.diagnosis = (
                f"Auto-retry exhausted ({len(strategies)} strategies attempted). "
                f"Last error: {last_error}. "
                f"Original: {error_code}. "
                f"Suggested: {resp.suggested_next_step}"
            )
        
        return resp.to_json()
