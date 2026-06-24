"""
Diagnostic Module — 失败原因诊断
=================================
Phase 1 (AI Ready): 解释"为什么失败"，给出可操作的修复建议

方法论:
  1. 分析 UnpackContext 中的事件日志
  2. 识别失败模式 (OEP未找到 / CRC崩溃 / IAT不完整等)
  3. 输出机器可读的诊断JSON
"""

from .core.context import UnpackContext
from .agent_interface import ErrorCode, NEXT_STEP_SUGGESTIONS


def diagnose_oep_failure(ctx: UnpackContext) -> dict:
    """
    诊断OEP检测失败的原因。
    
    检查项:
      - 内存事件是否太少 (模拟未启动?)
      - 有没有RW→RX转换 (解密未执行?)
      - API调用是否异常 (DLL加载失败?)
    """
    result = {
        "issue": "oep_not_found",
        "likely_cause": "unknown",
        "evidence": {},
        "suggestion": NEXT_STEP_SUGGESTIONS.get(ErrorCode.ERR_OEP_NOT_FOUND)
    }
    
    # 检查内存事件
    mem_events = len(ctx.memory_events)
    api_events = len(ctx.api_events)
    
    if mem_events == 0 and api_events == 0:
        result["likely_cause"] = "emulation_never_started"
        result["suggestion"] = "Check DLL path and verify the file is a valid PE"
        return result
    
    if mem_events < 10:
        result["likely_cause"] = "emulation_too_short"
        result["evidence"]["memory_events"] = mem_events
        result["suggestion"] = "Emulation ended too quickly. Try enabling verbose mode."
        return result
    
    # 检查 RW→RX 转换
    rw_rx_count = 0
    for e in ctx.memory_events:
        if hasattr(e, 'operation') and e.operation == 'protect':
            rw_rx_count += 1
    
    if rw_rx_count == 0:
        result["likely_cause"] = "no_memory_decryption"
        result["evidence"]["rw_rx_transitions"] = 0
        result["suggestion"] = "Themida may not have decrypted yet. Try hook_code mode for deeper analysis."
        return result
    
    # 检查模块加载
    if len(ctx.modules) < 3:
        result["likely_cause"] = "insufficient_dll_loading"
        result["evidence"]["loaded_modules"] = len(ctx.modules)
        result["suggestion"] = "Missing DLLs. Verify win10_v1903 directory contains all required DLLs."
        return result
    
    result["likely_cause"] = "oep_not_detected_by_signals"
    result["evidence"]["memory_events"] = mem_events
    result["evidence"]["api_events"] = api_events
    result["evidence"]["rw_rx_transitions"] = rw_rx_count
    result["suggestion"] = "OEP signals were present but not sufficient. Try aggressive CRC bypass."
    
    return result


def diagnose_iat_failure(ctx: UnpackContext, original_error: str = "") -> dict:
    """
    诊断IAT重建失败的原因。
    """
    result = {
        "issue": "iat_rebuild_failed",
        "likely_cause": "unknown",
        "evidence": {},
        "suggestion": NEXT_STEP_SUGGESTIONS.get(ErrorCode.ERR_IAT_NO_IMPORTS)
    }
    
    if original_error and "space" in original_error.lower():
        result["likely_cause"] = "idata_section_too_small"
        result["suggestion"] = NEXT_STEP_SUGGESTIONS.get(ErrorCode.ERR_IAT_SPACE_FULL)
        return result
    
    if ctx.imports:
        total = sum(len(v) for v in ctx.imports.values())
        if total < 5:
            result["likely_cause"] = "insufficient_imports_recovered"
            result["evidence"]["recovered_imports"] = total
            result["evidence"]["dlls"] = list(ctx.imports.keys())
            result["suggestion"] = ("Only {0} imports recovered. The original PE's import table was "
                                   "heavily obfuscated. Use runtime import scanning (already done) "
                                   "and consider Scylla for manual recovery.").format(total)
            return result
    
    result["likely_cause"] = "iat_write_failed"
    result["suggestion"] = "Check .idata section boundaries. Try expanding the section."
    return result


def diagnose_emulation_crash(ctx: UnpackContext, error: str = "") -> dict:
    """
    诊断Unicorn模拟崩溃的原因。
    """
    result = {
        "issue": "emulation_crash",
        "likely_cause": "unknown",
        "evidence": {},
        "suggestion": NEXT_STEP_SUGGESTIONS.get(ErrorCode.ERR_EMULATION_CRASH)
    }
    
    err_lower = error.lower()
    
    if "unmapped" in err_lower:
        result["likely_cause"] = "memory_access_violation"
        result["suggestion"] = "Increase ImageBaseEnd or add missing memory mappings."
    elif "timeout" in err_lower:
        result["likely_cause"] = "emulation_timeout"
        result["suggestion"] = "Increase timeout or check for infinite loops in the sample."
    elif "invalid" in err_lower and "fetch" in err_lower:
        result["likely_cause"] = "invalid_instruction_fetch"
        result["suggestion"] = "Memory region not mapped as executable. Check section privileges."
    
    if ctx.exception_events:
        last_ex = ctx.exception_events[-1] if ctx.exception_events else None
        if last_ex:
            result["evidence"]["last_exception"] = repr(last_ex)
    
    return result


def full_diagnosis(ctx: UnpackContext, stage: str = "", error: str = "") -> dict:
    """
    全量诊断 — 分析上下文并输出诊断结果。
    
    Returns:
        {
          "stage": "oep_detection",
          "diagnosis": {...},
          "context_summary": {...}
        }
    """
    diagnosis = {
        "stage": stage,
        "timestamp": str(ctx._oep_state if hasattr(ctx, '_oep_state') else "unknown"),
        "diagnosis": {},
        "context_summary": {
            "modules_loaded": len(ctx.modules),
            "api_events": len(ctx.api_events),
            "memory_events": len(ctx.memory_events),
            "exception_events": len(ctx.exception_events),
            "runtime_apis": len(ctx.runtime_api_calls),
            "oep": f"0x{ctx.oep:x}" if ctx.oep else None,
            "recovered_imports": sum(len(v) for v in ctx.imports.values()),
        }
    }
    
    if not ctx.oep:
        diagnosis["diagnosis"] = diagnose_oep_failure(ctx)
    elif error and "iat" in error.lower():
        diagnosis["diagnosis"] = diagnose_iat_failure(ctx, error)
    elif error and ("crash" in error.lower() or "uc_err" in error.lower()):
        diagnosis["diagnosis"] = diagnose_emulation_crash(ctx, error)
    else:
        diagnosis["diagnosis"] = {
            "issue": "unknown",
            "likely_cause": "Post-OEP execution failure",
            "suggestion": "Check dump file with PE analyzer. IAT may need manual fix."
        }
    
    return diagnosis
