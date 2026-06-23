"""
Runtime API Call Recorder
==========================
Bobalkkagi升级 — P2: 运行时IAT重建

在Unicorn模拟期间记录所有通过GetProcAddress/LoadLibrary
解析的API调用。这些记录用于在IAT重建时补充原始PE导入表。

工作流程:
1. 模拟开始前: clear()
2. 模拟期间: 每个hook_GetProcAddress/hook_LoadLibrary等调用 record()
3. 模拟结束后: get_calls() 获取完整记录
4. IAT重建: 与原始PE导入表合并，生成更完整的IAT
"""

from collections import defaultdict
from datetime import datetime

# 全局调用记录
# 格式: {(dll_name, func_name), ...} — set去重
_api_calls = set()

# 每个DLL的调用计数
_api_counts = defaultdict(int)

# 记录时间戳
_recording_start = None
_recording_end = None


def clear():
    """清空所有调用记录（在模拟开始前调用）"""
    global _recording_start
    _api_calls.clear()
    _api_counts.clear()
    _recording_start = datetime.now()


def record(dll_name: str, func_name: str):
    """
    记录一次API调用。
    dll_name: DLL名称（小写，如 'kernel32.dll'）
    func_name: 函数名（如 'CreateFileW'）
    """
    key = (dll_name.lower(), func_name)
    _api_calls.add(key)
    _api_counts[key] += 1


def get_calls() -> list:
    """
    获取所有运行时记录的API调用。
    返回: [(dll_name, func_name), ...] 按DLL分组排序
    """
    # 按DLL名称分组
    by_dll = defaultdict(list)
    for dll_name, func_name in sorted(_api_calls):
        by_dll[dll_name].append(func_name)
    
    # 按DLL排序，每个DLL内函数名排序
    result = []
    for dll_name in sorted(by_dll.keys()):
        for func_name in sorted(by_dll[dll_name]):
            result.append((dll_name, func_name))
    
    return result


def get_calls_by_dll() -> dict:
    """
    获取按DLL分组的调用记录。
    返回: {dll_name: [func_name1, func_name2, ...], ...}
    """
    by_dll = defaultdict(list)
    for dll_name, func_name in sorted(_api_calls):
        by_dll[dll_name].append(func_name)
    
    # 每个DLL内函数名去重+排序
    result = {}
    for dll_name in sorted(by_dll.keys()):
        result[dll_name] = sorted(set(by_dll[dll_name]))
    
    return result


def get_stats() -> dict:
    """获取统计信息"""
    return {
        'total_calls': len(_api_calls),
        'unique_dlls': len(set(dll for dll, _ in _api_calls)),
        'unique_funcs': len(_api_calls),
        'start': _recording_start,
        'end': _recording_end,
    }


def summary() -> str:
    """生成易读的调用摘要"""
    if not _api_calls:
        return "  无API调用记录"
    
    by_dll = get_calls_by_dll()
    lines = [f"  运行时API调用记录 ({len(_api_calls)}个函数, {len(by_dll)}个DLL):"]
    for dll_name, funcs in by_dll.items():
        func_list = ', '.join(funcs[:8])
        if len(funcs) > 8:
            func_list += f' ...({len(funcs)})'
        lines.append(f"    {dll_name}: {func_list}")
    
    return '\n'.join(lines)
