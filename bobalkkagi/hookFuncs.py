HookFuncs={
    # === 原35个钩子 (0-32) ===
    "kernel32.dll_GetModuleHandleA" : 0,
    "kernel32.dll_LoadLibraryA" : 1,
    "kernel32.dll_GetProcAddress" : 2,
    "ntdll.dll_ZwOpenThread" : 3,
    "kernel32.dll_GetUserDefaultUILanguage" : 4,
    "ntdll.dll_RtlAllocateHeap" : 5,
    "kernel32.dll_GetCurrentDirectoryW" : 6,
    "kernel32.dll_GetModuleFileNameW" : 7,
    "kernel32.dll_SetCurrentDirectoryW" : 8,
    "kernel32.dll_GetCommandLineA" : 9,
    "ntdll.dll_ZwQueryInformationProcess" : 10,
    "ntdll.dll_ZwAllocateVirtualMemory" : 11,
    "ntdll.dll_ZwGetContextThread" : 12,
    "kernel32.dll_VirtualFree" : 13,
    "ntdll.dll_ZwSetInformationThread" : 14,
    "advapi32.dll_OpenThreadToken" : 15,
    "advapi32.dll_OpenProcessToken" : 16,
    "ntdll.dll_ZwQueryInformationToken" : 17,
    "ntdll.dll_ZwSetInformationProcess" : 18,
    "ntdll.dll_ZwClose" : 19,
    "ntdll.dll_RtlFreeHeap" : 20,
    "ntdll.dll_ZwOpenThreadTokenEx" : 21,
    "ntdll.dll_ZwOpenProcessTokenEx" : 22,
    "ntdll.dll_ZwDuplicateToken" : 23,
    "ntdll.dll_ZwAccessCheck" : 24,
    "kernel32.dll_VirtualProtect" : 25,
    "win32u.dll_NtUserGetForegroundWindow" : 26,
    "user32.dll_GetWindowTextA" : 27,
    "ntdll.dll_ZwQuerySystemInformation" : 28,
    "kernelbase.dll_RegOpenKeyExA" : 29,
    "advapi32.dll_RegQueryValueExA" : 30,
    "advapi32.dll_RegCloseKey" : 31,
    "kernelbase.dll_VirtualProtect" : 32,
    # === Bobalkkagi升级: 新增API钩子 (33+) ===
    
    # ntdll - 注册表操作 (33-36)
    "ntdll.dll_ZwOpenKey" : 33,
    "ntdll.dll_ZwCreateKey" : 34,
    "ntdll.dll_ZwQueryValueKey" : 35,
    "ntdll.dll_ZwDeleteKey" : 36,
    
    # ntdll - 文件/内存映射 (38-41)
    "ntdll.dll_ZwCreateFile" : 37,
    "ntdll.dll_ZwOpenFile" : 38,
    "ntdll.dll_ZwCreateSection" : 39,
    "ntdll.dll_ZwMapViewOfSection" : 40,
    
    # ntdll - 同步/线程 (41-43)
    "ntdll.dll_ZwDelayExecution" : 41,
    "ntdll.dll_ZwCreateMutant" : 42,
    "ntdll.dll_ZwCreateEvent" : 43,
    "ntdll.dll_ZwOpenEvent" : 44,
    
    # ntdll - 进程/线程 (45-48)
    "ntdll.dll_ZwCreateThreadEx" : 45,
    "ntdll.dll_ZwTerminateProcess" : 46,
    "ntdll.dll_ZwRaiseHardError" : 47,
    "ntdll.dll_ZwQueryInformationThread" : 48,
    
    # ntdll - 杂项 (49-51)
    "ntdll.dll_ZwQueryObject" : 49,
    "ntdll.dll_ZwYieldExecution" : 50,
    "ntdll.dll_LdrLoadDll" : 51,
    
    # kernel32 - 线程/同步 (52-54)
    "kernel32.dll_CreateThread" : 52,
    "kernel32.dll_WaitForSingleObject" : 53,
    "kernel32.dll_WaitForMultipleObjects" : 54,
    
    # kernel32 - 系统信息 (55-58)
    "kernel32.dll_GetSystemInfo" : 55,
    "kernel32.dll_GetNativeSystemInfo" : 56,
    "kernel32.dll_QueryPerformanceCounter" : 57,
    "kernel32.dll_GetTickCount" : 58,
    "kernel32.dll_GetTickCount64" : 59,
    
    # kernel32 - 杂项 (60-62)
    "kernel32.dll_IsProcessorFeaturePresent" : 60,
    "kernel32.dll_GetACP" : 61,
    "kernel32.dll_GetOEMCP" : 62,
    "kernel32.dll_TlsGetValue" : 63,
    "kernel32.dll_TlsSetValue" : 64,
    "kernel32.dll_EncodePointer" : 65,
    "kernel32.dll_DecodePointer" : 66,
    "kernel32.dll_InitializeCriticalSection" : 67,
    "kernel32.dll_GetUserDefaultLCID" : 68,
    
    # kernelbase (69-71)
    "kernelbase.dll_GetSystemInfo" : 69,
    "kernelbase.dll_GetNativeSystemInfo" : 70,
    "kernelbase.dll_QueryPerformanceCounter" : 71,
    "kernelbase.dll_GetTickCount" : 72,
    "kernelbase.dll_GetTickCount64" : 73,
    "kernelbase.dll_IsProcessorFeaturePresent" : 74,
    "kernelbase.dll_InitializeCriticalSection" : 75,
    "kernelbase.dll_LCMapStringEx" : 76,
    "kernelbase.dll_GetStringTypeW" : 77,
    "kernelbase.dll_FindResourceW" : 78,
    "kernelbase.dll_SizeofResource" : 79,
    "kernelbase.dll_LoadResource" : 80,
    
    # ntdll - 杂项增强 (81)
    "ntdll.dll_RtlGetVersion" : 81,
}
