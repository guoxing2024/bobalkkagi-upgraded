from unicorn import *
from unicorn.x86_const import *

from .loader import PE_Loader
from .reflector import REFLECTOR
from .globalValue import GLOBAL_VAR,  DLL_SETTING, HEAP_HANDLE, InvDllDict
from .util import *
from . import api_recorder

import struct
import os
import random


ThreadHandle=[]
AllocChunk = {}
Token=[]


privilege = {
        0x0: UC_PROT_EXEC | UC_PROT_READ, 
        0x2: UC_PROT_READ, 
        0x4: UC_PROT_READ | UC_PROT_WRITE,
        0x10:UC_PROT_EXEC,
        0x20:UC_PROT_EXEC | UC_PROT_READ, 
        0x40:UC_PROT_ALL
    }

class REGS:
    rax=None    
    rbx=None
    rcx=None
    rdx=None
    rdi=None
    rsi=None
    rsp=None
    rbp=None
    rip=None
    r8=None
    r9=None
    r10=None
    r11=None
    r12=None
    r13=None
    r14=None
    r15=None
    rflags=None

def set_register(register):
    
    REGS.rax=register["rax"]
    REGS.rbx=register["rbx"]
    REGS.rcx=register["rcx"]
    REGS.rdx=register["rdx"]
    REGS.rdi=register["rdi"]
    REGS.rsi=register["rsi"]
    REGS.rsp=register["rsp"]
    REGS.rbp=register["rbp"]
    REGS.rip=register["rip"]
    REGS.r8=register["r8"]
    REGS.r9=register["r9"]
    REGS.r10=register["r10"]
    REGS.r11=register["r11"]
    REGS.r12=register["r12"]
    REGS.r13=register["r13"]
    REGS.r14=register["r14"]
    REGS.r15=register["r15"]
    REGS.rflags=register["rflags"]

def ret(uc, rsp):
    
    ret=struct.unpack('<Q',uc.mem_read(rsp,8))[0]
    uc.reg_write(UC_X86_REG_RIP, ret)
    uc.reg_write(UC_X86_REG_RSP, rsp+8)
    

def hook_GetModuleFileNameW(uc, log, regs):
    
    set_register(regs)
    if not REGS.rcx:
        path = os.path.abspath(GLOBAL_VAR.sample_path)
    else:
        try:
            module_name = DLL_SETTING.LoadedDll[REGS.rcx]
        except KeyError:
            module_name = "somefakename.dll"
        path = f"C:/Windows/System32/{module_name}"
    
    uc.reg_write(UC_X86_REG_R11,REGS.rdx)
    
    log.warning(f"HOOK_API_CALL : GetModuleFileNameW, RDX : {hex(REGS.rdx)}, path : {path}")
    uc.mem_write(REGS.rsp+0x8,struct.pack('<Q',REGS.rbx))
    uc.mem_write(REGS.rsp+0x10,struct.pack('<Q',REGS.rbp))
    uc.mem_write(REGS.rsp+0x18,struct.pack('<Q',REGS.rsi))
    uc.mem_write(REGS.rdx,path.encode("utf-16"))
    uc.reg_write(UC_X86_REG_RAX,len(path))
    uc.reg_write(UC_X86_REG_RDX,0x0)
    uc.reg_write(UC_X86_REG_R8,0x0)
    
    ret(uc, REGS.rsp)
    

def hook_GetModuleHandleA(uc, log, regs):
    
    set_register(regs)
    
    d_address = 0
    
    handle = EndOfString(bytes(uc.mem_read(REGS.rcx, 0x50))).lower()
    
    if ".dll" not in handle: #nc load ws2_32
        handle += ".dll" 
    
    if handle in REFLECTOR:
        handle = REFLECTOR[handle]
    
    if handle in DLL_SETTING.LoadedDll:
        d_address = DLL_SETTING.LoadedDll[handle]

    log.warning(f"HOOK_API_CALL : GetModuleHandleA, Handle : {handle}, Address : {hex(d_address)}")   
    if d_address:
        uc.reg_write(UC_X86_REG_RAX, d_address)
    
    ret(uc, REGS.rsp)

def hook_LoadLibraryA(uc, log, regs):
    
    set_register(regs)

    d_address = 0
    dllName = EndOfString(bytes(uc.mem_read(REGS.rcx, 0x20))) #byte string
    
    # Record DLL load for runtime IAT reconstruction
    api_recorder.record(dllName, "__load__")
    
    if dllName not in DLL_SETTING.LoadedDll:
        PE_Loader(uc, dllName, GLOBAL_VAR.dll_end)
        InvDllDict()

    d_address = DLL_SETTING.LoadedDll[dllName]
    if d_address:
        uc.reg_write(UC_X86_REG_RAX,d_address)
    else:
        print(f"[LOAD ERROR] {dllName}: {hex(d_address)}")


    log.warning(f"HOOK_API_CALL : LoadLibraryA, {dllName}: {hex(d_address)}")
    
    uc.mem_write(REGS.rsp+0x8,struct.pack('<Q',REGS.rbx))
    uc.mem_write(REGS.rsp+0x10,struct.pack('<Q',REGS.rsi))
    
    ret(uc, REGS.rsp)

def hook_GetProcAddress(uc, log, regs):
    
    set_register(regs)
  
    f_address = 0

    functionName=EndOfString(bytes(uc.mem_read(REGS.rdx, 0x20)))
    dll_name = DLL_SETTING.InverseLoadedDll.get(REGS.rcx, "unknown.dll")
    functionName_full = dll_name + "_" + functionName
    
    # Record this API call for runtime IAT reconstruction
    api_recorder.record(dll_name, functionName)
    
    try:
        f_address = DLL_SETTING.DllFuncs[functionName_full]
    except KeyError:
        f_address = 0

    uc.mem_write(REGS.rsp+0x8,struct.pack('<Q',REGS.rbx))
    uc.mem_write(REGS.rsp+0x18,struct.pack('<Q',REGS.rbp))
    uc.mem_write(REGS.rsp+0x20,struct.pack('<Q',REGS.rsi))
    uc.mem_write(REGS.rsp+0x10,struct.pack('<Q',f_address))
    if f_address:
        uc.reg_write(UC_X86_REG_RAX,f_address)
    log.warning(f"HOOK_API_CALL : GetProcAddress, {functionName_full}: {hex(f_address)}")
    
    

    ret(uc, REGS.rsp)
    


def hook_ZwOpenThread(uc, log, regs):
    
    set_register(regs)
    
    handle = random.randrange(1,0x200)
    ThreadHandle.append(handle)
    uc.mem_write(REGS.rsp+0x90,struct.pack('<Q',handle))

    log.warning(f"HOOK_API_CALL : ZwOpenThread, handle : {hex(handle)}")    
    
    
    ret(uc, REGS.rsp)
    


def hook_GetUserDefaultUILanguage(uc, log, regs):
    
    set_register(regs)
    
    uc.mem_write(REGS.rsp+0x8,struct.pack('<Q',0x409))
    log.warning(f"HOOK_API_CALL : GetUserDefaultUILanguage, RCX : {hex(REGS.rcx)}")
    
    
    uc.reg_write(UC_X86_REG_RAX,0x409)
    ret(uc, REGS.rsp)
    


def hook_RtlAllocateHeap(uc, log, regs):
    
    set_register(regs)

    HEAP_HANDLE.HeapHandle.append(HEAP_HANDLE.HeapHandle[HEAP_HANDLE.HeapHandleSize-1]+(align(REGS.r8)))
    HEAP_HANDLE.HeapHandleSize+=1

    uc.reg_write(UC_X86_REG_RAX,HEAP_HANDLE.HeapHandle[HEAP_HANDLE.HeapHandleSize-1])
   
    uc.mem_write(REGS.rsp+0x8,struct.pack('<Q',0x3))
    uc.mem_write(REGS.rsp+0x10,struct.pack('<Q',REGS.rbx))
    uc.mem_write(REGS.rsp+0x18,struct.pack('<Q',REGS.rsi))
    uc.mem_write(REGS.rsp+0x20,struct.pack('<Q',REGS.rdi))

    log.warning(f"HOOK_API_CALL : RtlAllocateHeap, handle : {hex(REGS.rcx)}, RAX : {hex(HEAP_HANDLE.HeapHandle[HEAP_HANDLE.HeapHandleSize-1])}")
    
    ret(uc, REGS.rsp)
    

def hook_GetCurrentDirectoryW(uc, log, regs):
    
    set_register(regs)
    
    cwd = os.getcwd()
    cwd_len = len(cwd)
    
    log.warning(f"HOOK_API_CALL : GetCurrentDirectoryW, RCX : {hex(REGS.rcx)}, RDX : {hex(REGS.rdx)}, path : {cwd}, len : {hex(cwd_len)}")
    
    uc.mem_write(REGS.rdx,cwd.encode('utf-8'))
    uc.reg_write(UC_X86_REG_RAX,cwd_len)
    uc.reg_write(UC_X86_REG_RCX,REGS.rdx)
    uc.reg_write(UC_X86_REG_R11,REGS.rdx)
    
    ret(uc, REGS.rsp)
    

def hook_SetCurrentDirectoryW(uc, log, regs):
    
    set_register(regs)
    
    log.warning(f"HOOK_API_CALL : SetCurrentDirectoryW")
    
    
    uc.reg_write(UC_X86_REG_RAX, 0x1)
    ret(uc, REGS.rsp)
    

def hook_GetCommandLineA(uc, log, regs):
    
    set_register(regs)

    path = "\""+os.path.abspath(GLOBAL_VAR.sample_path)+"\""
    
    log.warning(f"HOOK_API_CALL : GetCommandLineA, path : {path}")
    
    
    uc.mem_write(0x000001E9E3900000,path.encode("utf-8"))
    uc.reg_write(UC_X86_REG_RAX,0x000001E9E3900000) #임시포인터
    ret(uc, REGS.rsp)
    

def hook_ZwAllocateVirtualMemory(uc, log, regs):
    
    set_register(regs)

    REGS.rcx = struct.unpack('<Q',uc.mem_read(uc.reg_read(UC_X86_REG_RDX),8))[0]
    REGS.rdx = struct.unpack('<Q',uc.mem_read(uc.reg_read(UC_X86_REG_R9),8))[0]
    REGS.r9 = struct.unpack('<L',uc.mem_read(REGS.rsp+0x30,4))[0]
    
    page_size = 4 * 1024
    if REGS.rcx == 0:
        offset = GLOBAL_VAR.allocate_chunk_end
    else:
        offset = REGS.rcx

    aligned_size = align(REGS.rdx, page_size)
    uc.mem_map(offset, aligned_size ,privilege[REGS.r9])
    GLOBAL_VAR.allocate_chunk_end = offset + aligned_size
    AllocChunk[offset] = aligned_size
    log.warning(f"HOOK_API_CALL : ZwAllocateVirtualMemory, Address : {hex(offset)}, Size : {hex(REGS.rdx)}, Privilege : {hex(REGS.r9)}")
    uc.mem_write(uc.reg_read(UC_X86_REG_RDX),struct.pack('<Q',offset))
    uc.mem_write(uc.reg_read(UC_X86_REG_RDX)+0x8,struct.pack('<Q',aligned_size))

    
    uc.reg_write(UC_X86_REG_RAX,0x0)
    uc.reg_write(UC_X86_REG_RDX,0x0)
    uc.reg_write(UC_X86_REG_R8,REGS.rsp)
    uc.reg_write(UC_X86_REG_R9,REGS.rbp)
    ret(uc, REGS.rsp)
    



def hook_VirtualFree(uc, log, regs):
    
    set_register(regs)
    
   
    log.warning(f"HOOK_API_CALL : VirtualFree, Address : {hex(REGS.rcx)}")    
    uc.mem_unmap(REGS.rcx, AllocChunk[REGS.rcx])

    uc.mem_write(REGS.rsp+0x8,struct.pack('<Q',AllocChunk[REGS.rcx]))
    uc.mem_write(REGS.rsp+0x10,struct.pack('<Q',REGS.rcx))
    uc.mem_write(REGS.rsp+0x18,struct.pack('<Q',REGS.rbx))
    uc.mem_write(REGS.rsp+0x20,struct.pack('<Q',REGS.rsi))

    
    uc.reg_write(UC_X86_REG_RAX,0x1)
    ret(uc, REGS.rsp)
    


def hook_OpenThreadToken(uc, log, regs):
    global Token
    set_register(regs)
    token = random.randrange(1,0x200)
    Token.append(token)
    log.warning(f"HOOK_API_CALL : OpenThreadToken")
    uc.reg_write(UC_X86_REG_RAX,0x0)
    ret(uc, REGS.rsp)
    

def hook_OpenProcessToken(uc, log, regs):
    global Token
    set_register(regs)
    token = random.randrange(1, 0x200)
    Token.append(token)
    
    log.warning(f"HOOK_API_CALL : OpenProcessToken, token : {hex(token)}")
    uc.mem_write(REGS.r8,struct.pack('<Q',token))
    
    
    uc.reg_write(UC_X86_REG_RAX,0x1)
    ret(uc, REGS.rsp)
    

def hook_ZwOpenThreadTokenEx(uc, log, regs):
    
    set_register(regs)
    
    
    log.warning(f"HOOK_API_CALL : ZwOpenThreadTokenEx")
    
    
    uc.reg_write(UC_X86_REG_RAX, 0x00000000C000007C)
    uc.reg_write(UC_X86_REG_RDX, 0x0)
    uc.reg_write(UC_X86_REG_R8, REGS.rsp)
    uc.reg_write(UC_X86_REG_R9, REGS.rbp)
    uc.reg_write(UC_X86_REG_RCX, REGS.rip + 0x14)
    ret(uc, REGS.rsp)
    

def hook_ZwOpenProcessTokenEx(uc, log, regs):
    global Token
    set_register(regs)
     # tmp=ret

    token = random.randrange(1,0x200)
    Token.append(token)
    
    log.warning(f"HOOK_API_CALL : ZwOpenProcessTokenEx, token : {hex(token)}")
    
    uc.mem_write(REGS.r9,struct.pack('<Q',token))
    uc.reg_write(UC_X86_REG_RAX, 0x0)
    uc.reg_write(UC_X86_REG_RDX, 0x0)
    uc.reg_write(UC_X86_REG_R8, REGS.rsp)
    uc.reg_write(UC_X86_REG_R9, REGS.rbp)
    uc.reg_write(UC_X86_REG_R10, 0x0)
    uc.reg_write(UC_X86_REG_RCX, REGS.rip + 0x14)
    ret(uc, REGS.rsp)
    

def hook_ZwDuplicateToken(uc, log, regs):
    
    set_register(regs)
    
    
    log.warning(f"HOOK_API_CALL : ZwDuplicateToken")
    
    uc.reg_write(UC_X86_REG_RAX, 0x0)
    uc.reg_write(UC_X86_REG_RDX, 0x0)
    uc.reg_write(UC_X86_REG_R8, REGS.rsp)
    uc.reg_write(UC_X86_REG_R9, REGS.rbp)
    uc.reg_write(UC_X86_REG_R10, 0x0)
    uc.reg_write(UC_X86_REG_RCX, REGS.rip+0x14)
    ret(uc, REGS.rsp)
    

def hook_ZwQueryInformationToken(uc, log, regs):
    global Token
    set_register(regs)
    
    token = random.randrange(1,0x200)
    Token.append(token)
    log.warning(f"HOOK_API_CALL : ZwQueryInformationToken, token : {hex(token)}")
    uc.mem_write(REGS.r10,struct.pack('<Q',token))
    
   
    uc.reg_write(UC_X86_REG_RAX,0x23) # STATUS_BUFFER_TOO_SMALL
    ret(uc, REGS.rsp)
    

def hook_ZwClose(uc, log, regs):
    
    set_register(regs)
    
    log.warning(f"HOOK_API_CALL : ZwClose, handle : {hex(REGS.rcx)}")
    
    
    uc.reg_write(UC_X86_REG_RAX, 0x0)
    uc.reg_write(UC_X86_REG_R8, REGS.rsp)
    uc.reg_write(UC_X86_REG_R9, REGS.rbp)
    uc.reg_write(UC_X86_REG_R10, 0x0)
    uc.reg_write(UC_X86_REG_RCX, REGS.rip+0x14)
    
    ret(uc, REGS.rsp)
    

def hook_ZwAccessCheck(uc, log, regs):
    
    set_register(regs)
    
    log.warning(f"HOOK_API_CALL : ZwAccessCheck")
    
    
    uc.reg_write(UC_X86_REG_RAX, 0x0)
    uc.reg_write(UC_X86_REG_RDX, 0x0)
    uc.reg_write(UC_X86_REG_R8, REGS.rsp)
    uc.reg_write(UC_X86_REG_R9, REGS.rbp)
    uc.reg_write(UC_X86_REG_R10, 0x0)
    uc.reg_write(UC_X86_REG_RCX, REGS.rip+0x14)
    
    ret(uc, REGS.rsp)
    


def hook_VirtualAlloc(uc, log, regs):
    """V7: 监控 VirtualAlloc — Themida 3.x 在此分配执行页"""
    set_register(regs)
    addr = REGS.rcx; size = REGS.rdx; alloc_type = REGS.r8 & 0xFFFFFFFF; protect = REGS.r9 & 0xFFFFFFFF
    log.warning(f"HOOK_API_CALL : VirtualAlloc, Address : 0x{addr:x}, Size : 0x{size:x}, Type : 0x{alloc_type:x}, Protect : 0x{protect:x}")
    
    if addr == 0 and size > 0:
        # Allocate memory in UC
        from unicorn import UC_PROT_ALL
        new_addr = 0x30000000  # dedicated alloc region
        aligned = (size + 0xFFF) & ~0xFFF
        uc.mem_map(new_addr, aligned, UC_PROT_ALL)
        uc.reg_write(UC_X86_REG_RAX, new_addr)
    else:
        uc.reg_write(UC_X86_REG_RAX, addr)
    
    ret(uc, REGS.rsp)
    

    set_register(regs)
    REGS.r8 = uc.reg_read(UC_X86_REG_R8) & 0xffffffff

    
    
    log.warning(f"HOOK_API_CALL : VirtualProtect, Address : {hex(REGS.rcx)}, Size : {hex(REGS.rdx)}, Privilege : {hex(REGS.r8)}")

    # V6: block execute on .text (Themida decrypts → we keep RW)
    TEXT_START = 0x140001000
    TEXT_SIZE  = 0x1a4000  # page-aligned
    if TEXT_START <= REGS.rcx < TEXT_START + TEXT_SIZE:
        prot = REGS.r8 & 0xFFFFFFFF
        if prot & 0x10:
            log.warning(f"  [V6] Stripping execute from .text VirtualProtect")
            REGS.r8 = prot & ~0xF0
            uc.reg_write(UC_X86_REG_R8, REGS.r8)
    
    if align(REGS.rcx) > REGS.rcx:
        offset =  REGS.rcx - (align(REGS.rcx)- 0x1000)
        uc.mem_protect(align(REGS.rcx)-0x1000, align(REGS.rdx+offset), privilege[REGS.r8])   
    else:   
        uc.mem_protect(align(REGS.rcx), align(REGS.rdx), privilege[REGS.r8])
    
    oldPriv=0
    for section in GLOBAL_VAR.section_info:
        if (REGS.rcx - section[1]) >= 0 and (REGS.rcx - section[1]) < section[2] :
            oldPriv = section[3]
            break         
    
    uc.mem_write(REGS.rsp+8, struct.pack('<Q',REGS.rdx))
    uc.mem_write(REGS.r9, struct.pack('<L',oldPriv))
    uc.reg_write(UC_X86_REG_RAX,0x1)
    uc.reg_write(UC_X86_REG_RDX,0x0)
    uc.reg_write(UC_X86_REG_R8,REGS.rsp-0x50)
    uc.reg_write(UC_X86_REG_R9,REGS.r8)
    ret(uc, REGS.rsp)
    

def hook_NtUserGetForegroundWindow(uc, log, regs):
    
    set_register(regs)
    
    log.warning(f"HOOK_API_CALL : NtUserGetForegroundWindow")
    
    
    uc.reg_write(UC_X86_REG_RAX, 0x0)
    uc.reg_write(UC_X86_REG_R8, REGS.rsp)
    uc.reg_write(UC_X86_REG_R9, REGS.rbp)
    uc.reg_write(UC_X86_REG_R10, 0x0)
    uc.reg_write(UC_X86_REG_RCX, REGS.rip+0x14)
    
    ret(uc, REGS.rsp)
    

def hook_GetWindowTextA(uc, log, regs):
    
    set_register(regs)
    
    
    log.warning(f"HOOK_API_CALL : GetWindowTextA")
    
    
    uc.reg_write(UC_X86_REG_RAX, 0x0)
    uc.mem_write(REGS.rsp+0x8,struct.pack('<Q', REGS.rbx))
    uc.mem_write(REGS.rsp+0x10,struct.pack('<Q', REGS.rsi))
    ret(uc, REGS.rsp)
    


def hook_ZwRaiseException(uc, log, regs):
    
    set_register(regs)
    log.warning(f"HOOK_API_CALL : ZwRaiseException")
    
    
    uc.reg_write(UC_X86_REG_RAX,0x0)
    
    ret(uc, REGS.rsp)
    
'''
'''
def hook_RtlRaiseStatus(uc, log, regs):
    
    set_register(regs)
    log.warning(f"HOOK_API_CALL : RtlRaiseStatus")
    
    
    uc.reg_write(UC_X86_REG_RAX,0x0)
    
    ret(uc, REGS.rsp)
    



def hook_RtlFreeHeap(uc, log, regs):
    
    set_register(regs)
    log.warning(f"HOOK_API_CALL : RtlFreeHeap, handle : {hex(REGS.rcx)},")
    
    
    uc.reg_write(UC_X86_REG_RAX,0x1)
    ret(uc, REGS.rsp)
    

def hook_ZwQueryInformationProcess(uc, log, regs):  # 안티디버깅
    
    set_register(regs)
    
    log.warning(f"HOOK_API_CALL : ZwQueryInformationProcess")
    
    
    if REGS.rdx == 0x7:
        uc.mem_write(REGS.r8,struct.pack('<Q',0x0))
        uc.reg_write(UC_X86_REG_RAX, 0x0)
    elif REGS.rdx == 0x1e:
        uc.reg_write(UC_X86_REG_RAX, 0xC0000353)
        uc.mem_write(REGS.r8,struct.pack('<Q',0x0))
    elif REGS.rdx == 0x1f:
        uc.reg_write(UC_X86_REG_RAX, 0x1)
        uc.mem_write(REGS.r8,struct.pack('<Q',0x1))
    else:
        uc.reg_write(UC_X86_REG_RAX, 0x0)

    uc.reg_write(UC_X86_REG_RDX, 0x0)
    uc.reg_write(UC_X86_REG_RCX, REGS.rsi+0x14)
    uc.reg_write(UC_X86_REG_R8, REGS.rsp)
    uc.reg_write(UC_X86_REG_R9, REGS.rbp)
    uc.reg_write(UC_X86_REG_R10, 0x0)
    
    ret(uc, REGS.rsp)
    


def hook_ZwQuerySystemInformation(uc, log, regs):  # 안티디버깅
    
    set_register(regs)
    
    
    log.warning(f"HOOK_API_CALL : ZwQuerySystemInformation")
    
    

    #uc.reg_write(UC_X86_REG_RAX, 0xC0000023)
    uc.reg_write(UC_X86_REG_RAX, 0x0)
    ret(uc, REGS.rsp)
    

def hook_ZwSetInformationThread(uc, log, regs):  # 안티디버깅
    
    set_register(regs)
    
    log.warning(f"HOOK_API_CALL : ZwSetInformationThread")
    
    
    if REGS.rdx == 0x11:
        uc.reg_write(UC_X86_REG_RDX, 0x0)

    uc.reg_write(UC_X86_REG_RAX, 0x0)
    #uc.reg_write(UC_X86_REG_RCX, rax+0x14)
    #uc.reg_write(UC_X86_REG_R8, rsp)
    #uc.reg_write(UC_X86_REG_R9, rdi)
    
    ret(uc, REGS.rsp)
    

def hook_ZwSetInformationProcess(uc, log, regs):  # 안티디버깅
    
    set_register(regs)
    
    
    log.warning(f"HOOK_API_CALL : ZwSetInformationProcess")
    
    
    if REGS.rdx == 0x11:
        uc.reg_write(UC_X86_REG_RDX, 0x0)

    uc.reg_write(UC_X86_REG_RAX, 0x0)
    uc.reg_write(UC_X86_REG_RCX, REGS.rax+0x14)
    uc.reg_write(UC_X86_REG_R8, REGS.rsp)
    uc.reg_write(UC_X86_REG_R9, REGS.rdi)
    ret(uc, REGS.rsp)
    

def hook_RegOpenKeyExA(uc, log, regs): 
    
    set_register(regs)
    
    
    log.warning(f"HOOK_API_CALL : RegOpenKeyExA")
    
    text = EndOfString(bytes(uc.mem_read(REGS.rdx, 0x100)))
    if text == "HARDWARE\ACPI\DSDT\VBOX__":
        uc.reg_write(UC_X86_REG_RAX, 0x2)
    else:
        uc.reg_write(UC_X86_REG_RAX, 0x0)
    
    ret(uc, REGS.rsp)
    

def hook_RegQueryValueExA(uc, log, regs): 
    
    set_register(regs)
    
    log.warning(f"HOOK_API_CALL : RegQueryValueExA")
    
    uc.reg_write(UC_X86_REG_RAX, 0x0)
    ret(uc, REGS.rsp)
    

def hook_RegCloseKey(uc, log, regs): 
    
    set_register(regs)
    
    
    log.warning(f"HOOK_API_CALL : RegCloseKey")
    

    uc.reg_write(UC_X86_REG_RAX, 0x0)
    ret(uc, REGS.rsp)
    


def hook_ZwGetContextThread(uc, log, regs): #안티디버깅
    
    set_register(regs)
    log.warning(f"HOOK_API_CALL : ZwGetContextThread")
    
    
    uc.reg_write(UC_X86_REG_RAX, 0)
    ret(uc, REGS.rsp)
    

def hook_ZwOpenKeyEx(uc, log, regs): #안티디버깅
    
    set_register(regs)
    
    
    log.warning(f"HOOK_API_CALL : ZwOpenKeyEx")
    
    
    handle = random.randrange(1,0x200)

    uc.mem_write(REGS.rcx, struct.pack('<Q',handle))
    uc.reg_write(UC_X86_REG_RAX, 0)
    uc.reg_write(UC_X86_REG_R8, REGS.rsp)
    uc.reg_write(UC_X86_REG_R9, REGS.rbp)
    uc.reg_write(UC_X86_REG_RDX, 0x0)
    ret(uc, REGS.rsp)
    
def hook__set_fmode(uc, log, regs):
    
    set_register(regs)
   
    log.warning(f"HOOK_API_CALL : _set_fmode, mode: {hex(REGS.rcx)}")
    
    
    ret(uc, REGS.rsp)

def hook__crt_atexit(uc, log, regs):
    
    set_register(regs)
   
    log.warning(f"HOOK_API_CALL : _crt_atexit, func+address: {hex(REGS.rcx)}")
    
    uc.reg_write(UC_X86_REG_RAX, 0x0)
    ret(uc, REGS.rsp)

def hook__configure_narrow_argv(uc, log, regs):
    
    set_register(regs)
   
    log.warning(f"HOOK_API_CALL : _configure_narrow_argv ")
    
    uc.reg_write(UC_X86_REG_RAX, 0x0)
    ret(uc, REGS.rsp)

def hook__configthreadlocale(uc, log, regs):
    
    set_register(regs)
   
    log.warning(f"HOOK_API_CALL : _configthreadlocale ")
    
    uc.reg_write(UC_X86_REG_RAX, REGS.rcx+2)
    ret(uc, REGS.rsp)

def hook__initialize_narrow_environment(uc, log, regs):
    
    set_register(regs)
   
    log.warning(f"HOOK_API_CALL : _initialize_narrow_environment ")
    
    uc.reg_write(UC_X86_REG_RAX, 0)
    ret(uc, REGS.rsp)

def hook__get_initial_narrow_environment(uc, log, regs):
    
    set_register(regs)
   
    log.warning(f"HOOK_API_CALL : _get_initial_narrow_environment ")
    
    uc.reg_write(UC_X86_REG_RAX, 0)
    ret(uc, REGS.rsp)
    

def hook__initterm(uc, log, regs):
    
    set_register(regs)
   
    log.warning(f"HOOK_API_CALL : _initterm, start : {hex(REGS.rcx)}, end : {hex(REGS.rdx)} ")
    
    uc.reg_write(UC_X86_REG_RAX, 0)
    ret(uc, REGS.rsp)
    
def hook__isatty(uc, log, regs):
    
    set_register(regs)
  
    log.warning(f"HOOK_API_CALL : _isatty")
    
    uc.reg_write(UC_X86_REG_RAX,0x1)
    ret(uc, REGS.rsp)
    

def hook___stdio_common_vfprintf(uc, log, regs):
    
    set_register(regs)
    
    uc.reg_write(UC_X86_REG_R11,REGS.rdx)
    
    string = EndOfString(bytes(uc.mem_read(REGS.r8, 0x50)))
    log.warning(f"HOOK_API_CALL : __stdio_common_vfprintf")
    uc.mem_write(REGS.rsp+0x10,struct.pack('<Q',REGS.rcx))
    uc.mem_write(REGS.rsp+0x18,struct.pack('<Q',REGS.r8))
    uc.mem_write(REGS.rsp+0x20,struct.pack('<Q',REGS.rsi))
    uc.mem_write(REGS.rsp+0x28,struct.pack('<Q',REGS.rdx))
    uc.reg_write(UC_X86_REG_RAX,len(string))
    uc.reg_write(UC_X86_REG_RDX,0x0)
    uc.reg_write(UC_X86_REG_R8,0x0)
    
    ret(uc, REGS.rsp)
    

def hook_MessageBoxExW(uc, log, regs):
    
    set_register(regs)
  
    text = bytes(uc.mem_read(REGS.rdx, 0x100)).decode('utf-16')
    title = bytes(uc.mem_read(REGS.r8, 0x10)).decode('utf-16')
    
    log.warning(f"HOOK_API_CALL : MessageBoxExW, hadnle : {hex(REGS.rcx)}, TEXT : {text}, TITLE : {title}")
    
    uc.reg_write(UC_X86_REG_RAX,0x1)
    ret(uc, REGS.rsp)
    

def hook_MessageBoxW(uc, log, regs):
    
    set_register(regs)
  
    text = bytes(uc.mem_read(REGS.rdx, 0x20)).decode('utf-16')
    title = bytes(uc.mem_read(REGS.r8, 0x10)).decode('utf-16')
    
    log.warning(f"HOOK_API_CALL : MessageBoxW, hadnle : {hex(REGS.rcx)}, TEXT : {text}, TITLE : {title}")
    
    uc.reg_write(UC_X86_REG_RAX,0x1)
    ret(uc, REGS.rsp)
    

def hook_exit(uc, log, regs):
    
    set_register(regs)
    log.warning(f"HOOK_API_CALL : exit, Process Terminate.")

    return 1

# =====================================================================
# Bobalkkagi升级: 新增API钩子 (33-80)
#
# 反调试/反模拟策略说明:
# Themida 3.1.8+ 会检测:
#   - 调试端口 (ZwQueryInformationProcess ProcessDebugPort)
#   - 调试标志 (ZwQueryInformationProcess ProcessDebugFlags)
#   - 内核调试器 (ZwQuerySystemInformation)
#   - RDTSC 时间戳延迟
#   - KUSER_SHARED_DATA 中的 KdDebuggerEnabled
#   - PEB 中的 BeingDebugged / NtGlobalFlag
#   - 硬件调试寄存器
# 每个hook的返回策略在函数注释中标注
# =====================================================================

# ----- ntdll 注册表操作 (33-36) -----

def hook_ZwOpenKey(uc, log, regs):
    """ZwOpenKey - 返回成功+伪handle"""
    set_register(regs)
    handle = random.randrange(1, 0x200)
    if REGS.rdx:  # KeyHandle output
        uc.mem_write(REGS.rdx, struct.pack('<Q', handle))
    log.warning(f"HOOK_API_CALL : ZwOpenKey, handle=0x{handle:x}")
    uc.reg_write(UC_X86_REG_RAX, 0x0)  # STATUS_SUCCESS
    ret(uc, REGS.rsp)

def hook_ZwCreateKey(uc, log, regs):
    """ZwCreateKey - 返回成功+伪handle"""
    set_register(regs)
    handle = random.randrange(1, 0x200)
    if REGS.rcx:  # KeyHandle output
        uc.mem_write(REGS.rcx, struct.pack('<Q', handle))
    log.warning(f"HOOK_API_CALL : ZwCreateKey, handle=0x{handle:x}")
    uc.reg_write(UC_X86_REG_RAX, 0x0)
    ret(uc, REGS.rsp)

def hook_ZwQueryValueKey(uc, log, regs):
    """ZwQueryValueKey - 伪装返回STATUS_OBJECT_NAME_NOT_FOUND"""
    set_register(regs)
    log.warning(f"HOOK_API_CALL : ZwQueryValueKey")
    uc.reg_write(UC_X86_REG_RAX, 0xC0000034)  # STATUS_OBJECT_NAME_NOT_FOUND
    ret(uc, REGS.rsp)

def hook_ZwDeleteKey(uc, log, regs):
    """ZwDeleteKey - 返回成功"""
    set_register(regs)
    log.warning(f"HOOK_API_CALL : ZwDeleteKey")
    uc.reg_write(UC_X86_REG_RAX, 0x0)
    ret(uc, REGS.rsp)

# ----- ntdll 文件/内存映射 (37-40) -----

def hook_ZwCreateFile(uc, log, regs):
    """ZwCreateFile - 返回伪handle+成功"""
    set_register(regs)
    handle = random.randrange(0x50, 0x200)
    # IoStatusBlock at r8
    if REGS.r8:
        try:
            uc.mem_write(REGS.r8+0x0, struct.pack('<Q', 0x0))  # Status
            uc.mem_write(REGS.r8+0x8, struct.pack('<Q', 0x0))  # Information
        except:
            pass
    log.warning(f"HOOK_API_CALL : ZwCreateFile, handle=0x{handle:x}")
    uc.reg_write(UC_X86_REG_RAX, 0x0)  # STATUS_SUCCESS
    ret(uc, REGS.rsp)

def hook_ZwOpenFile(uc, log, regs):
    """ZwOpenFile - 返回伪handle+成功"""
    set_register(regs)
    handle = random.randrange(0x50, 0x200)
    log.warning(f"HOOK_API_CALL : ZwOpenFile, handle=0x{handle:x}")
    uc.reg_write(UC_X86_REG_RAX, 0x0)
    ret(uc, REGS.rsp)

def hook_ZwCreateSection(uc, log, regs):
    """ZwCreateSection - 返回伪handle+成功"""
    set_register(regs)
    handle = random.randrange(0x50, 0x200)
    if REGS.rcx:
        uc.mem_write(REGS.rcx, struct.pack('<Q', handle))
    log.warning(f"HOOK_API_CALL : ZwCreateSection, handle=0x{handle:x}")
    uc.reg_write(UC_X86_REG_RAX, 0x0)
    ret(uc, REGS.rsp)

def hook_ZwMapViewOfSection(uc, log, regs):
    """ZwMapViewOfSection - 在分配块中映射内存"""
    set_register(regs)
    offset = GLOBAL_VAR.allocate_chunk_end
    size = 0x10000  # 64KB default
    try:
        uc.mem_map(offset, size, UC_PROT_ALL)
    except:
        pass
    GLOBAL_VAR.allocate_chunk_end = offset + size
    if REGS.rdx:
        uc.mem_write(REGS.rdx, struct.pack('<Q', offset))
    if REGS.r9:
        uc.mem_write(REGS.r9, struct.pack('<Q', size))
    log.warning(f"HOOK_API_CALL : ZwMapViewOfSection, addr=0x{offset:x}, size=0x{size:x}")
    uc.reg_write(UC_X86_REG_RAX, 0x0)
    ret(uc, REGS.rsp)

# ----- ntdll 同步/线程 (41-44) -----

def hook_ZwDelayExecution(uc, log, regs):
    """ZwDelayExecution - 跳过延时（不等待）"""
    set_register(regs)
    log.warning(f"HOOK_API_CALL : ZwDelayExecution, Alertable=0x{REGS.rcx:x}")
    uc.reg_write(UC_X86_REG_RAX, 0x0)  # STATUS_SUCCESS (no wait)
    ret(uc, REGS.rsp)

def hook_ZwCreateMutant(uc, log, regs):
    """ZwCreateMutant - 返回伪mutant handle"""
    set_register(regs)
    handle = random.randrange(1, 0x200)
    if REGS.rcx:
        uc.mem_write(REGS.rcx, struct.pack('<Q', handle))
    log.warning(f"HOOK_API_CALL : ZwCreateMutant, handle=0x{handle:x}")
    uc.reg_write(UC_X86_REG_RAX, 0x0)
    ret(uc, REGS.rsp)

def hook_ZwCreateEvent(uc, log, regs):
    """ZwCreateEvent - 返回伪event handle"""
    set_register(regs)
    handle = random.randrange(1, 0x200)
    if REGS.rcx:
        uc.mem_write(REGS.rcx, struct.pack('<Q', handle))
    log.warning(f"HOOK_API_CALL : ZwCreateEvent, handle=0x{handle:x}")
    uc.reg_write(UC_X86_REG_RAX, 0x0)
    ret(uc, REGS.rsp)

def hook_ZwOpenEvent(uc, log, regs):
    """ZwOpenEvent - 返回伪event handle"""
    set_register(regs)
    handle = random.randrange(1, 0x200)
    if REGS.rdx:
        uc.mem_write(REGS.rdx, struct.pack('<Q', handle))
    log.warning(f"HOOK_API_CALL : ZwOpenEvent, handle=0x{handle:x}")
    uc.reg_write(UC_X86_REG_RAX, 0x0)
    ret(uc, REGS.rsp)

# ----- ntdll 进程/线程 (45-48) -----

def hook_ZwCreateThreadEx(uc, log, regs):
    """ZwCreateThreadEx - 返回伪thread handle"""
    set_register(regs)
    handle = random.randrange(0x200, 0x400)
    if REGS.rcx:
        uc.mem_write(REGS.rcx, struct.pack('<Q', handle))
    log.warning(f"HOOK_API_CALL : ZwCreateThreadEx, handle=0x{handle:x}, "
                f"start=0x{struct.unpack('<Q',uc.mem_read(REGS.rsp+0x28,8))[0]:x}" 
                if REGS.rsp else f"start=???")
    uc.reg_write(UC_X86_REG_RAX, 0x0)
    ret(uc, REGS.rsp)

def hook_ZwTerminateProcess(uc, log, regs):
    """ZwTerminateProcess - 阻止进程终止"""
    set_register(regs)
    log.warning(f"HOOK_API_CALL : ZwTerminateProcess, handle=0x{REGS.rcx:x}, "
                f"status=0x{REGS.rdx:x}")
    # 如果是终止整个进程(handle=-1=0xffffffffffffffff)
    if REGS.rcx == 0xffffffffffffffff or REGS.rcx == 0xffffffff:
        log.warning(f"  -> BLOCKED self-termination")
        # Don't terminate - just return and continue execution
        uc.reg_write(UC_X86_REG_RAX, 0xC0000022)  # STATUS_ACCESS_DENIED
        ret(uc, REGS.rsp)
        return 0  # Don't stop emulation
    # 单个线程终止 - allow
    uc.reg_write(UC_X86_REG_RAX, 0x0)
    ret(uc, REGS.rsp)

def hook_ZwRaiseHardError(uc, log, regs):
    """ZwRaiseHardError - 忽略硬错误（反调试常用）"""
    set_register(regs)
    log.warning(f"HOOK_API_CALL : ZwRaiseHardError - ignored")
    uc.reg_write(UC_X86_REG_RAX, 0x0)
    ret(uc, REGS.rsp)

def hook_ZwQueryInformationThread(uc, log, regs):
    """ZwQueryInformationThread - 反调试绕过"""
    set_register(regs)
    info_class = REGS.rdx
    log.warning(f"HOOK_API_CALL : ZwQueryInformationThread, class=0x{info_class:x}")
    
    if info_class == 0x11:  # ThreadHideFromDebugger
        uc.reg_write(UC_X86_REG_RAX, 0x0)  # STATUS_SUCCESS (already hidden)
    else:
        uc.reg_write(UC_X86_REG_RAX, 0xC0000353)  # STATUS_INFO_LENGTH_MISMATCH
    ret(uc, REGS.rsp)

# ----- ntdll 杂项 (49-51) -----

def hook_ZwQueryObject(uc, log, regs):
    """ZwQueryObject - 返回STATUS_INFO_LENGTH_MISMATCH（反调试）
    
    策略: Themida 3.1.8+通过NtQueryObject检测调试器句柄。
    返回STATUS_INFO_LENGTH_MISMATCH阻止枚举。"""
    set_register(regs)
    log.warning(f"HOOK_API_CALL : ZwQueryObject, handle=0x{REGS.rcx:x}, "
                f"class=0x{REGS.rdx:x}")
    uc.reg_write(UC_X86_REG_RAX, 0xC0000004)  # STATUS_INFO_LENGTH_MISMATCH
    ret(uc, REGS.rsp)

def hook_ZwYieldExecution(uc, log, regs):
    """ZwYieldExecution - 让出CPU"""
    set_register(regs)
    log.warning(f"HOOK_API_CALL : ZwYieldExecution")
    uc.reg_write(UC_X86_REG_RAX, 0x101)  # STATUS_NO_YIELD_PERFORMED
    ret(uc, REGS.rsp)

def hook_ZwSetContextThread(uc, log, regs):
    """ZwSetContextThread - 允许设置上下文（反调试绕过）
    
    策略: Themida检查是否能通过此API访问其他线程上下文来判断调试器。"""
    set_register(regs)
    log.warning(f"HOOK_API_CALL : ZwSetContextThread, handle=0x{REGS.rcx:x}")
    uc.reg_write(UC_X86_REG_RAX, 0x0)  # STATUS_SUCCESS
    ret(uc, REGS.rsp)

def hook_ZwGetContextThread(uc, log, regs):
    """ZwGetContextThread - 返回成功（反调试绕过）"""
    set_register(regs)
    log.warning(f"HOOK_API_CALL : ZwGetContextThread, handle=0x{REGS.rcx:x}")
    uc.reg_write(UC_X86_REG_RAX, 0x0)
    ret(uc, REGS.rsp)

def hook_LdrLoadDll(uc, log, regs):
    """LdrLoadDll - 模拟DLL加载"""
    set_register(regs)
    # PathToFile at rdx
    try:
        if REGS.rdx:
            dll_path_ptr = struct.unpack('<Q', uc.mem_read(REGS.rdx, 8))[0]
            if dll_path_ptr:
                dll_path = EndOfString(bytes(uc.mem_read(dll_path_ptr, 0x100)))
                log.warning(f"HOOK_API_CALL : LdrLoadDll, path={dll_path}")
                dll_name = os.path.basename(dll_path).lower()
                if dll_name in DLL_SETTING.LoadedDll:
                    base = DLL_SETTING.LoadedDll[dll_name]
                    if REGS.r8:
                        uc.mem_write(REGS.r8, struct.pack('<Q', base))
                else:
                    from .loader import PE_Loader
                    PE_Loader(uc, dll_name, GLOBAL_VAR.dll_end)
    except Exception as e:
        log.warning(f"HOOK_API_CALL : LdrLoadDll - error: {e}")
    
    uc.reg_write(UC_X86_REG_RAX, 0x0)
    ret(uc, REGS.rsp)

# ----- kernel32 线程/同步 (52-54) -----

def hook_CreateThread(uc, log, regs):
    """CreateThread - 返回伪thread handle"""
    set_register(regs)
    handle = random.randrange(0x200, 0x400)
    tid = random.randrange(0x1000, 0x2000)
    log.warning(f"HOOK_API_CALL : CreateThread, start=0x{REGS.rdx:x}, "
                f"param=0x{REGS.r8:x}")
    uc.reg_write(UC_X86_REG_RAX, handle)
    ret(uc, REGS.rsp)

def hook_WaitForSingleObject(uc, log, regs):
    """WaitForSingleObject - 立即返回（不等待）"""
    set_register(regs)
    log.warning(f"HOOK_API_CALL : WaitForSingleObject, handle=0x{REGS.rcx:x}, "
                f"timeout=0x{REGS.rdx:x}")
    uc.reg_write(UC_X86_REG_RAX, 0x0)  # WAIT_OBJECT_0
    ret(uc, REGS.rsp)

def hook_WaitForMultipleObjects(uc, log, regs):
    """WaitForMultipleObjects - 立即返回"""
    set_register(regs)
    log.warning(f"HOOK_API_CALL : WaitForMultipleObjects")
    uc.reg_write(UC_X86_REG_RAX, 0x0)  # WAIT_OBJECT_0
    ret(uc, REGS.rsp)

# ----- kernel32 系统信息 (55-59) -----

def hook_GetSystemInfo(uc, log, regs):
    """GetSystemInfo - 返回伪系统信息"""
    set_register(regs)
    log.warning(f"HOOK_API_CALL : GetSystemInfo")
    if REGS.rcx:
        # SYSTEM_INFO structure (x64)
        info = struct.pack('<IIIHHIIIIQQ',
            0x0009,      # wProcessorArchitecture (PROCESSOR_ARCHITECTURE_AMD64)
            0x0000,      # wReserved
            0x00001000,  # dwPageSize
            0x00000000,  # lpMinimumApplicationAddress (low)
            0x00000000,  # lpMinimumApplicationAddress (high) - actually 64KB
            0x00000000,  # lpMaximumApplicationAddress (low)
            0x00007FFF,  # lpMaximumApplicationAddress (high) - user space max
            0x00000001,  # dwActiveProcessorMask (low)
            0x00000000,  # dwActiveProcessorMask (high)
            0x00000004,  # dwNumberOfProcessors
            0x00000000,  # dwProcessorType
            0x00000000,  # dwAllocationGranularity
            0x0004,      # wProcessorLevel
            0x0006,      # wProcessorRevision
        )
        uc.mem_write(REGS.rcx, info[:48])  # Write SYSTEM_INFO
    uc.reg_write(UC_X86_REG_RAX, 0x0)
    ret(uc, REGS.rsp)

def hook_GetNativeSystemInfo(uc, log, regs):
    """GetNativeSystemInfo - 同GetSystemInfo"""
    hook_GetSystemInfo(uc, log, regs)

def hook_QueryPerformanceCounter(uc, log, regs):
    """QueryPerformanceCounter - 返回递增计数器"""
    set_register(regs)
    global _qpc_counter
    try:
        _qpc_counter += 1000
    except:
        _qpc_counter = 1000
    if REGS.rcx:
        uc.mem_write(REGS.rcx, struct.pack('<Q', _qpc_counter))
    log.warning(f"HOOK_API_CALL : QueryPerformanceCounter")
    uc.reg_write(UC_X86_REG_RAX, 0x1)
    ret(uc, REGS.rsp)

def hook_GetTickCount(uc, log, regs):
    """GetTickCount - 返回伪tick"""
    set_register(regs)
    global _tick_counter
    try:
        _tick_counter += 16
    except:
        _tick_counter = 1000
    log.warning(f"HOOK_API_CALL : GetTickCount, tick={_tick_counter}")
    uc.reg_write(UC_X86_REG_RAX, _tick_counter)
    ret(uc, REGS.rsp)

def hook_GetTickCount64(uc, log, regs):
    """GetTickCount64 - 返回64位伪tick"""
    set_register(regs)
    global _tick_counter
    try:
        _tick_counter += 16
    except:
        _tick_counter = 1000
    log.warning(f"HOOK_API_CALL : GetTickCount64, tick={_tick_counter}")
    uc.reg_write(UC_X86_REG_RAX, _tick_counter)
    ret(uc, REGS.rsp)

# ----- kernel32 杂项 (60-68) -----

def hook_IsProcessorFeatureFeature(uc, log, regs):
    """IsProcessorFeaturePresent - 返回真"""
    set_register(regs)
    log.warning(f"HOOK_API_CALL : IsProcessorFeaturePresent, feature=0x{REGS.rcx:x}")
    uc.reg_write(UC_X86_REG_RAX, 0x1)
    ret(uc, REGS.rsp)

def hook_GetACP(uc, log, regs):
    """GetACP - 返回936 (Chinese GBK)"""
    set_register(regs)
    log.warning(f"HOOK_API_CALL : GetACP")
    uc.reg_write(UC_X86_REG_RAX, 936)
    ret(uc, REGS.rsp)

def hook_GetOEMCP(uc, log, regs):
    """GetOEMCP - 返回936"""
    set_register(regs)
    log.warning(f"HOOK_API_CALL : GetOEMCP")
    uc.reg_write(UC_X86_REG_RAX, 936)
    ret(uc, REGS.rsp)

def hook_TlsGetValue(uc, log, regs):
    """TlsGetValue - 返回0（无TLS值）"""
    set_register(regs)
    log.warning(f"HOOK_API_CALL : TlsGetValue, index=0x{REGS.rcx:x}")
    uc.reg_write(UC_X86_REG_RAX, 0x0)
    ret(uc, REGS.rsp)

def hook_TlsSetValue(uc, log, regs):
    """TlsSetValue - 返回成功"""
    set_register(regs)
    log.warning(f"HOOK_API_CALL : TlsSetValue")
    uc.reg_write(UC_X86_REG_RAX, 0x1)
    ret(uc, REGS.rsp)

def hook_EncodePointer(uc, log, regs):
    """EncodePointer - 无操作(返回原值)"""
    set_register(regs)
    log.warning(f"HOOK_API_CALL : EncodePointer")
    # Return the pointer unchanged
    uc.reg_write(UC_X86_REG_RAX, REGS.rcx)
    ret(uc, REGS.rsp)

def hook_DecodePointer(uc, log, regs):
    """DecodePointer - 无操作(返回原值)"""
    set_register(regs)
    log.warning(f"HOOK_API_CALL : DecodePointer")
    uc.reg_write(UC_X86_REG_RAX, REGS.rcx)
    ret(uc, REGS.rsp)

def hook_InitializeCriticalSection(uc, log, regs):
    """InitializeCriticalSection - 初始化临界区结构"""
    set_register(regs)
    log.warning(f"HOOK_API_CALL : InitializeCriticalSection, cs=0x{REGS.rcx:x}")
    if REGS.rcx:
        # Write minimal CRITICAL_SECTION structure
        uc.mem_write(REGS.rcx, struct.pack('<QQQii',
            0x0,          # DebugInfo (NULL)
            0x0,          # LockCount
            0xFFFFFFFFFFFFFFFF,  # RecursionCount (-1)
            0x0,          # SpinCount
            0x0,          # OwningThread
        ))
    ret(uc, REGS.rsp)

def hook_GetUserDefaultLCID(uc, log, regs):
    """GetUserDefaultLCID - 返回0x804 (Chinese)"""
    set_register(regs)
    log.warning(f"HOOK_API_CALL : GetUserDefaultLCID")
    uc.reg_write(UC_X86_REG_RAX, 0x804)
    ret(uc, REGS.rsp)

# ----- ntdll RtlGetVersion (helpers) -----

def hook_RtlGetVersion(uc, log, regs):
    """RtlGetVersion - 返回Windows 10 1903版本信息"""
    set_register(regs)
    log.warning(f"HOOK_API_CALL : RtlGetVersion, buffer=0x{REGS.rcx:x}")
    if REGS.rcx:
        # RTL_OSVERSIONINFOEXW structure
        # Write: dwOSVersionInfoSize, dwMajorVersion, dwMinorVersion, dwBuildNumber, dwPlatformId
        version_data = struct.pack('<IIIIII', 
            0x150,    # dwOSVersionInfoSize (sizeof RTL_OSVERSIONINFOEXW)
            0x000A,   # dwMajorVersion = 10
            0x0000,   # dwMinorVersion = 0
            0x3A98,   # dwBuildNumber = 15063 (Win10 1703) / could be 18362 (1903)
            0x0002,   # dwPlatformId = VER_PLATFORM_WIN32_NT
            0x0000,   # szCSDVersion[0] (empty)
        )
        uc.mem_write(REGS.rcx, version_data)
    uc.reg_write(UC_X86_REG_RAX, 0x0)  # STATUS_SUCCESS
    ret(uc, REGS.rsp)

# ----- kernelbase 独有钩子 (通过kernel32/kernelbase共享分发) -----
# 注意: hook系统通过函数名分发(去掉.dll_前缀)
# kernelbase.dll_GetSystemInfo → hook_GetSystemInfo(kernel32的同名handler)
# 以下为只有kernelbase有、kernel32没有的独有API

def hook_LCMapStringEx(uc, log, regs):
    """LCMapStringEx - 返回伪结果"""
    set_register(regs)
    log.warning(f"HOOK_API_CALL : LCMapStringEx")
    uc.reg_write(UC_X86_REG_RAX, REGS.r9)  # Return cchSrc as count
    ret(uc, REGS.rsp)

def hook_GetStringTypeW(uc, log, regs):
    """GetStringTypeW - 返回成功"""
    set_register(regs)
    log.warning(f"HOOK_API_CALL : GetStringTypeW")
    uc.reg_write(UC_X86_REG_RAX, 0x1)
    ret(uc, REGS.rsp)

def hook_FindResourceW(uc, log, regs):
    """FindResourceW - 返回NULL（资源不存在）"""
    set_register(regs)
    log.warning(f"HOOK_API_CALL : FindResourceW, "
                f"module=0x{REGS.rcx:x}, type=0x{REGS.rdx:x}, name=0x{REGS.r8:x}")
    uc.reg_write(UC_X86_REG_RAX, 0x0)
    ret(uc, REGS.rsp)

def hook_SizeofResource(uc, log, regs):
    """SizeofResource - 返回0"""
    set_register(regs)
    log.warning(f"HOOK_API_CALL : SizeofResource")
    uc.reg_write(UC_X86_REG_RAX, 0x0)
    ret(uc, REGS.rsp)

def hook_LoadResource(uc, log, regs):
    """LoadResource - 返回NULL"""
    set_register(regs)
    log.warning(f"HOOK_API_CALL : LoadResource")
    uc.reg_write(UC_X86_REG_RAX, 0x0)
    ret(uc, REGS.rsp)

# ----- Themidie2 兼容: 反调试补充 hook (84+) -----

def hook_FindWindowW(uc, log, regs):
    """FindWindowW - 返回NULL（未找到调试器窗口）"""
    set_register(regs)
    log.warning(f"HOOK_API_CALL : FindWindowW, class=0x{REGS.rcx:x}, title=0x{REGS.rdx:x}")
    uc.reg_write(UC_X86_REG_RAX, 0x0)
    ret(uc, REGS.rsp)

def hook_FindWindowA(uc, log, regs):
    """FindWindowA - 返回NULL"""
    set_register(regs)
    log.warning(f"HOOK_API_CALL : FindWindowA, class=0x{REGS.rcx:x}, title=0x{REGS.rdx:x}")
    uc.reg_write(UC_X86_REG_RAX, 0x0)
    ret(uc, REGS.rsp)

def hook_Process32NextW(uc, log, regs):
    """Process32NextW - 返回FALSE（枚举结束）"""
    set_register(regs)
    log.warning(f"HOOK_API_CALL : Process32NextW, handle=0x{REGS.rcx:x}")
    uc.reg_write(UC_X86_REG_RAX, 0x0)
    uc.reg_write(UC_X86_REG_ERR, 0x12)  # ERROR_NO_MORE_FILES
    ret(uc, REGS.rsp)

def hook_RegOpenKeyExW(uc, log, regs):
    """RegOpenKeyExW - 返回ERROR_FILE_NOT_FOUND"""
    set_register(regs)
    log.warning(f"HOOK_API_CALL : RegOpenKeyExW, key=0x{REGS.rcx:x}, subkey=0x{REGS.rdx:x}")
    uc.reg_write(UC_X86_REG_RAX, 0x2)  # ERROR_FILE_NOT_FOUND
    ret(uc, REGS.rsp)

def hook_RegQueryValueExW(uc, log, regs):
    """RegQueryValueExW - 返回ERROR_FILE_NOT_FOUND"""
    set_register(regs)
    log.warning(f"HOOK_API_CALL : RegQueryValueExW, key=0x{REGS.rcx:x}, value=0x{REGS.rdx:x}")
    uc.reg_write(UC_X86_REG_RAX, 0x2)  # ERROR_FILE_NOT_FOUND
    ret(uc, REGS.rsp)

def hook_LoadLibraryExW(uc, log, regs):
    """LoadLibraryExW - 模拟LoadLibraryA行为"""
    set_register(regs)
    log.warning(f"HOOK_API_CALL : LoadLibraryExW, path=0x{REGS.rcx:x}, flags=0x{REGS.r8:x}")
    if REGS.rcx:
        try:
            name = bytes(uc.mem_read(REGS.rcx, 260)).split(b'\x00')[0].decode('utf-16-le', errors='ignore')
            log.warning(f"  DLL name: {name}")
        except:
            pass
    # Return NULL to let callers handle
    uc.reg_write(UC_X86_REG_RAX, 0x0)
    ret(uc, REGS.rsp)

def hook_FindFirstFileExW(uc, log, regs):
    """FindFirstFileExW - 返回INVALID_HANDLE_VALUE"""
    set_register(regs)
    log.warning(f"HOOK_API_CALL : FindFirstFileExW, path=0x{REGS.rcx:x}")
    uc.reg_write(UC_X86_REG_RAX, -1)  # INVALID_HANDLE_VALUE
    ret(uc, REGS.rsp)

def hook_SHGetFileInfoA(uc, log, regs):
    """SHGetFileInfoA - 返回0"""
    set_register(regs)
    log.warning(f"HOOK_API_CALL : SHGetFileInfoA")
    uc.reg_write(UC_X86_REG_RAX, 0x0)
    ret(uc, REGS.rsp)

def hook_SHGetFileInfoW(uc, log, regs):
    """SHGetFileInfoW - 返回0"""
    set_register(regs)
    log.warning(f"HOOK_API_CALL : SHGetFileInfoW")
    uc.reg_write(UC_X86_REG_RAX, 0x0)
    ret(uc, REGS.rsp)

def hook_ExtractIconW(uc, log, regs):
    """ExtractIconW - 返回NULL"""
    set_register(regs)
    log.warning(f"HOOK_API_CALL : ExtractIconW")
    uc.reg_write(UC_X86_REG_RAX, 0x0)
    ret(uc, REGS.rsp)

def hook_ExtractIconExW(uc, log, regs):
    """ExtractIconExW - 返回0"""
    set_register(regs)
    log.warning(f"HOOK_API_CALL : ExtractIconExW")
    uc.reg_write(UC_X86_REG_RAX, 0x0)
    ret(uc, REGS.rsp)