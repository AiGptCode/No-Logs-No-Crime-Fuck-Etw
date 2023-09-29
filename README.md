## NO LOGS NO CRIME ! 
 
# 「⚙️」python version Bypass ETW & Ntdll Unhooking
Bypass the Event Trace Windows(ETW) and unhook ntdll.

```
         _______           _______  _        _______ _________
        (  ____ \|\     /|(  ____ \| \    /\(  ____ \\__   __/|\     /|
        | (    \/| )   ( || (    \/|  \  / /| (    \/   ) (   | )   ( |
        | (__    | |   | || |      |  (_/ / | (__       | |   | | _ | |
        |  __)   | |   | || |      |   _ (  |  __)      | |   | |( )| |
        | (      | |   | || |      |  ( \ \ | (         | |   | || || |
        | )      | (___) || (____/\|  /  \ \| (____/\   | |   | () () |
        |/       (_______)(_______/|_/    \/(_______/   )_(   (_______)

                                
                                        [v1.0]



[i] Hooked Ntdll Base Address : 0x00007FFA9A110000
[i] Unhooked Ntdll Base Address: 0x00007FF7C970F000

[+] PID Of The Current Proccess: [1956]

[#] Ready For ETW Patch.
[+] Press <Enter> To Patch ETW ...


[+] ETW Patched, No Logs No Crime !
```


1. Displays a banner and initializes variables.
2. Opens the ntdll.dll file using `CreateFileA`.
3. Creates a file mapping using `CreateFileMappingA` with the `PAGE_READONLY` and `SEC_IMAGE` flags.
4. Maps the file into memory using `MapViewOfFile`.
5. Calls the `UnhookNTDLL` function to unhook the Ntdll.dll library.
6. Displays the address of the unhooked Ntdll base.
7. Cleans up the mapped file and handles.
8. Displays the current process ID and waits for user input.
9. Calls the `FuckEtw` function to patch the ETW.
10. Displays a message indicating that the ETW has been patched.


