# simple_hook_checker.py - Fixed version
import ctypes

def check_hook():
    user32 = ctypes.WinDLL('user32')
    addr = ctypes.cast(user32.MessageBoxA, ctypes.c_void_p).value
    
    print(f"MessageBoxA address: 0x{addr:x}")
    
    # Read first 5 bytes
    kernel32 = ctypes.WinDLL('kernel32')
    buffer = ctypes.create_string_buffer(5)
    bytes_read = ctypes.c_size_t()
    
    # Use ctypes.c_void_p for address
    result = kernel32.ReadProcessMemory(
        ctypes.c_void_p(-1),  # HANDLE
        ctypes.c_void_p(addr),  # address
        buffer,  # buffer
        5,  # size
        ctypes.byref(bytes_read)  # bytes read
    )
    
    print(f"First 5 bytes: {buffer.raw.hex()}")
    
    if buffer.raw[0] == 0xE9:
        print("\n" + "="*50)
        print("⚠️ HOOK DETECTED! First byte is 0xE9 (JMP)")
        print("="*50)
        return True
    else:
        print("\n✓ No hook detected")
        return False

if __name__ == "__main__":
    check_hook()