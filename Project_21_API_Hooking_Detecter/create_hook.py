# create_hook.py - Simple working hook
import ctypes
import ctypes.wintypes

def create_hook():
    try:
        # Get MessageBoxA address
        user32 = ctypes.WinDLL('user32')
        addr = ctypes.cast(user32.MessageBoxA, ctypes.c_void_p).value
        print(f"[+] MessageBoxA address: 0x{addr:x}")
        
        # Read original first 8 bytes
        kernel32 = ctypes.WinDLL('kernel32')
        buffer = ctypes.create_string_buffer(8)
        bytes_read = ctypes.c_size_t()
        
        kernel32.ReadProcessMemory(ctypes.c_void_p(-1), ctypes.c_void_p(addr), 
                                    buffer, 8, ctypes.byref(bytes_read))
        print(f"[+] Original bytes: {buffer.raw.hex()}")
        
        # Change memory protection to allow writing
        old_protect = ctypes.c_ulong()
        kernel32.VirtualProtectEx(ctypes.c_void_p(-1), ctypes.c_void_p(addr), 5, 
                                  0x40, ctypes.byref(old_protect))
        
        # Write JMP instruction (0xE9) - creates a hook
        # For testing, we just change first byte to 0xE9
        hook_byte = b'\xE9'
        bytes_written = ctypes.c_size_t()
        kernel32.WriteProcessMemory(ctypes.c_void_p(-1), ctypes.c_void_p(addr), 
                                     hook_byte, 1, ctypes.byref(bytes_written))
        
        # Restore protection
        kernel32.VirtualProtectEx(ctypes.c_void_p(-1), ctypes.c_void_p(addr), 5, 
                                  old_protect, ctypes.byref(old_protect))
        
        print("[!] HOOK INSTALLED! First byte changed to 0xE9 (JMP)")
        print("[!] Run the API hook detector now!")
        
        return addr, buffer.raw
        
    except Exception as e:
        print(f"[-] Error: {e}")
        return None, None

def restore_hook(addr, original_bytes):
    try:
        kernel32 = ctypes.WinDLL('kernel32')
        
        # Change protection
        old_protect = ctypes.c_ulong()
        kernel32.VirtualProtectEx(ctypes.c_void_p(-1), ctypes.c_void_p(addr), 8, 
                                  0x40, ctypes.byref(old_protect))
        
        # Restore original bytes
        bytes_written = ctypes.c_size_t()
        kernel32.WriteProcessMemory(ctypes.c_void_p(-1), ctypes.c_void_p(addr), 
                                     original_bytes, len(original_bytes), ctypes.byref(bytes_written))
        
        # Restore protection
        kernel32.VirtualProtectEx(ctypes.c_void_p(-1), ctypes.c_void_p(addr), 8, 
                                  old_protect, ctypes.byref(old_protect))
        
        print("[+] Hook removed! Original bytes restored")
        
    except Exception as e:
        print(f"[-] Error restoring: {e}")

if __name__ == "__main__":
    print("\n" + "="*50)
    print("  API HOOK CREATOR")
    print("="*50 + "\n")
    
    addr, original = create_hook()
    
    if addr:
        print(f"\n[!] Hook active on MessageBoxA")
        input("\nPress Enter to remove hook...")
        restore_hook(addr, original)