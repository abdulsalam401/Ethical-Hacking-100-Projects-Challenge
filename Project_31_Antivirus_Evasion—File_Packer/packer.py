# #!/usr/bin/env python3
# """
# PROJECT #31 — File Packer (Educational) - FIXED TEMPLATE
# """

# import os
# import sys
# import base64
# from cryptography.fernet import Fernet

# IS_LINUX = sys.platform.startswith('linux')

# class FilePacker:
#     def __init__(self, input_file, output_file=None):
#         self.input_file = input_file
#         self.output_file = output_file or f"packed_{os.path.basename(input_file)}.py"
        
#     def encrypt_file(self):
#         print(f"[*] Reading: {self.input_file}")
#         with open(self.input_file, 'rb') as f:
#             data = f.read()
#         print(f"[*] Size: {len(data)} bytes")
        
#         # Generate Fernet key and encrypt the binary payload
#         key = Fernet.generate_key()
#         fernet = Fernet(key)
#         encrypted = fernet.encrypt(data)
        
#         print(f"[+] Encrypted: {len(encrypted)} bytes")
#         return key, encrypted
    
#     def generate_stub(self, key, encrypted_data):
#         # Convert binary segments to base64 strings for stable script embedding
#         key_b64 = base64.b64encode(key).decode()
#         data_b64 = base64.b64encode(encrypted_data).decode()
        
#         # Raw template string - no outer f-string to prevent brace corruption
#         template = '''#!/usr/bin/env python3
# import os
# import sys
# import base64
# import tempfile
# import subprocess
# from cryptography.fernet import Fernet

# def check_debug():
#     if sys.platform.startswith('win'):
#         try:
#             import ctypes
#             if ctypes.windll.kernel32.IsDebuggerPresent():
#                 print("[!] Debugger detected via kernel32!")
#                 sys.exit(1)
#         except: 
#             pass
#     if sys.platform.startswith('linux'):
#         try:
#             res = subprocess.run(['ps', 'aux'], capture_output=True, text=True)
#             for tool in ['gdb', 'lldb', 'strace', 'ltrace', 'valgrind']:
#                 if tool in res.stdout:
#                     print(f"[!] Analysis tool '{tool}' detected active in process tree!")
#                     sys.exit(1)
#         except: 
#             pass

# # Run environmental checks
# check_debug()

# try:
#     # Decode embedded transmission layers
#     key = base64.b64decode("{{KEY_PLACEHOLDER}}")
#     data = base64.b64decode("{{DATA_PLACEHOLDER}}")
    
#     fernet = Fernet(key)
#     decrypted = fernet.decrypt(data)
    
#     # Establish operational target workspace platform suffix
#     suffix = '.exe' if sys.platform.startswith('win') else '.elf'
    
#     # Generate temporary execution marker file descriptor safely
#     with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as tmp_file:
#         tmp_file.write(decrypted)
#         tmp_path = tmp_file.name
    
#     if sys.platform.startswith('linux'):
#         os.chmod(tmp_path, 0o755)
    
#     # Execute the underlying compiled asset binary application
#     subprocess.run([tmp_path], check=True)
    
#     # Clean up file space immediately post-execution
#     os.unlink(tmp_path)
    
# except Exception as error:
#     print("[-] Runtime Extraction Error: " + str(error))
#     sys.exit(1)
# '''
#         # Perform clean textual replacements
#         stub = template.replace("{{KEY_PLACEHOLDER}}", key_b64)
#         stub = template.replace("{{DATA_PLACEHOLDER}}", data_b64)
#         return stub
    
#     def pack(self):
#         print("\n" + "="*60)
#         print("   PROJECT #31 — Structural File Wrapper")
#         print("="*60 + "\n")
#         print("⚠️  ETHICAL WARNING: Only use on your own files.\n")
        
#         if not os.path.exists(self.input_file):
#             print(f"[-] Target payload entry not located: {self.input_file}")
#             return False
        
#         key, encrypted = self.encrypt_file()
#         stub = self.generate_stub(key, encrypted)
        
#         with open(self.output_file, 'w') as f:
#             f.write(stub)
        
#         if IS_LINUX:
#             os.chmod(self.output_file, 0o755)
        
#         print(f"\n[+] Script mapping completed successfully: {self.output_file}")
#         print(f"[+] Run: python3 {self.output_file}")
#         return True

# def main():
#     import argparse
#     parser = argparse.ArgumentParser(description="Educational Data Archive Wrapper")
#     parser.add_argument("--input", required=True, help="Path to input executable or script")
#     parser.add_argument("--output", help="Path to output python wrapper script")
#     args = parser.parse_args()
    
#     packer = FilePacker(args.input, args.output)
#     packer.pack()

# if __name__ == "__main__":
#     main()



#!/usr/bin/env python3
"""
PROJECT #31 — File Packer (Educational) - SIMPLIFIED
"""

import os
import sys
import random
import string
import subprocess
import tempfile
import base64
from cryptography.fernet import Fernet

IS_WINDOWS = sys.platform.startswith('win')
IS_LINUX = sys.platform.startswith('linux')

class FilePacker:
    def __init__(self, input_file, output_file=None):
        self.input_file = input_file
        self.output_file = output_file or f"packed_{os.path.basename(input_file)}.py"
        
    def encrypt_file(self):
        print(f"[*] Reading: {self.input_file}")
        with open(self.input_file, 'rb') as f:
            data = f.read()
        print(f"[*] Size: {len(data)} bytes")
        
        # Generate key
        key = Fernet.generate_key()
        fernet = Fernet(key)
        encrypted = fernet.encrypt(data)
        
        print(f"[+] Encrypted: {len(encrypted)} bytes")
        return key, encrypted
    
    def generate_stub(self, key, encrypted_data):
        # Convert to base64 for easier embedding
        key_b64 = base64.b64encode(key).decode()
        data_b64 = base64.b64encode(encrypted_data).decode()
        
        stub = f'''#!/usr/bin/env python3
import os, sys, base64, tempfile, subprocess
from cryptography.fernet import Fernet

# Anti-debugging
def check_debug():
    if sys.platform.startswith('win'):
        try:
            import ctypes
            if ctypes.windll.kernel32.IsDebuggerPresent():
                print("[!] Debugger detected!")
                sys.exit(1)
        except: pass
    if sys.platform.startswith('linux'):
        try:
            import subprocess
            r = subprocess.run(['ps', 'aux'], capture_output=True, text=True)
            for d in ['gdb','lldb','strace','ltrace','valgrind']:
                if d in r.stdout:
                    print(f"[!] {{d}} detected!")
                    sys.exit(1)
        except: pass
check_debug()

try:
    key = base64.b64decode("{key_b64}")
    data = base64.b64decode("{data_b64}")
    
    fernet = Fernet(key)
    decrypted = fernet.decrypt(data)
    
    suffix = '.exe' if sys.platform.startswith('win') else '.elf'
    tmp = tempfile.mktemp(suffix=suffix)
    with open(tmp, 'wb') as f:
        f.write(decrypted)
    
    if sys.platform.startswith('linux'):
        os.chmod(tmp, 0o755)
    
    subprocess.run([tmp], check=True)
    os.unlink(tmp)
    
except Exception as e:
    print(f"[-] Error: {{e}}")
    sys.exit(1)
'''
        return stub
    
    def pack(self):
        print("\n" + "="*60)
        print("  PROJECT #31 — File Packer")
        print("="*60 + "\n")
        print("⚠️  ETHICAL WARNING: Only use on your own files.\n")
        
        if not os.path.exists(self.input_file):
            print(f"[-] Not found: {self.input_file}")
            return False
        
        key, encrypted = self.encrypt_file()
        stub = self.generate_stub(key, encrypted)
        
        with open(self.output_file, 'w') as f:
            f.write(stub)
        
        if IS_LINUX:
            os.chmod(self.output_file, 0o755)
        
        print(f"\n[+] Packed: {self.output_file}")
        print(f"[+] Run: python3 {self.output_file}")
        return True

def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    parser.add_argument("--output")
    args = parser.parse_args()
    
    packer = FilePacker(args.input, args.output)
    packer.pack()

if __name__ == "__main__":
    main()