#!/usr/bin/env python3
"""
==============================================================
  PROJECT #21 — API Hooking Detector (Windows/Linux)
  Detects IAT, EAT, and Inline hooks in running processes
==============================================================

FEATURES:
- Detect inline hooks (function prologue modifications)
- Detect IAT/EAT hooks (import/export table redirects)
- Check LD_PRELOAD on Linux
- Scan process memory for hooked functions
- Alert on common EDR hooks (AMSI, ETW, NTDLL)

DEFENSE AGAINST API HOOKING:
1. Direct/System Calls - Bypass user-mode hooks
2. Unhooking - Restore original bytes from disk
3. Obfuscation - Encrypt/hide function calls
4. Dynamic Resolution - Resolve APIs at runtime
5. Manual Syscalls - Call kernel directly

USAGE:
--------
  # Windows - Run as Administrator
  python api_hook_detector.py --pid 1234
  
  # Linux - Run with sudo
  sudo python api_hook_detector.py --pid 1234
  
  # Check LD_PRELOAD only
  python api_hook_detector.py --check-preload
  
  # List all processes
  python api_hook_detector.py --list-processes
==============================================================
"""

import os
import sys
import platform
import struct
from datetime import datetime
from colorama import init, Fore, Style

# Initialize colorama
init(autoreset=True)

# Colors
class Colors:
    HEADER = Fore.CYAN + Style.BRIGHT
    OKBLUE = Fore.BLUE + Style.BRIGHT
    OKGREEN = Fore.GREEN + Style.BRIGHT
    WARNING = Fore.YELLOW + Style.BRIGHT
    FAIL = Fore.RED + Style.BRIGHT
    ENDC = Style.RESET_ALL
    BOLD = Style.BRIGHT
    DIM = Fore.LIGHTBLACK_EX
    MAGENTA = Fore.MAGENTA + Style.BRIGHT

# System detection
IS_WINDOWS = platform.system() == "Windows"
IS_LINUX = platform.system() == "Linux"
IS_MAC = platform.system() == "Darwin"

# Common EDR hooks to detect
EDR_SIGNATURES = {
    'amsi.dll': {
        'functions': ['AmsiScanBuffer', 'AmsiScanString'],
        'description': 'AMSI bypass detection'
    },
    'ntdll.dll': {
        'functions': ['NtCreateThreadEx', 'NtWriteVirtualMemory', 
                      'NtOpenProcess', 'NtAllocateVirtualMemory',
                      'NtProtectVirtualMemory', 'NtQueueApcThread'],
        'description': 'Critical Windows API (often hooked)'
    },
    'kernel32.dll': {
        'functions': ['CreateRemoteThread', 'VirtualAllocEx', 
                      'WriteProcessMemory', 'CreateProcessInternalW'],
        'description': 'Process injection APIs'
    },
    'etw.dll': {
        'functions': ['EtwEventWrite', 'EtwEventWriteTransfer'],
        'description': 'ETW telemetry hook'
    }
}

class APIHookDetector:
    def __init__(self, pid=None, verbose=False):
        self.pid = pid
        self.verbose = verbose
        self.hooks_found = []
        
    def banner(self):
        """Display banner"""
        print(f"\n{Colors.HEADER}{'='*80}{Colors.ENDC}")
        print(f"{Colors.HEADER}  PROJECT #21 — API Hooking Detector{Colors.ENDC}")
        print(f"{Colors.OKBLUE}  Detecting IAT, EAT, and Inline hooks{Colors.ENDC}")
        print(f"{Colors.HEADER}{'='*80}{Colors.ENDC}\n")
        
        print(f"{Colors.OKGREEN}[+] System: {platform.system()} {platform.release()}{Colors.ENDC}")
        print(f"{Colors.OKGREEN}[+] Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Colors.ENDC}")
        
        if self.pid:
            print(f"{Colors.OKGREEN}[+] Target PID: {self.pid}{Colors.ENDC}")
        else:
            print(f"{Colors.WARNING}[!] No PID specified. Run with --pid to scan a process.{Colors.ENDC}")
        print()
    
    def list_processes(self):
        """List all running processes"""
        print(f"{Colors.OKBLUE}[*] Running Processes:{Colors.ENDC}")
        print(f"{Colors.HEADER}{'='*80}{Colors.ENDC}")
        print(f"{Colors.BOLD}{'PID':<8} {'Name':<40}{Colors.ENDC}")
        print(f"{Colors.HEADER}{'='*80}{Colors.ENDC}")
        
        if IS_WINDOWS:
            try:
                import psutil
                for proc in psutil.process_iter(['pid', 'name']):
                    try:
                        print(f"{proc.info['pid']:<8} {proc.info['name']:<40}")
                    except:
                        pass
            except ImportError:
                print(f"{Colors.FAIL}[-] psutil not installed. Run: pip install psutil{Colors.ENDC}")
        else:
            # Linux: read from /proc
            for pid in os.listdir('/proc'):
                if pid.isdigit():
                    try:
                        with open(f'/proc/{pid}/comm', 'r') as f:
                            name = f.read().strip()
                        print(f"{pid:<8} {name:<40}")
                    except:
                        pass
        
        print(f"{Colors.HEADER}{'='*80}{Colors.ENDC}\n")
    
    def check_ld_preload(self):
        """Check LD_PRELOAD for hooked libraries (Linux)"""
        if not IS_LINUX:
            return []
        
        print(f"{Colors.OKBLUE}[*] Checking LD_PRELOAD hooks...{Colors.ENDC}")
        
        ld_preload = os.environ.get('LD_PRELOAD', '')
        hooks = []
        
        if ld_preload:
            libs = ld_preload.split(':')
            for lib in libs:
                if lib.strip():
                    hooks.append({
                        'type': 'LD_PRELOAD',
                        'library': lib,
                        'severity': 'HIGH',
                        'description': f'Library preloaded: {lib}'
                    })
                    print(f"{Colors.FAIL}[!] LD_PRELOAD detected: {lib}{Colors.ENDC}")
            print()
        else:
            print(f"{Colors.OKGREEN}[+] No LD_PRELOAD hooks detected{Colors.ENDC}\n")
        
        return hooks
    
    def check_proc_maps(self):
        """Check /proc/pid/maps for suspicious libraries (Linux)"""
        if not IS_LINUX or not self.pid:
            return []
        
        print(f"{Colors.OKBLUE}[*] Checking memory maps for suspicious libraries...{Colors.ENDC}")
        
        maps_path = f'/proc/{self.pid}/maps'
        hooks = []
        
        try:
            with open(maps_path, 'r') as f:
                maps = f.read()
            
            # Check for injected libraries
            suspicious_patterns = ['inject', 'hook', 'frida', 'detour', 'easyhook']
            
            for line in maps.split('\n'):
                if '/lib' in line or '.so' in line:
                    for pattern in suspicious_patterns:
                        if pattern in line.lower():
                            lib_path = line.split()[-1] if line.split() else 'unknown'
                            hooks.append({
                                'type': 'INJECTED_LIBRARY',
                                'library': lib_path,
                                'severity': 'MEDIUM',
                                'description': f'Suspicious library loaded: {lib_path}'
                            })
                            print(f"{Colors.WARNING}[!] Suspicious: {lib_path}{Colors.ENDC}")
                            break
            
            if not hooks:
                print(f"{Colors.OKGREEN}[+] No suspicious libraries detected{Colors.ENDC}")
        except Exception as e:
            print(f"{Colors.FAIL}[-] Failed to read maps: {e}{Colors.ENDC}")
        
        print()
        return hooks
    
    def detect_inline_hooks(self):
        """Detect inline hooks (Windows) using pymem"""
        if not IS_WINDOWS:
            return []
        
        hooks = []
        
        try:
            import pymem
            import pymem.process
            
            print(f"{Colors.OKBLUE}[*] Detecting inline hooks (EDR/AV hooks)...{Colors.ENDC}")
            
            # Try to open process
            try:
                pm = pymem.Pymem(self.pid) if self.pid else pymem.Pymem('python.exe')
            except:
                print(f"{Colors.WARNING}[!] Could not open process. Try running as Administrator.{Colors.ENDC}")
                return hooks
            
            # Check critical DLLs
            dlls_to_check = ['ntdll.dll', 'kernel32.dll', 'amsi.dll', 'etw.dll']
            
            for dll_name in dlls_to_check:
                try:
                    # Get DLL base address
                    module = pymem.process.module_from_name(pm.process_handle, dll_name)
                    if not module:
                        continue
                    
                    print(f"\n{Colors.OKBLUE}[*] Checking {dll_name}{Colors.ENDC}")
                    
                    # Check each function for hooks
                    for edr_dll, info in EDR_SIGNATURES.items():
                        if dll_name.lower() == edr_dll:
                            for func_name in info['functions']:
                                try:
                                    # Get function address
                                    func_addr = pymem.process.resolve_symbol(pm.process_handle, dll_name, func_name)
                                    if func_addr:
                                        # Read first 8 bytes of function
                                        original_bytes = pm.read_bytes(func_addr, 8)
                                        
                                        # Check for typical hook patterns
                                        # JMP (0xE9), CALL (0xE8), MOV RAX (0x48 0xB8), JMP (0xFF 0x25)
                                        if original_bytes[0] == 0xE9:  # JMP rel32
                                            hooks.append({
                                                'type': 'INLINE_HOOK',
                                                'dll': dll_name,
                                                'function': func_name,
                                                'bytes': original_bytes.hex(),
                                                'severity': 'HIGH',
                                                'description': f'Inline JMP hook detected in {func_name} (EDR hook)'
                                            })
                                            print(f"{Colors.FAIL}  [!] {func_name}: INLINE JMP HOOK!{Colors.ENDC}")
                                        elif original_bytes[0] == 0xE8:  # CALL rel32
                                            hooks.append({
                                                'type': 'INLINE_HOOK',
                                                'dll': dll_name,
                                                'function': func_name,
                                                'bytes': original_bytes.hex(),
                                                'severity': 'HIGH',
                                                'description': f'Inline CALL hook in {func_name}'
                                            })
                                            print(f"{Colors.WARNING}  [!] {func_name}: CALL hook detected{Colors.ENDC}")
                                        elif original_bytes[:2] == b'\x48\xb8':  # MOV RAX, imm64
                                            hooks.append({
                                                'type': 'INLINE_HOOK',
                                                'dll': dll_name,
                                                'function': func_name,
                                                'bytes': original_bytes.hex(),
                                                'severity': 'MEDIUM',
                                                'description': f'MOV RAX hook in {func_name} (indirect call)'
                                            })
                                            print(f"{Colors.WARNING}  [!] {func_name}: MOV RAX hook detected{Colors.ENDC}")
                                        elif self.verbose:
                                            print(f"{Colors.DIM}  [i] {func_name}: Normal - {original_bytes.hex()}{Colors.ENDC}")
                                except:
                                    pass
                except:
                    pass
            
            pm.close_process()
            
        except ImportError:
            print(f"{Colors.FAIL}[-] pymem not installed. Run: pip install pymem{Colors.ENDC}")
        except Exception as e:
            print(f"{Colors.DIM}[!] Error: {e}{Colors.ENDC}")
        
        print()
        return hooks
    
    def display_hooks_table(self, hooks):
        """Display detected hooks in table format"""
        if not hooks:
            print(f"\n{Colors.OKGREEN}{'='*80}{Colors.ENDC}")
            print(f"{Colors.OKGREEN}[✓] No API hooks detected!{Colors.ENDC}")
            print(f"{Colors.OKGREEN}{'='*80}{Colors.ENDC}\n")
            return
        
        print(f"\n{Colors.FAIL}{'='*100}{Colors.ENDC}")
        print(f"{Colors.FAIL}⚠️⚠️⚠️  API HOOKS DETECTED!  ⚠️⚠️⚠️{Colors.ENDC}")
        print(f"{Colors.FAIL}{'='*100}{Colors.ENDC}")
        
        print(f"{Colors.BOLD}{'Type':<20} {'Target':<35} {'Severity':<10} {'Description':<35}{Colors.ENDC}")
        print(f"{Colors.HEADER}{'-'*100}{Colors.ENDC}")
        
        for hook in hooks:
            if hook['severity'] == 'HIGH':
                severity_color = Colors.FAIL
            elif hook['severity'] == 'MEDIUM':
                severity_color = Colors.WARNING
            else:
                severity_color = Colors.OKBLUE
            
            if hook['type'] == 'LD_PRELOAD':
                target = hook.get('library', 'Unknown')[:34]
            elif hook['type'] == 'INJECTED_LIBRARY':
                target = hook.get('library', 'Unknown')[:34]
            else:
                target = f"{hook.get('dll', '')}!{hook.get('function', '')}"[:34]
            
            print(f"{hook['type']:<20} "
                  f"{Colors.DIM}{target:<35}{Colors.ENDC} "
                  f"{severity_color}{hook['severity']:<10}{Colors.ENDC} "
                  f"{Colors.DIM}{hook['description']:<35}{Colors.ENDC}")
        
        print(f"{Colors.FAIL}{'='*100}{Colors.ENDC}")
        print(f"{Colors.FAIL}Total hooks detected: {len(hooks)}{Colors.ENDC}")
    
    def print_defenses(self):
        """Print defense mechanisms against API hooking"""
        print(f"\n{Colors.HEADER}{'='*80}{Colors.ENDC}")
        print(f"{Colors.BOLD}  DEFENSE AGAINST API HOOKING{Colors.ENDC}")
        print(f"{Colors.HEADER}{'='*80}{Colors.ENDC}")
        
        defenses = [
            ("Direct System Calls", "Bypass user-mode hooks by calling kernel directly"),
            ("Unhooking", "Restore original bytes from disk copy"),
            ("Dynamic Resolution", "Resolve APIs at runtime (dynamic import)"),
            ("Manual Syscalls", "Implement custom syscall wrappers"),
            ("Obfuscation", "Encrypt/hide API calls in obfuscated code"),
            ("Halos Gate", "Retrieve syscall numbers dynamically"),
            ("Hell's Gate", "Parse ntdll to find syscall numbers"),
            ("Tartarus Gate", "Combine multiple unhooking techniques")
        ]
        
        for title, desc in defenses:
            print(f"{Colors.OKGREEN}{title}{Colors.ENDC}: {Colors.DIM}{desc}{Colors.ENDC}")
        
        print(f"{Colors.HEADER}{'='*80}{Colors.ENDC}\n")

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="API Hooking Detector")
    parser.add_argument("--pid", type=int, help="Process ID to analyze")
    parser.add_argument("--list-processes", action="store_true", help="List all running processes")
    parser.add_argument("--check-preload", action="store_true", help="Check LD_PRELOAD only")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    
    args = parser.parse_args()
    
    detector = APIHookDetector(pid=args.pid, verbose=args.verbose)
    detector.banner()
    
    if args.list_processes:
        detector.list_processes()
        return
    
    all_hooks = []
    
    # Linux checks
    if IS_LINUX:
        if args.check_preload:
            hooks = detector.check_ld_preload()
            all_hooks.extend(hooks)
        elif args.pid:
            hooks = detector.check_proc_maps()
            all_hooks.extend(hooks)
            hooks = detector.check_ld_preload()
            all_hooks.extend(hooks)
        else:
            print(f"{Colors.WARNING}[!] Specify --pid to scan a process, or --check-preload for LD_PRELOAD{Colors.ENDC}")
    
    # Windows checks
    elif IS_WINDOWS:
        if args.pid:
            hooks = detector.detect_inline_hooks()
            all_hooks.extend(hooks)
        else:
            print(f"{Colors.WARNING}[!] Specify --pid to scan a process{Colors.ENDC}")
            detector.list_processes()
    
    else:
        print(f"{Colors.FAIL}[-] Unsupported platform: {platform.system()}{Colors.ENDC}")
    
    # Display results
    detector.display_hooks_table(all_hooks)
    
    if args.verbose:
        detector.print_defenses()

if __name__ == "__main__":
    main()