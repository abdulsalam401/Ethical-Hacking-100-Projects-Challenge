#!/usr/bin/env python3
"""
==============================================================
  PROJECT #21 — API Hooking Detector (Enhanced)
  Automatically scans all running processes for hooks
==============================================================
"""

import os
import sys
import platform
import struct
from datetime import datetime
from colorama import init, Fore, Style
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

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

IS_WINDOWS = platform.system() == "Windows"
IS_LINUX = platform.system() == "Linux"

# Critical processes to check (most relevant for hook detection)
CRITICAL_PROCESSES = [
    'explorer.exe', 'svchost.exe', 'lsass.exe', 'winlogon.exe',
    'services.exe', 'csrss.exe', 'wininit.exe', 'spoolsv.exe',
    'chrome.exe', 'firefox.exe', 'msedge.exe', 'powershell.exe',
    'cmd.exe', 'notepad.exe', 'Code.exe'
]

# Functions to check for hooks
FUNCTIONS_TO_CHECK = [
    'NtCreateThreadEx', 'NtWriteVirtualMemory', 'NtOpenProcess',
    'NtAllocateVirtualMemory', 'NtProtectVirtualMemory', 'NtQueueApcThread',
    'CreateRemoteThread', 'VirtualAllocEx', 'WriteProcessMemory',
    'CreateProcessInternalW', 'AmsiScanBuffer', 'AmsiScanString'
]

class EnhancedHookDetector:
    def __init__(self, verbose=False):
        self.verbose = verbose
        self.all_hooks = []
        self.scanned_processes = 0
        
    def banner(self):
        print(f"\n{Colors.HEADER}{'='*80}{Colors.ENDC}")
        print(f"{Colors.HEADER}  PROJECT #21 — API Hooking Detector (Auto-Scan){Colors.ENDC}")
        print(f"{Colors.OKBLUE}  Automatically scanning all processes for API hooks{Colors.ENDC}")
        print(f"{Colors.HEADER}{'='*80}{Colors.ENDC}\n")
        
        print(f"{Colors.OKGREEN}[+] System: {platform.system()} {platform.release()}{Colors.ENDC}")
        print(f"{Colors.OKGREEN}[+] Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Colors.ENDC}")
        print(f"{Colors.WARNING}[!] Note: Run as Administrator for full access{Colors.ENDC}\n")
    
    def get_all_processes(self):
        """Get list of all running processes"""
        processes = []
        try:
            import psutil
            for proc in psutil.process_iter(['pid', 'name']):
                try:
                    processes.append({
                        'pid': proc.info['pid'],
                        'name': proc.info['name'].lower() if proc.info['name'] else 'unknown'
                    })
                except:
                    pass
        except ImportError:
            print(f"{Colors.FAIL}[-] psutil not installed. Run: pip install psutil{Colors.ENDC}")
            sys.exit(1)
        return processes
    
    def detect_hooks_in_process(self, pid, process_name):
        """Detect hooks in a single process"""
        hooks = []
        
        try:
            import pymem
            import pymem.process
            
            # Try to open process
            try:
                pm = pymem.Pymem(pid)
            except:
                return hooks  # Can't open process (access denied or doesn't exist)
            
            # Check critical DLLs
            dlls_to_check = ['ntdll.dll', 'kernel32.dll', 'amsi.dll', 'etw.dll']
            
            for dll_name in dlls_to_check:
                try:
                    module = pymem.process.module_from_name(pm.process_handle, dll_name)
                    if not module:
                        continue
                    
                    # Check each function
                    for func_name in FUNCTIONS_TO_CHECK:
                        try:
                            func_addr = pymem.process.resolve_symbol(pm.process_handle, dll_name, func_name)
                            if func_addr:
                                # Read first 8 bytes of function
                                original_bytes = pm.read_bytes(func_addr, 8)
                                
                                # Check for hook patterns
                                if original_bytes[0] == 0xE9:  # JMP
                                    hooks.append({
                                        'pid': pid,
                                        'process': process_name,
                                        'dll': dll_name,
                                        'function': func_name,
                                        'hook_type': 'INLINE_JMP',
                                        'bytes': original_bytes.hex(),
                                        'severity': 'HIGH'
                                    })
                                elif original_bytes[0] == 0xE8:  # CALL
                                    hooks.append({
                                        'pid': pid,
                                        'process': process_name,
                                        'dll': dll_name,
                                        'function': func_name,
                                        'hook_type': 'INLINE_CALL',
                                        'bytes': original_bytes.hex(),
                                        'severity': 'HIGH'
                                    })
                                elif original_bytes[:2] == b'\x48\xb8':  # MOV RAX
                                    hooks.append({
                                        'pid': pid,
                                        'process': process_name,
                                        'dll': dll_name,
                                        'function': func_name,
                                        'hook_type': 'MOV_RAX',
                                        'bytes': original_bytes.hex(),
                                        'severity': 'MEDIUM'
                                    })
                        except:
                            pass
                except:
                    pass
            
            pm.close_process()
            
        except Exception as e:
            if self.verbose:
                print(f"{Colors.DIM}[!] Error scanning {process_name} (PID: {pid}): {e}{Colors.ENDC}")
        
        return hooks
    
    def scan_all_processes(self):
        """Scan all running processes for hooks"""
        print(f"{Colors.OKBLUE}[*] Scanning all running processes...{Colors.ENDC}")
        print(f"{Colors.DIM}This may take a moment...{Colors.ENDC}\n")
        
        processes = self.get_all_processes()
        
        # Filter to relevant processes (skip system idle, etc.)
        relevant_processes = [p for p in processes if p['pid'] > 100 and p['name'] != 'system']
        
        print(f"{Colors.OKGREEN}[+] Found {len(relevant_processes)} processes to scan{Colors.ENDC}\n")
        
        # Progress indicator
        scanned = 0
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {executor.submit(self.detect_hooks_in_process, p['pid'], p['name']): p for p in relevant_processes}
            
            for future in as_completed(futures):
                scanned += 1
                process = futures[future]
                try:
                    hooks = future.result()
                    self.all_hooks.extend(hooks)
                    if self.verbose and hooks:
                        print(f"{Colors.WARNING}[!] Found {len(hooks)} hooks in {process['name']} (PID: {process['pid']}){Colors.ENDC}")
                except:
                    pass
                
                # Progress update
                if scanned % 20 == 0:
                    print(f"{Colors.DIM}[*] Scanned {scanned}/{len(relevant_processes)} processes...{Colors.ENDC}")
        
        print(f"\n{Colors.OKGREEN}[+] Scan complete! Scanned {scanned} processes{Colors.ENDC}")
        return self.all_hooks
    
    def display_hooks_summary(self):
        """Display hooks in a clean summary format"""
        if not self.all_hooks:
            print(f"\n{Colors.OKGREEN}{'='*80}{Colors.ENDC}")
            print(f"{Colors.OKGREEN}[✓] NO API HOOKS DETECTED!{Colors.ENDC}")
            print(f"{Colors.OKGREEN}{'='*80}{Colors.ENDC}")
            print(f"\n{Colors.DIM}Your system appears clean. No EDR/AV hooks detected.{Colors.ENDC}\n")
            return
        
        # Group hooks by severity
        high_hooks = [h for h in self.all_hooks if h['severity'] == 'HIGH']
        medium_hooks = [h for h in self.all_hooks if h['severity'] == 'MEDIUM']
        
        print(f"\n{Colors.FAIL}{'='*100}{Colors.ENDC}")
        print(f"{Colors.FAIL}⚠️⚠️⚠️  API HOOKS DETECTED!  ⚠️⚠️⚠️{Colors.ENDC}")
        print(f"{Colors.FAIL}{'='*100}{Colors.ENDC}")
        
        # High severity hooks
        if high_hooks:
            print(f"\n{Colors.FAIL}[!] HIGH SEVERITY HOOKS (EDR/AV Monitoring):{Colors.ENDC}")
            print(f"{Colors.HEADER}{'Process':<25} {'Function':<35} {'Hook Type':<15} {'DLL':<20}{Colors.ENDC}")
            print(f"{Colors.DIM}{'-'*100}{Colors.ENDC}")
            
            for hook in high_hooks[:20]:  # Show first 20
                proc_name = hook['process'][:24] if len(hook['process']) > 24 else hook['process']
                func_name = hook['function'][:34] if len(hook['function']) > 34 else hook['function']
                print(f"{Colors.FAIL}{proc_name:<25} {func_name:<35} {hook['hook_type']:<15} {hook['dll']:<20}{Colors.ENDC}")
            
            if len(high_hooks) > 20:
                print(f"{Colors.DIM}... and {len(high_hooks)-20} more high severity hooks{Colors.ENDC}")
        
        # Medium severity hooks
        if medium_hooks:
            print(f"\n{Colors.WARNING}[!] MEDIUM SEVERITY HOOKS:{Colors.ENDC}")
            print(f"{Colors.HEADER}{'Process':<25} {'Function':<35} {'Hook Type':<15} {'DLL':<20}{Colors.ENDC}")
            print(f"{Colors.DIM}{'-'*100}{Colors.ENDC}")
            
            for hook in medium_hooks[:20]:
                proc_name = hook['process'][:24] if len(hook['process']) > 24 else hook['process']
                func_name = hook['function'][:34] if len(hook['function']) > 34 else hook['function']
                print(f"{Colors.WARNING}{proc_name:<25} {func_name:<35} {hook['hook_type']:<15} {hook['dll']:<20}{Colors.ENDC}")
        
        print(f"\n{Colors.FAIL}{'='*100}{Colors.ENDC}")
        print(f"{Colors.FAIL}Total: {len(self.all_hooks)} hooks (High: {len(high_hooks)}, Medium: {len(medium_hooks)}){Colors.ENDC}")
        
        # Explanation
        if high_hooks:
            print(f"\n{Colors.WARNING}[!] HIGH severity hooks indicate EDR/AV monitoring:{Colors.ENDC}")
            print(f"{Colors.DIM}  • INLINE_JMP - Function redirected to EDR for analysis{Colors.ENDC}")
            print(f"{Colors.DIM}  • INLINE_CALL - EDR callback installed{Colors.ENDC}")
            print(f"{Colors.DIM}  • Common in: ntdll.dll, kernel32.dll, amsi.dll{Colors.ENDC}")
    
    def scan_critical_only(self):
        """Scan only critical processes (faster)"""
        print(f"{Colors.OKBLUE}[*] Scanning critical processes only...{Colors.ENDC}")
        
        processes = self.get_all_processes()
        critical = [p for p in processes if p['name'].lower() in [c.lower() for c in CRITICAL_PROCESSES]]
        
        print(f"{Colors.OKGREEN}[+] Found {len(critical)} critical processes to scan{Colors.ENDC}\n")
        
        for proc in critical:
            print(f"{Colors.DIM}[*] Scanning {proc['name']} (PID: {proc['pid']})...{Colors.ENDC}")
            hooks = self.detect_hooks_in_process(proc['pid'], proc['name'])
            self.all_hooks.extend(hooks)
            if hooks:
                print(f"{Colors.WARNING}    Found {len(hooks)} hooks{Colors.ENDC}")
        
        return self.all_hooks

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="Enhanced API Hooking Detector")
    parser.add_argument("--quick", action="store_true", help="Quick scan (critical processes only)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    parser.add_argument("--pid", type=int, help="Scan single process by PID")
    
    args = parser.parse_args()
    
    # Check for admin rights
    if IS_WINDOWS:
        try:
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
            if not is_admin:
                print(f"{Colors.WARNING}[!] Not running as Administrator. Some processes may be inaccessible.{Colors.ENDC}")
                print(f"{Colors.DIM}    Right-click PowerShell → Run as Administrator for full access{Colors.ENDC}\n")
        except:
            pass
    
    detector = EnhancedHookDetector(verbose=args.verbose)
    detector.banner()
    
    if args.pid:
        # Scan single process
        import psutil
        try:
            proc = psutil.Process(args.pid)
            proc_name = proc.name()
            print(f"{Colors.OKBLUE}[*] Scanning single process: {proc_name} (PID: {args.pid}){Colors.ENDC}\n")
            hooks = detector.detect_hooks_in_process(args.pid, proc_name)
            detector.all_hooks = hooks
        except Exception as e:
            print(f"{Colors.FAIL}[-] Failed to find process: {e}{Colors.ENDC}")
            return
    elif args.quick:
        detector.scan_critical_only()
    else:
        detector.scan_all_processes()
    
    detector.display_hooks_summary()

if __name__ == "__main__":
    main()