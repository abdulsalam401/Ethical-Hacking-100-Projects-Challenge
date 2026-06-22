#!/usr/bin/env python3
"""
==============================================================
  PROJECT #16 — Process Monitor & Anti-Debugging Detector
  100 Ethical Hacking Projects Series
  
  Features:
  - List all running processes with details
  - Detect debuggers (ptrace, gdb, x64dbg, ollydbg)
  - Detect VM/sandbox environments
  - Anti-anti-debugging (self-debugging detection)
==============================================================

DEFENSE AGAINST PROCESS MONITORING & DEBUGGING:
1. Anti-Debugging Techniques:
   - ptrace self-attach detection
   - Timing checks (INT3 detection)
   - Hardware breakpoint detection
  
2. VM Detection Evasion:
   - Hide VM artifacts
   - Modify VM signatures
   - Use anti-VM techniques

3. Process Hiding:
   - Rootkits (DKOM)
   - LD_PRELOAD hooks
   - Kernel modules

USAGE:
--------
  # Basic process monitoring
  python3 monitor.py
  
  # Save output to file
  python3 monitor.py --output processes.txt
  
  # Continuous monitoring mode
  python3 monitor.py --continuous --interval 2
  
  # Verbose mode (all checks)
  python3 monitor.py --verbose
==============================================================
"""

import sys
import os
import platform
import time
import subprocess
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
    CYAN = Fore.CYAN

# Platform detection
IS_WINDOWS = platform.system() == "Windows"
IS_LINUX = platform.system() == "Linux"
IS_MAC = platform.system() == "Darwin"

# Try to import psutil (required for process monitoring)
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    print(f"{Colors.FAIL}[-] psutil not installed! Run: pip3 install psutil{Colors.ENDC}")
    PSUTIL_AVAILABLE = False

class AntiDebugDetector:
    """Detect if script is being debugged"""
    
    def __init__(self):
        self.debug_detected = False
        self.debug_methods = []
        
    def check_ptrace(self):
        """Check ptrace (Linux) - Can't debug self if ptrace attached"""
        if not IS_LINUX:
            return False
        
        try:
            # Try to ptrace self (should fail if already being traced)
            import ctypes
            import ctypes.util
            
            libc = ctypes.CDLL(ctypes.util.find_library('c'))
            ptrace = libc.ptrace
            ptrace.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p]
            ptrace.restype = ctypes.c_long
            
            PTRACE_TRACEME = 0
            
            # If already being traced, this will fail
            result = ptrace(PTRACE_TRACEME, 0, None, None)
            if result == -1:
                self.debug_detected = True
                self.debug_methods.append("ptrace (Linux tracer detected)")
                return True
        except:
            pass
        return False
    
    def check_debugger_processes(self):
        """Check for known debugger processes"""
        debugger_processes = [
            # Linux debuggers
            'gdb', 'lldb', 'strace', 'ltrace', 'valgrind', 'rr',
            # Windows debuggers
            'x64dbg', 'ollydbg', 'immunity', 'windbg', 'ida',
            'ida64', 'procdump', 'vbox', 'vmware',
            # Mac debuggers
            'dtrace', 'fs_usage', 'sc_usage'
        ]
        
        found = []
        for proc in psutil.process_iter(['name']):
            try:
                proc_name = proc.info['name'].lower() if proc.info['name'] else ''
                for debugger in debugger_processes:
                    if debugger in proc_name:
                        found.append(debugger)
            except:
                pass
        
        if found:
            self.debug_detected = True
            self.debug_methods.append(f"Debugger processes: {', '.join(found)}")
            return True
        return False
    
    def check_tracer_pid(self):
        """Check /proc/self/status for TracerPid (Linux)"""
        if not IS_LINUX:
            return False
        
        try:
            with open('/proc/self/status', 'r') as f:
                for line in f:
                    if line.startswith('TracerPid:'):
                        tracer_pid = line.split()[1]
                        if tracer_pid != '0':
                            self.debug_detected = True
                            self.debug_methods.append(f"TracerPid: {tracer_pid}")
                            return True
        except:
            pass
        return False
    
    def check_parent_process(self):
        """Check if parent process is a debugger"""
        try:
            parent = psutil.Process(os.getppid())
            parent_name = parent.name().lower() if parent.name() else ''
            
            debug_parents = ['gdb', 'lldb', 'strace', 'bash', 'sh', 'cmd']
            
            for debugger in debug_parents:
                if debugger in parent_name:
                    self.debug_detected = True
                    self.debug_methods.append(f"Parent process: {parent_name}")
                    return True
        except:
            pass
        return False
    
    def check_timing(self):
        """Check execution timing (debuggers slow execution)"""
        start = time.time()
        # Perform some CPU-intensive operations
        sum([i**2 for i in range(10000)])
        elapsed = time.time() - start
        
        # If execution is suspiciously slow, might be under debugger
        if elapsed > 0.1:  # Adjust threshold as needed
            self.debug_detected = True
            self.debug_methods.append(f"Timing anomaly: {elapsed:.3f}s")
            return True
        return False
    
    def check_environment_variables(self):
        """Check for debugger-related environment variables"""
        debug_env_vars = ['DEBUG', 'PYTHONDEBUG', 'PYTHONVERBOSE', 'GDB', 'VALGRIND']
        
        found = []
        for var in debug_env_vars:
            if var in os.environ:
                found.append(var)
        
        if found:
            self.debug_detected = True
            self.debug_methods.append(f"Debug env vars: {', '.join(found)}")
            return True
        return False
    
    def detect(self):
        """Run all detection methods"""
        self.check_ptrace()
        self.check_tracer_pid()
        self.check_debugger_processes()
        self.check_parent_process()
        self.check_timing()
        self.check_environment_variables()
        
        return self.debug_detected, self.debug_methods

class VMSandboxDetector:
    """Detect if running in VM/sandbox environment"""
    
    def __init__(self):
        self.vm_detected = False
        self.vm_signatures = []
    
    def check_processes(self):
        """Check for VM-related processes"""
        vm_processes = [
            'vboxservice', 'vboxtray', 'vmtoolsd', 'vmwaretray',
            'vmwareuser', 'docker', 'containerd', 'com.docker',
            'vmmem', 'vmmemctl'
        ]
        
        found = []
        for proc in psutil.process_iter(['name']):
            try:
                proc_name = proc.info['name'].lower() if proc.info['name'] else ''
                for vm_proc in vm_processes:
                    if vm_proc in proc_name:
                        found.append(vm_proc)
            except:
                pass
        
        if found:
            self.vm_detected = True
            self.vm_signatures.append(f"VM processes: {', '.join(found)}")
            return True
        return False
    
    def check_drivers_modules(self):
        """Check for VM drivers/modules (Linux)"""
        if not IS_LINUX:
            return False
        
        vm_modules = [
            'vboxguest', 'vboxsf', 'vmw_balloon', 'vmxnet3',
            'vmhgfs', 'virtio', 'xen-blkfront'
        ]
        
        try:
            with open('/proc/modules', 'r') as f:
                modules = f.read()
                for module in vm_modules:
                    if module in modules:
                        self.vm_detected = True
                        self.vm_signatures.append(f"VM module: {module}")
                        return True
        except:
            pass
        return False
    
    def check_dmi_info(self):
        """Check DMI info for VM signatures (Linux)"""
        if not IS_LINUX:
            return False
        
        vm_strings = ['VirtualBox', 'VMware', 'KVM', 'Xen', 'QEMU']
        dmi_paths = [
            '/sys/class/dmi/id/product_name',
            '/sys/class/dmi/id/sys_vendor',
            '/sys/class/dmi/id/board_vendor'
        ]
        
        for path in dmi_paths:
            try:
                with open(path, 'r') as f:
                    content = f.read().strip()
                    for vm_string in vm_strings:
                        if vm_string in content:
                            self.vm_detected = True
                            self.vm_signatures.append(f"DMI: {content}")
                            return True
            except:
                pass
        return False
    
    def check_mac_addresses(self):
        """Check MAC addresses for VM vendors"""
        vm_mac_prefixes = [
            '00:05:69', '00:0C:29', '00:50:56', '00:1C:42',  # VMware
            '08:00:27', '0A:00:27',  # VirtualBox
            '00:15:5D',  # Hyper-V
            '00:16:E3',  # Xen
            '00:18:51', '00:20:56',  # VMware
        ]
        
        try:
            import netifaces
            for iface in netifaces.interfaces():
                addrs = netifaces.ifaddresses(iface)
                if netifaces.AF_LINK in addrs:
                    mac = addrs[netifaces.AF_LINK][0]['addr'].upper()
                    for prefix in vm_mac_prefixes:
                        if mac.startswith(prefix):
                            self.vm_detected = True
                            self.vm_signatures.append(f"VM MAC: {mac}")
                            return True
        except:
            pass
        return False
    
    def check_cpu_features(self):
        """Check CPU features for VM indicators"""
        if not IS_LINUX:
            return False
        
        try:
            with open('/proc/cpuinfo', 'r') as f:
                cpuinfo = f.read()
                
            vm_cpu_flags = ['hypervisor', 'kvm', 'xen', 'vmx', 'svm']
            found_flags = []
            
            for flag in vm_cpu_flags:
                if flag in cpuinfo.lower():
                    found_flags.append(flag)
            
            if found_flags:
                self.vm_detected = True
                self.vm_signatures.append(f"CPU flags: {', '.join(found_flags)}")
                return True
        except:
            pass
        return False
    
    def detect(self):
        """Run all VM detection methods"""
        self.check_processes()
        self.check_drivers_modules()
        self.check_dmi_info()
        self.check_mac_addresses()
        self.check_cpu_features()
        
        return self.vm_detected, self.vm_signatures

class ProcessMonitor:
    """Monitor and list system processes"""
    
    def __init__(self, verbose=False):
        self.verbose = verbose
        self.processes = []
        
    def get_process_list(self):
        """Get list of all processes with details"""
        processes = []
        
        for proc in psutil.process_iter(['pid', 'name', 'memory_info', 'cpu_percent', 
                                          'ppid', 'create_time', 'status']):
            try:
                proc_info = proc.info
                processes.append({
                    'pid': proc_info['pid'],
                    'name': proc_info['name'] or 'Unknown',
                    'ppid': proc_info['ppid'] or 0,
                    'memory_mb': proc_info['memory_info'].rss / 1024 / 1024 if proc_info['memory_info'] else 0,
                    'cpu_percent': proc_info['cpu_percent'] or 0,
                    'status': proc_info['status'] or 'Unknown',
                    'create_time': datetime.fromtimestamp(proc_info['create_time']).strftime('%H:%M:%S') if proc_info['create_time'] else 'N/A'
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        
        return sorted(processes, key=lambda x: x['memory_mb'], reverse=True)
    
    def display_processes(self, processes):
        """Display processes in color-coded table"""
        print(f"\n{Colors.HEADER}{'='*100}{Colors.ENDC}")
        print(f"{Colors.BOLD}{'PID':<8} {'PPID':<8} {'Name':<30} {'Memory(MB)':<12} {'CPU%':<8} {'Status':<10} {'Time':<10}{Colors.ENDC}")
        print(f"{Colors.HEADER}{'='*100}{Colors.ENDC}")
        
        for proc in processes[:50]:  # Show top 50 processes
            # Color code based on memory usage
            if proc['memory_mb'] > 500:
                mem_color = Colors.FAIL
            elif proc['memory_mb'] > 100:
                mem_color = Colors.WARNING
            else:
                mem_color = Colors.OKGREEN
            
            # Color code based on status
            if proc['status'] == 'running':
                status_color = Colors.OKGREEN
            elif proc['status'] == 'sleeping':
                status_color = Colors.DIM
            else:
                status_color = Colors.WARNING
            
            print(f"{proc['pid']:<8} {proc['ppid']:<8} "
                  f"{Colors.CYAN}{proc['name'][:29]:<30}{Colors.ENDC} "
                  f"{mem_color}{proc['memory_mb']:<12.1f}{Colors.ENDC} "
                  f"{proc['cpu_percent']:<8.1f} "
                  f"{status_color}{proc['status']:<10}{Colors.ENDC} "
                  f"{Colors.DIM}{proc['create_time']:<10}{Colors.ENDC}")
        
        if len(processes) > 50:
            print(f"{Colors.DIM}... and {len(processes)-50} more processes{Colors.ENDC}")
        
        print(f"{Colors.HEADER}{'='*100}{Colors.ENDC}")
        print(f"{Colors.OKGREEN}Total processes: {len(processes)}{Colors.ENDC}")
    
    def display_summary(self, processes):
        """Display process summary statistics"""
        total_memory = sum(p['memory_mb'] for p in processes)
        total_cpu = sum(p['cpu_percent'] for p in processes)
        
        print(f"\n{Colors.HEADER}{'='*100}{Colors.ENDC}")
        print(f"{Colors.BOLD}  SYSTEM SUMMARY{Colors.ENDC}")
        print(f"{Colors.HEADER}{'='*100}{Colors.ENDC}")
        print(f"{Colors.OKGREEN}Total Memory Usage: {total_memory:.1f} MB ({total_memory/1024:.1f} GB){Colors.ENDC}")
        print(f"{Colors.OKGREEN}Total CPU Usage: {total_cpu:.1f}%{Colors.ENDC}")
        print(f"{Colors.OKGREEN}Process Count: {len(processes)}{Colors.ENDC}")
        
        # Top 5 memory consumers
        print(f"\n{Colors.BOLD}Top 5 Memory Consumers:{Colors.ENDC}")
        for i, proc in enumerate(processes[:5], 1):
            print(f"  {i}. {proc['name']} - {proc['memory_mb']:.1f} MB")
        
        print(f"{Colors.HEADER}{'='*100}{Colors.ENDC}\n")

def banner():
    """Display banner"""
    print(f"{Colors.HEADER}{'='*70}{Colors.ENDC}")
    print(f"{Colors.HEADER}  PROJECT #16 — Process Monitor & Anti-Debugging Detector{Colors.ENDC}")
    print(f"{Colors.OKBLUE}  Process monitoring with anti-debugging/VM detection{Colors.ENDC}")
    print(f"{Colors.HEADER}{'='*70}{Colors.ENDC}\n")
    
    print(f"{Colors.OKGREEN}[+] Platform: {platform.system()} {platform.release()}{Colors.ENDC}")
    print(f"{Colors.OKGREEN}[+] Python: {sys.version.split()[0]}{Colors.ENDC}")
    print(f"{Colors.OKGREEN}[+] User: {os.getenv('USER', os.getenv('USERNAME', 'Unknown'))}{Colors.ENDC}")

def print_defenses():
    """Print defense mechanisms"""
    print(f"\n{Colors.HEADER}{'='*70}{Colors.ENDC}")
    print(f"{Colors.BOLD}  DEFENSE AGAINST PROCESS MONITORING & DEBUGGING{Colors.ENDC}")
    print(f"{Colors.HEADER}{'='*70}{Colors.ENDC}")
    
    defenses = [
        ("Anti-Debugging Techniques:", ""),
        ("  • Ptrace self-attach", "Prevents debugger attachment on Linux"),
        ("  • Timing checks", "Detect debugger slowdowns"),
        ("  • INT3 detection", "Detect software breakpoints"),
        ("  • Hardware breakpoint detection", "Detect hardware debug registers"),
        ("", ""),
        ("VM Detection Evasion:", ""),
        ("  • Patch VM signatures", "Modify DMI/MAC/PCI IDs"),
        ("  • Hide VM processes", "Unload VM kernel modules"),
        ("  • CPU flag masking", "Hide hypervisor CPU flags"),
        ("", ""),
        ("Process Hiding:", ""),
        ("  • DKOM (Direct Kernel Object Manipulation)", "Hide processes from EPROCESS list"),
        ("  • LD_PRELOAD hooks", "Intercept system calls"),
        ("  • Kernel modules", "Run at ring 0 for full control"),
        ("", ""),
        ("Detection & Monitoring:", ""),
        ("  • EDR/XDR solutions", "Enterprise detection"),
        ("  • Syscall monitoring", "Detect suspicious API calls"),
        ("  • Memory scanning", "Find hidden processes")
    ]
    
    for title, desc in defenses:
        if title and not desc:
            print(f"{Colors.OKGREEN}{title}{Colors.ENDC}")
        elif desc:
            print(f"{Colors.OKBLUE}{title}{Colors.ENDC}: {Colors.DIM}{desc}{Colors.ENDC}")
        else:
            print()
    
    print(f"{Colors.HEADER}{'='*70}{Colors.ENDC}\n")

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="Process Monitor & Anti-Debugging Detector")
    parser.add_argument("-o", "--output", help="Save output to file")
    parser.add_argument("-c", "--continuous", action="store_true", help="Continuous monitoring mode")
    parser.add_argument("-i", "--interval", type=int, default=2, help="Update interval in seconds")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("-q", "--quiet", action="store_true", help="Quiet mode (no process list)")
    
    args = parser.parse_args()
    
    if not PSUTIL_AVAILABLE:
        sys.exit(1)
    
    banner()
    
    # Anti-debugging detection
    debug_detector = AntiDebugDetector()
    is_debugged, debug_methods = debug_detector.detect()
    
    if is_debugged:
        print(f"{Colors.FAIL}{'='*70}{Colors.ENDC}")
        print(f"{Colors.FAIL}⚠️⚠️⚠️  DEBUGGER DETECTED!  ⚠️⚠️⚠️{Colors.ENDC}")
        print(f"{Colors.FAIL}{'='*70}{Colors.ENDC}")
        for method in debug_methods:
            print(f"{Colors.FAIL}[!] {method}{Colors.ENDC}")
        print(f"{Colors.FAIL}{'='*70}{Colors.ENDC}\n")
    else:
        print(f"{Colors.OKGREEN}✅ No debugger detected{Colors.ENDC}\n")
    
    # VM/Sandbox detection
    vm_detector = VMSandboxDetector()
    is_vm, vm_signatures = vm_detector.detect()
    
    if is_vm:
        print(f"{Colors.WARNING}[!] Virtual Machine/Sandbox Detected!{Colors.ENDC}")
        for sig in vm_signatures:
            print(f"{Colors.DIM}   → {sig}{Colors.ENDC}")
    else:
        print(f"{Colors.OKGREEN}✅ Running on bare metal/native system{Colors.ENDC}")
    
    print()
    
    # Process monitoring
    monitor = ProcessMonitor(args.verbose)
    
    if args.continuous:
        # Continuous monitoring mode
        print(f"{Colors.OKBLUE}[*] Continuous monitoring mode (Ctrl+C to stop){Colors.ENDC}")
        try:
            while True:
                os.system('clear' if platform.system() != 'Windows' else 'cls')
                banner()
                
                # Re-check debugger (in case attached later)
                is_debugged, debug_methods = debug_detector.detect()
                if is_debugged:
                    print(f"{Colors.FAIL}⚠️ DEBUGGER DETECTED!{Colors.ENDC}")
                
                processes = monitor.get_process_list()
                if not args.quiet:
                    monitor.display_processes(processes)
                monitor.display_summary(processes)
                
                time.sleep(args.interval)
        except KeyboardInterrupt:
            print(f"\n{Colors.WARNING}[!] Monitoring stopped{Colors.ENDC}")
    else:
        # Single scan mode
        processes = monitor.get_process_list()
        
        if not args.quiet:
            monitor.display_processes(processes)
        monitor.display_summary(processes)
        
        # Save to file if requested
        if args.output:
            try:
                with open(args.output, 'w') as f:
                    f.write(f"Process Monitor Report - {datetime.now()}\n")
                    f.write(f"{'='*100}\n")
                    f.write(f"{'PID':<8} {'PPID':<8} {'Name':<30} {'Memory(MB)':<12} {'CPU%':<8} {'Status':<10}\n")
                    f.write(f"{'='*100}\n")
                    for proc in processes:
                        f.write(f"{proc['pid']:<8} {proc['ppid']:<8} {proc['name'][:29]:<30} {proc['memory_mb']:<12.1f} {proc['cpu_percent']:<8.1f} {proc['status']:<10}\n")
                    f.write(f"{'='*100}\n")
                    f.write(f"Total processes: {len(processes)}\n")
                print(f"{Colors.OKGREEN}[+] Output saved to {args.output}{Colors.ENDC}")
            except Exception as e:
                print(f"{Colors.FAIL}[-] Failed to save output: {e}{Colors.ENDC}")
    
    # Print defenses
    if args.verbose:
        print_defenses()

if __name__ == "__main__":
    main()