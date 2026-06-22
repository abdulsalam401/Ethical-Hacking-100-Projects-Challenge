#!/usr/bin/env python3
"""
============================================================
  PROJECT #16 — Process Monitor & Anti-Debugging Detector
  100 Ethical Hacking Projects Series
  Libs : psutil, ctypes, /proc (Linux), sysctl (macOS)
============================================================

WHAT THIS IS
-------------
A system introspection tool with three layers:

1. PROCESS MONITOR — equivalent to "ps aux" + Task Manager.
   Incident response use: enumerate all running processes,
   flag suspicious ones (injected DLLs, hidden PIDs, masqueraded
   process names). Blue team first step after a host compromise.

2. DEBUGGER DETECTOR — checks if THIS process is being traced
   (ptrace, gdb, strace, x64dbg) and if known debugger processes
   are running on the system.

   DEFENSIVE (malware analyst): Real malware checks for debuggers
   and behaves differently if detected (sleep, crash, delete self).
   Knowing the detection technique lets you bypass it in sandboxes
   (e.g., patch ptrace check, rename gdb to something innocent).

   OFFENSIVE (red team): An authorized implant that detects sandbox
   analysis is a realistic APT simulation — demonstrates to the
   client that their sandbox would be evaded. SANS FOR610 Chapter 16.

3. VM / SANDBOX DETECTOR — identifies VMware, VirtualBox, Docker,
   WSL, Hyper-V artifacts via DMI strings, MAC OUI, process names,
   filesystem markers, and cpuid leaves.

   DEFENSIVE: Helps sandbox builders harden their environments.
   Real malware families (Emotet, TrickBot) check these and refuse
   to run — automated analysis gets clean reports.
   Offensive/research: Shows which sandbox artifacts are detectable.

DEFENSE AGAINST PROCESS MONITORING
-------------------------------------
1. PROCESS HIDING (kernel rootkits) — hook getdents() syscall to
   hide PIDs from /proc. Detected by cross-referencing multiple
   enumeration methods (psutil vs /proc vs netstat).
2. EDR PROCESS INJECTION DETECTION — monitor CreateRemoteThread,
   NtWriteVirtualMemory for cross-process write signatures.
3. SYSMON Event ID 1 (Process Create) — log every process start
   with full command line and parent PID.
4. INTEGRITY CHECKING — hash known-good process images; alert if
   a process with a legitimate name (svchost.exe) has wrong hash.

USAGE
------
  python3 project16_monitor.py                    # full scan
  python3 project16_monitor.py --procs-only       # process list only
  python3 project16_monitor.py --debug-only       # debugger check only
  python3 project16_monitor.py --vm-only          # VM/sandbox check only
  python3 project16_monitor.py --top 20           # top 20 by memory
  python3 project16_monitor.py --filter ssh       # filter by name
  python3 project16_monitor.py --output report.json
============================================================
"""

import argparse, os, sys, time, platform, subprocess
import json, datetime, socket, struct, re
from pathlib import Path

try:
    import psutil
    PSUTIL_OK = True
except ImportError:
    PSUTIL_OK = False
    print("pip install psutil --break-system-packages")
    sys.exit(1)

# ── colours ───────────────────────────────────────────────
R="\033[0m";BOLD="\033[1m";RED="\033[91m";GREEN="\033[92m"
YELLOW="\033[93m";CYAN="\033[96m";MAGENTA="\033[95m";DIM="\033[2m"
BLUE="\033[94m"
def c(t,code): return f"{code}{t}{R}"

IS_LINUX   = platform.system() == "Linux"
IS_WINDOWS = platform.system() == "Windows"
IS_MACOS   = platform.system() == "Darwin"

# ═════════════════════════════════════════════════════════
# ❶  PROCESS MONITOR
# ═════════════════════════════════════════════════════════

# processes that are commonly injected into or suspicious
SUSPICIOUS_NAMES = {
    "mimikatz","meterpreter","beacon","cobaltstrike",
    "empire","metasploit","netcat","ncat","nc.exe",
    "procdump","lazagne","pwdump","gsecdump","wce",
    "psexec","wmiexec","smbexec","dcomexec",
}

# legit processes that malware masquerades as (check path)
MASQUERADE_TARGETS = {
    "svchost.exe","lsass.exe","csrss.exe","winlogon.exe",
    "explorer.exe","services.exe","taskmgr.exe",
}

def bytes_human(n: int) -> str:
    for unit in ["B","KB","MB","GB"]:
        if n < 1024: return f"{n:.1f}{unit}"
        n /= 1024
    return f"{n:.1f}TB"

def get_processes(name_filter: str = "", top_n: int = 0) -> list[dict]:
    procs = []
    for p in psutil.process_iter(["pid","name","status","ppid",
                                   "memory_info","cpu_percent","username",
                                   "exe","cmdline","create_time"]):
        try:
            info = p.info
            name = info["name"] or ""

            if name_filter and name_filter.lower() not in name.lower():
                continue

            mem  = info["memory_info"].rss if info["memory_info"] else 0
            cpu  = info["cpu_percent"] or 0.0
            exe  = info["exe"] or ""
            cmd  = " ".join(info["cmdline"] or [])[:80]
            user = info["username"] or "?"

            # suspicion flags
            flags = []
            nl = name.lower().rstrip(".exe")
            if nl in SUSPICIOUS_NAMES:
                flags.append("SUSPICIOUS_NAME")
            if (name.lower() in MASQUERADE_TARGETS and exe and
                    not any(d in exe.lower() for d in
                            ["system32","syswow64","windows"])):
                flags.append("PATH_MISMATCH")
            # hidden PID check (Linux only)
            if IS_LINUX and not os.path.exists(f"/proc/{info['pid']}"):
                flags.append("HIDDEN_PID")

            procs.append({
                "pid"   : info["pid"],
                "name"  : name,
                "status": info["status"],
                "ppid"  : info["ppid"] or 0,
                "mem"   : mem,
                "cpu"   : cpu,
                "user"  : user,
                "exe"   : exe,
                "cmd"   : cmd,
                "flags" : flags,
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    procs.sort(key=lambda x: x["mem"], reverse=True)
    return procs[:top_n] if top_n else procs

def print_process_table(procs: list[dict]):
    print()
    print(c("  ── RUNNING PROCESSES ───────────────────────────────────────────────────", CYAN))
    print()
    print(f"  {c('PID',R):<10}{c('PPID',R):<9}{c('NAME',R):<26}"
          f"{c('USER',R):<18}{c('MEM',R):<10}{c('CPU%',R):<7}"
          f"{c('STATUS',R):<14}{c('FLAGS',R)}")
    print("  "+c("─"*98, DIM))

    for p in procs:
        flag_s = ""
        if p["flags"]:
            flag_s = c(" ⚠ " + " ".join(p["flags"]), RED+BOLD)

        name_c = (c(p["name"][:24], RED+BOLD) if p["flags"]
                  else c(p["name"][:24], GREEN))
        status_c = (c(p["status"], GREEN) if p["status"] == "running"
                    else c(p["status"], DIM))

        print(f"  {c(str(p['pid']),CYAN):<18}"
              f"{c(str(p['ppid']),DIM):<17}"
              f"{name_c:<35}"
              f"{c(p['user'][:16],MAGENTA):<26}"
              f"{c(bytes_human(p['mem']),YELLOW):<18}"
              f"{c(str(round(p['cpu'],1)),DIM):<15}"
              f"{status_c:<22}"
              f"{flag_s}")

    # summary
    total_mem = sum(p["mem"] for p in procs)
    sus       = [p for p in procs if p["flags"]]
    print()
    print(f"  Total: {c(str(len(procs)), BOLD)} processes  "
          f"RAM used: {c(bytes_human(total_mem), YELLOW)}  "
          f"Suspicious: {c(str(len(sus)), RED+BOLD if sus else GREEN)}")
    print()
    return sus

# ═════════════════════════════════════════════════════════
# ❷  DEBUGGER DETECTOR
# ═════════════════════════════════════════════════════════

DEBUGGER_PROC_NAMES = {
    # Linux
    "gdb","gdbserver","strace","ltrace","ptrace","radare2","r2",
    "frida","frida-server","pin","valgrind","perf",
    # Windows
    "x64dbg","x32dbg","ollydbg","windbg","ida","ida64",
    "immunity","idaq","idaq64","pestudio","processhacker",
    "wireshark","fiddler","procmon","procexp","autoruns",
    # macOS
    "lldb","dtrace","instruments",
}

def check_tracerpid() -> tuple[bool, int]:
    """Linux: read /proc/self/status TracerPid field."""
    try:
        status = Path("/proc/self/status").read_text()
        for line in status.splitlines():
            if line.startswith("TracerPid:"):
                pid = int(line.split(":")[1].strip())
                return pid != 0, pid
    except Exception:
        pass
    return False, 0

def check_ptrace() -> bool:
    """
    Linux: attempt ptrace(PTRACE_TRACEME, 0, 0, 0).
    Returns True if we ARE being traced (call fails with EPERM).
    If not traced, we successfully self-attach then detach.
    """
    if not IS_LINUX:
        return False
    try:
        import ctypes
        libc = ctypes.CDLL("libc.so.6", use_errno=True)
        PTRACE_TRACEME = 0
        ret = libc.ptrace(PTRACE_TRACEME, 0, 0, 0)
        if ret == -1:
            # EPERM = 1 → already being traced
            import ctypes.util
            errno = ctypes.get_errno()
            if errno == 1:   # EPERM
                return True
        else:
            # successfully attached → detach immediately
            PTRACE_DETACH = 17
            libc.ptrace(PTRACE_DETACH, 0, 0, 0)
        return False
    except Exception:
        return False

def check_windows_debugger() -> bool:
    """Windows: IsDebuggerPresent + CheckRemoteDebuggerPresent."""
    if not IS_WINDOWS:
        return False
    try:
        import ctypes
        if ctypes.windll.kernel32.IsDebuggerPresent():
            return True
        is_dbg = ctypes.c_bool(False)
        handle  = ctypes.windll.kernel32.GetCurrentProcess()
        ctypes.windll.kernel32.CheckRemoteDebuggerPresent(
            handle, ctypes.byref(is_dbg))
        return is_dbg.value
    except Exception:
        return False

def check_macos_debugger() -> bool:
    """macOS: sysctl kinfo_proc p_flag & P_TRACED."""
    if not IS_MACOS:
        return False
    try:
        import ctypes, ctypes.util
        libc = ctypes.CDLL(ctypes.util.find_library("c"))
        # sysctl([CTL_KERN, KERN_PROC, KERN_PROC_PID, pid], ...)
        # Simplified: check via subprocess
        result = subprocess.run(
            ["sysctl", f"kern.proc.pid.{os.getpid()}"],
            capture_output=True, text=True)
        return "P_TRACED" in result.stdout
    except Exception:
        return False

def check_timing_anomaly() -> bool:
    """
    Timing-based debugger detection.
    A debugger introduces significant latency between instructions.
    Time a tight loop — if >5ms for 1000 iterations, suspect debugger.
    """
    t0    = time.perf_counter()
    count = 0
    for _ in range(10_000):
        count += 1
    elapsed_ms = (time.perf_counter() - t0) * 1000
    # threshold: >50ms for 10k noop iterations = likely traced
    return elapsed_ms > 50

def scan_debugger_processes() -> list[str]:
    """Find known debugger/analysis tools in the process list."""
    found = []
    for p in psutil.process_iter(["name","pid"]):
        try:
            name = (p.info["name"] or "").lower().rstrip(".exe")
            if name in DEBUGGER_PROC_NAMES:
                found.append(f"{p.info['name']}(PID={p.info['pid']})")
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return found

def check_env_analysis() -> list[str]:
    """
    Check environment variables that analysis tools set.
    Common in Cuckoo sandbox, ANY.RUN, Joe Sandbox.
    """
    indicators = []
    suspicious_env = {
        "FRIDA_GADGET_DELAY": "Frida gadget",
        "CUCKOO": "Cuckoo sandbox",
        "_JAVA_OPTIONS": "Java agent (possible instrumentation)",
        "WINEDEBUG": "Wine debugger",
        "LD_PRELOAD": "Library preload (hooking?)",
    }
    for var, label in suspicious_env.items():
        if os.environ.get(var):
            indicators.append(f"{var} ({label})")
    return indicators

def run_debugger_checks() -> dict:
    results = {
        "tracer_pid"     : False,
        "tracer_pid_val" : 0,
        "ptrace_detect"  : False,
        "windows_api"    : False,
        "macos_sysctl"   : False,
        "timing_anomaly" : False,
        "debugger_procs" : [],
        "env_indicators" : [],
        "verdict"        : "CLEAN",
    }

    traced, tpid = check_tracerpid()
    results["tracer_pid"]     = traced
    results["tracer_pid_val"] = tpid

    results["ptrace_detect"]  = check_ptrace()
    results["windows_api"]    = check_windows_debugger()
    results["macos_sysctl"]   = check_macos_debugger()
    results["timing_anomaly"] = check_timing_anomaly()
    results["debugger_procs"] = scan_debugger_processes()
    results["env_indicators"] = check_env_analysis()

    any_hit = (results["tracer_pid"] or results["ptrace_detect"] or
               results["windows_api"] or results["macos_sysctl"] or
               results["debugger_procs"])
    results["verdict"] = "DEBUGGER DETECTED" if any_hit else "CLEAN"
    return results

def print_debugger_results(r: dict):
    print(c("  ── DEBUGGER / TRACER DETECTION ─────────────────────────────", CYAN))
    print()

    def row(label, detected, detail=""):
        icon  = c("⚠ YES", RED+BOLD) if detected else c("✔ NO ", GREEN)
        det_s = c(f"  ({detail})", YELLOW) if detail else ""
        print(f"  {c(label+':', DIM):<40} {icon}{det_s}")

    row("TracerPid in /proc/self/status",
        r["tracer_pid"],
        f"PID={r['tracer_pid_val']}" if r["tracer_pid"] else "")
    row("ptrace(PTRACE_TRACEME) rejected",  r["ptrace_detect"])
    row("Windows IsDebuggerPresent API",    r["windows_api"])
    row("macOS P_TRACED sysctl flag",       r["macos_sysctl"])
    row("Timing anomaly (>50ms/10k loop)",  r["timing_anomaly"])

    if r["debugger_procs"]:
        print(f"\n  {c('⚠ Debugger processes found:', RED+BOLD)}")
        for p in r["debugger_procs"]:
            print(f"    {c('•', RED)} {c(p, YELLOW)}")
    else:
        print(f"\n  {c('✔ No known debugger/analysis processes found.', GREEN)}")

    if r["env_indicators"]:
        print(f"\n  {c('⚠ Suspicious environment variables:', YELLOW)}")
        for e in r["env_indicators"]:
            print(f"    {c('•', YELLOW)} {e}")

    print()
    verdict = r["verdict"]
    vcolor  = RED+BOLD if verdict != "CLEAN" else GREEN+BOLD
    print(f"  {c('VERDICT:', BOLD)} {c(verdict, vcolor)}")
    if verdict != "CLEAN":
        print(c("  ⚠ DEBUGGER DETECTED — analysis environment identified.", RED+BOLD))
        print(c("  Script would normally alter behaviour here (sleep/exit/decoy).", DIM))
    print()

# ═════════════════════════════════════════════════════════
# ❸  VM / SANDBOX DETECTOR
# ═════════════════════════════════════════════════════════

# MAC address OUI prefixes for virtual NICs
VM_MAC_OUIS = {
    "00:50:56": "VMware",
    "00:0c:29": "VMware",
    "00:05:69": "VMware",
    "08:00:27": "VirtualBox",
    "52:54:00": "QEMU/KVM",
    "00:15:5d": "Hyper-V",
    "00:1c:42": "Parallels",
    "00:16:3e": "Xen",
}

VM_PROC_NAMES = {
    "vmtoolsd","vmwaretray","vmwareuser",    # VMware
    "vboxservice","vboxclient",              # VirtualBox
    "prl_tools","prl_cc",                   # Parallels
    "xenservice","xe-daemon",                # Xen
    "qemu-ga",                               # QEMU
    "docker",                                # Docker
}

VM_DMI_STRINGS = {
    "vmware"     : "VMware",
    "virtualbox" : "VirtualBox",
    "vbox"       : "VirtualBox",
    "hyper-v"    : "Hyper-V",
    "hyperv"     : "Hyper-V",
    "qemu"       : "QEMU",
    "kvm"        : "KVM",
    "xen"        : "Xen",
    "parallels"  : "Parallels",
    "bhyve"      : "bhyve",
}

def check_dmi() -> list[str]:
    """Linux: read /sys/class/dmi/id/* for hypervisor strings."""
    hits = []
    dmi_files = [
        "/sys/class/dmi/id/sys_vendor",
        "/sys/class/dmi/id/product_name",
        "/sys/class/dmi/id/board_vendor",
        "/sys/class/dmi/id/bios_vendor",
    ]
    for f in dmi_files:
        try:
            val = Path(f).read_text().strip().lower()
            for key, label in VM_DMI_STRINGS.items():
                if key in val and label not in hits:
                    hits.append(f"{label} (via {Path(f).name}={val[:30]})")
        except Exception:
            pass
    return hits

def check_cpuid_hypervisor() -> str | None:
    """
    x86 CPUID leaf 0x1 bit 31 of ECX = hypervisor present.
    Leaf 0x40000000 returns hypervisor vendor string.
    Uses /proc/cpuinfo as fallback on Linux.
    """
    try:
        cpuinfo = Path("/proc/cpuinfo").read_text()
        if "hypervisor" in cpuinfo.lower():
            # try to get vendor from /proc/cpuinfo flags
            for line in cpuinfo.splitlines():
                if "hypervisor" in line:
                    return "Hypervisor bit set in CPUID"
    except Exception:
        pass
    return None

def check_mac_oui() -> list[str]:
    """Check NIC MAC addresses against known VM OUI prefixes."""
    hits = []
    try:
        for iface, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.family == psutil.AF_LINK:   # MAC
                    mac = addr.address.lower()
                    oui = mac[:8]
                    if oui in VM_MAC_OUIS:
                        hits.append(f"{VM_MAC_OUIS[oui]} (iface={iface} MAC={mac})")
    except Exception:
        pass
    return hits

def check_vm_processes() -> list[str]:
    """Find known VM guest agent processes."""
    found = []
    for p in psutil.process_iter(["name","pid"]):
        try:
            name = (p.info["name"] or "").lower().rstrip(".exe")
            if name in VM_PROC_NAMES:
                found.append(f"{p.info['name']}(PID={p.info['pid']})")
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return found

def check_filesystem_artifacts() -> list[str]:
    """Check for filesystem markers of containers and VMs."""
    artifacts = []
    checks = [
        ("/.dockerenv",           "Docker container"),
        ("/run/.containerenv",    "Podman/OCI container"),
        ("/proc/vz",              "OpenVZ"),
        ("/proc/xen",             "Xen hypervisor"),
        ("/dev/vmci",             "VMware VMCI device"),
        ("/dev/vboxguest",        "VirtualBox guest"),
        ("/dev/vboxuser",         "VirtualBox user"),
    ]
    for path, label in checks:
        if os.path.exists(path):
            artifacts.append(f"{label} ({path})")

    # cgroup check (Docker uses cgroup v2)
    try:
        cgroup = Path("/proc/1/cgroup").read_text()
        if "docker" in cgroup or "kubepods" in cgroup:
            artifacts.append("Docker/Kubernetes (cgroup)")
        elif "lxc" in cgroup:
            artifacts.append("LXC container (cgroup)")
    except Exception:
        pass

    return artifacts

def check_wsl() -> str | None:
    """Detect WSL (Windows Subsystem for Linux)."""
    try:
        version = Path("/proc/version").read_text().lower()
        if "microsoft" in version:
            if "wsl2" in version or "wsl" in version:
                return "WSL2 (Windows Subsystem for Linux)"
            return "WSL (Windows Subsystem for Linux)"
    except Exception:
        pass
    # also check env
    if os.environ.get("WSL_DISTRO_NAME"):
        return f"WSL ({os.environ['WSL_DISTRO_NAME']})"
    return None

def check_registry_vm_keys() -> list[str]:
    """Windows: check registry for VM artifacts."""
    if not IS_WINDOWS:
        return []
    hits = []
    try:
        import winreg
        vm_keys = [
            (winreg.HKEY_LOCAL_MACHINE,
             r"SOFTWARE\VMware, Inc.\VMware Tools", "VMware"),
            (winreg.HKEY_LOCAL_MACHINE,
             r"SOFTWARE\Oracle\VirtualBox Guest Additions", "VirtualBox"),
        ]
        for hive, path, label in vm_keys:
            try:
                winreg.OpenKey(hive, path)
                hits.append(f"{label} (registry key present)")
            except FileNotFoundError:
                pass
    except ImportError:
        pass
    return hits

def run_vm_checks() -> dict:
    results = {
        "dmi"        : check_dmi(),
        "cpuid"      : check_cpuid_hypervisor(),
        "mac_oui"    : check_mac_oui(),
        "vm_procs"   : check_vm_processes(),
        "fs_artifacts": check_filesystem_artifacts(),
        "wsl"        : check_wsl(),
        "registry"   : check_registry_vm_keys(),
        "environment": "",
        "confidence" : "NONE",
    }

    # aggregate confidence
    hit_count = (len(results["dmi"]) + len(results["mac_oui"]) +
                 len(results["vm_procs"]) + len(results["fs_artifacts"]) +
                 len(results["registry"]) +
                 (1 if results["cpuid"] else 0) +
                 (1 if results["wsl"] else 0))

    if results["wsl"]:
        results["environment"] = results["wsl"]
        results["confidence"]  = "HIGH"
    elif hit_count >= 3:
        # pick most-mentioned environment
        env_votes = {}
        for item in (results["dmi"] + results["mac_oui"] +
                     results["vm_procs"] + results["fs_artifacts"]):
            for label in VM_DMI_STRINGS.values():
                if label.lower() in item.lower():
                    env_votes[label] = env_votes.get(label, 0) + 1
        if "Docker container" in str(results["fs_artifacts"]):
            env_votes["Docker"] = env_votes.get("Docker", 0) + 3
        top = max(env_votes, key=env_votes.get) if env_votes else "Virtual Machine"
        results["environment"] = top
        results["confidence"]  = "HIGH"
    elif hit_count >= 1:
        results["confidence"] = "MED"
        results["environment"] = "Virtual/Container (unconfirmed)"
    else:
        results["environment"] = "Bare Metal (no VM artifacts)"
        results["confidence"]  = "NONE"

    return results

def print_vm_results(r: dict):
    print(c("  ── VM / SANDBOX / CONTAINER DETECTION ─────────────────────", CYAN))
    print()

    def section(title, items, color=YELLOW):
        print(f"  {c(title, DIM)}")
        if items:
            for item in items:
                print(f"    {c('⚠', RED)} {c(item, color)}")
        else:
            print(f"    {c('✔ None detected', GREEN)}")

    section("DMI / BIOS strings:",         r["dmi"])
    section("CPUID hypervisor bit:",        [r["cpuid"]] if r["cpuid"] else [])
    section("Virtual NIC MAC OUI:",         r["mac_oui"])
    section("VM guest agent processes:",    r["vm_procs"])
    section("Filesystem artifacts:",        r["fs_artifacts"])
    section("Registry (Windows):",          r["registry"])

    if r["wsl"]:
        print(f"\n  {c('⚠ WSL DETECTED:', RED+BOLD)} {c(r['wsl'], YELLOW)}")

    print()
    conf  = r["confidence"]
    cmap  = {"HIGH": RED+BOLD, "MED": YELLOW, "NONE": GREEN}
    print(f"  {c('Environment :', BOLD)} {c(r['environment'], cmap.get(conf, DIM))}")
    print(f"  {c('Confidence  :', BOLD)} {c(conf, cmap.get(conf, DIM))}")
    print()

# ═════════════════════════════════════════════════════════
# ❹  MAIN
# ═════════════════════════════════════════════════════════

def banner():
    print()
    print(c("  ╔══════════════════════════════════════════════════════╗", CYAN))
    print(c("  ║   PROJECT #16 · PROCESS MONITOR & ANTI-DEBUG         ║", CYAN))
    print(c("  ║   100 Ethical Hacking Projects Series                 ║", CYAN))
    print(c("  ╚══════════════════════════════════════════════════════╝", CYAN))
    print()
    print(f"  Host     : {c(socket.gethostname(), YELLOW)}")
    print(f"  OS       : {c(platform.system()+' '+platform.release(), MAGENTA)}")
    print(f"  Python   : {c(sys.version.split()[0], DIM)}")
    print(f"  Time     : {c(datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'), DIM)}")
    print(f"  Self PID : {c(str(os.getpid()), CYAN)}")
    print()

def main():
    parser = argparse.ArgumentParser(
        description="Project #16 — Process Monitor & Anti-Debugging Detector")
    parser.add_argument("--procs-only",  action="store_true")
    parser.add_argument("--debug-only",  action="store_true")
    parser.add_argument("--vm-only",     action="store_true")
    parser.add_argument("--top",         type=int, default=0,
                        help="Show only top N processes by memory")
    parser.add_argument("--filter",      default="",
                        help="Filter process list by name substring")
    parser.add_argument("--output",      default=None,
                        help="Save full report to JSON file")
    args = parser.parse_args()

    banner()
    report = {"host": socket.gethostname(),
              "time": datetime.datetime.now().isoformat()}

    do_all = not any([args.procs_only, args.debug_only, args.vm_only])

    # ── processes ─────────────────────────────────────────
    if do_all or args.procs_only:
        print(c("  ── PROCESS LIST ────────────────────────────────────────────", CYAN))
        procs = get_processes(args.filter, args.top)
        sus   = print_process_table(procs)
        report["processes"] = {
            "count": len(procs),
            "suspicious": [p["name"] for p in sus],
        }

    # ── debugger ──────────────────────────────────────────
    if do_all or args.debug_only:
        dbg = run_debugger_checks()
        print_debugger_results(dbg)
        report["debugger"] = dbg

    # ── VM ────────────────────────────────────────────────
    if do_all or args.vm_only:
        vm = run_vm_checks()
        print_vm_results(vm)
        report["vm"] = vm

    # ── JSON output ───────────────────────────────────────
    if args.output:
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2, default=str)
        print(c(f"  ✔ Report saved → {args.output}", GREEN))
        print()

if __name__ == "__main__":
    main()