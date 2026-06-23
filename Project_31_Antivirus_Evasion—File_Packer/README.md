# 🛠️ Antivirus Evasion & Crypter File Packer

This project is part of the **[Ethical-Hacking-100-Projects-Challenge](https://github.com/abdulsalam401/Ethical-Hacking-100-Projects-Challenge)** challenge. It is an educational utility designed to study antivirus evasion techniques, binary obfuscation, runtime decryption stubs, and process debugging protections.

---

## 📌 Project Overview
An educational crypter / file packer utility that packages compiled binaries or scripts inside a secure, self-extracting, and executing Python stub. The tool encrypts the target binary using AES-128 (Fernet), obfuscates the payload using Base64 encoding, and incorporates runtime anti-debugging checks to block static signature analysis and runtime debugger analysis.

### ⚙️ Specifications & Tech Stack
- **Category:** Ethical Hacking / Malware Analysis & Evasion Lab
- **Language:** Python 3 / C (for test payloads)
- **Tech Stack:** `Python 3`, `cryptography (Fernet)`, `base64`, `tempfile`, `subprocess`, `ctypes`
- **Prerequisites:** `cryptography`

---

## 🚀 Key Features
- **Symmetric Encryption (AES):** Secures target payloads using Fernet symmetric encryption keys.
- **Embedded Python Stub:** Packs the encrypted payload and key directly inside a generated Python wrapper script.
- **Anti-Debugging Guards:** 
  - *Windows:* Checks the Process Environment Block (PEB) via `kernel32.IsDebuggerPresent` to detect active debuggers.
  - *Linux:* Checks the active process tree (`ps aux`) for known analysis and debugging tools (`gdb`, `lldb`, `strace`, `ltrace`, `valgrind`).
- **Secure Runtime Execution:** Decrypts the binary at runtime into a temporary executable (`.exe` or `.elf`), executes it as a subprocess, and immediately deletes it from disk to minimize forensics footprints.

---

## 📖 Installation & Usage

### 1. Install Dependencies
Ensure you have the required cryptographic library installed:
```bash
pip install cryptography
```

### 2. Execution Commands
To pack a compiled executable (e.g., a test program compiled from `test.c`):

**Windows Command Prompt / PowerShell:**
```cmd
python packer.py --input test.exe --output packed_test.py
```

**Linux / macOS Terminal:**
```bash
python3 packer.py --input test --output packed_test.py
```

### 3. Running the Packed Executable
Run the generated Python stub script:
```bash
python3 packed_test.py
```
*Note: If a debugger or tracking tool is active, the script will detect it and exit before decrypting the payload.*

---

## ⚠️ Legal & Ethical Disclaimer
> **IMPORTANT WARNING:** This tool is created strictly for educational, defensive research, and authorized security auditing purposes. Packaging malware to bypass signature scanners in unauthorized environments is illegal. The developer (**Abdul Salam**) assumes no liability for misuse, damage, or legal consequences resulting from the deployment of this tool.

---

## 👤 Developer Profile
- **Developer:** [Abdul Salam](https://salamcs.app)
- **GitHub:** [salam.cyber1](https://github.com/abdulsalam401)
- **LinkedIn:** [Abdul Salam](https://www.linkedin.com/in/abdul-salam-39467a274)
- **Portfolio:** [salamcs.app](https://salamcs.app)
