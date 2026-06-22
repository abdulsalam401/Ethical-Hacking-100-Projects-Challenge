# 🛠️ SSL-Encrypted Interactive TTY Reverse Shell

This project is part of the **[Ethical-Hacking-100-Projects-Challenge](https://github.com/abdulsalam401/Ethical-Hacking-100-Projects-Challenge)** challenge. It is an educational utility designed to study cybersecurity concepts, network protocols, and system defenses.

---

## 📌 Project Overview
An advanced command-and-control client and server. It uses SSL/TLS wrapper sockets to secure network traffic, allocates a full pseudo-terminal (PTY) interface for interactive shell control on Unix, and includes a custom packet protocol for uploading and downloading files.

### ⚙️ Specifications & Tech Stack
- **Category:** Ethical Hacking / Cyber Security Lab
- **Language:** Python / C (where applicable)
- **Tech Stack:** `Python 3`, `ssl`, `socket`, `pty`, `subprocess`
- **Prerequisites:** `None (Uses standard libraries; self-signed certificates needed)`

---

## 🚀 Key Features
- Encrypted transport: wraps connection sockets in SSL/TLS.
- Interactive TTY: allocates a pseudo-terminal on Unix-based clients for commands like `top` or `nano`.
- Integrated file transfer: custom framing to upload and download files.
- Address reuse configuration to prevent binding errors on server restart.
- Automatic certificate validation fallback.

---

## 📖 Installation & Usage

### 1. Install Dependencies
Make sure you have Python 3 and the required libraries installed:
```bash
pip install -r requirements.txt
```
*(If a local `requirements.txt` is not present, install manually using `pip install None (Uses standard libraries; self-signed certificates needed)`)*

### 2. Execution Commands
Choose the command depending on your operating system:

**Windows Command Prompt / PowerShell:**
```cmd
python reverse_server.py  (or client)
```

**Linux / macOS Terminal:**
```bash
python3 reverse_server.py  (or client)
```

*Note: Some projects require administrative privileges (root/sudo) to bind to raw sockets, monitor network interfaces, or intercept system APIs.*

---

## ⚠️ Legal & Ethical Disclaimer
> **IMPORTANT WARNING:** This tool is created strictly for educational, defensive, and authorized security auditing purposes. Reverse shells that bypass network perimeters can be dangerous. Use this tool only inside authorized penetration testing environments. The developer (**Abdul Salam**) assumes no liability for misuse, damage, or legal consequences resulting from the deployment of this tool.

---

## 👤 Developer Profile
- **Developer:** [Abdul Salam](https://salamcs.app)
- **GitHub:** [salam.cyber1](https://github.com/abdulsalam401)
- **LinkedIn:** [Abdul Salam](https://www.linkedin.com/in/abdul-salam-39467a274)
- **Portfolio:** [salamcs.app](https://salamcs.app)
