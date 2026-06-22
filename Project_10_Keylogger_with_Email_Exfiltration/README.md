# 🛠️ Keylogger with Clipboard Capture & SMTP Exfiltration

This project is part of the **[Ethical-Hacking-100-Projects-Challenge](https://github.com/abdulsalam401/Ethical-Hacking-100-Projects-Challenge)** challenge. It is an educational utility designed to study cybersecurity concepts, network protocols, and system defenses.

---

## 📌 Project Overview
An advanced security telemetry simulator. It records target keystrokes and monitors clipboard modifications, encrypts/obfuscates the gathered telemetry using XOR + Base64, and exfiltrates the logs over secure TLS-encrypted SMTP mail using non-blocking worker threads.

### ⚙️ Specifications & Tech Stack
- **Category:** Ethical Hacking / Cyber Security Lab
- **Language:** Python / C (where applicable)
- **Tech Stack:** `Python 3`, `pynput`, `smtplib`, `threading`, `base64`
- **Prerequisites:** `pynput`, `pyperclip`

---

## 🚀 Key Features
- Keystroke tracking with concurrent clipboard polling via background threads.
- Telemetry obfuscation using symmetric XOR keys followed by Base64 encoding.
- Automatic periodic email exfiltration over secure SMTP (TLS).
- Emergency local backup cache if SMTP connection fails, to avoid data loss.
- Self-destruct module that wipes logs and exits via hotkey (e.g., F9).

---

## 📖 Installation & Usage

### 1. Install Dependencies
Make sure you have Python 3 and the required libraries installed:
```bash
pip install -r requirements.txt
```
*(If a local `requirements.txt` is not present, install manually using `pip install pynput pyperclip`)*

### 2. Execution Commands
Choose the command depending on your operating system:

**Windows Command Prompt / PowerShell:**
```cmd
python keylogger_email.py
```

**Linux / macOS Terminal:**
```bash
python3 keylogger_email.py
```

*Note: Some projects require administrative privileges (root/sudo) to bind to raw sockets, monitor network interfaces, or intercept system APIs.*

---

## ⚠️ Legal & Ethical Disclaimer
> **IMPORTANT WARNING:** This tool is created strictly for educational, defensive, and authorized security auditing purposes. Exfiltrating system activity logs to external servers without consent constitutes spyware/malware behavior. Use only for authorized security simulations. The developer (**Abdul Salam**) assumes no liability for misuse, damage, or legal consequences resulting from the deployment of this tool.

---

## 👤 Developer Profile
- **Developer:** [Abdul Salam](https://salamcs.app)
- **GitHub:** [salam.cyber1](https://github.com/abdulsalam401)
- **LinkedIn:** [Abdul Salam](https://www.linkedin.com/in/abdul-salam-39467a274)
- **Portfolio:** [salamcs.app](https://salamcs.app)
