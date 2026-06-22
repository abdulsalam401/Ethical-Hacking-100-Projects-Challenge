# 🛠️ Stealth Keylogger with XOR Encryption & Anti-Detection

This project is part of the **[Ethical-Hacking-100-Projects-Challenge](https://github.com/abdulsalam401/Ethical-Hacking-100-Projects-Challenge)** challenge. It is an educational utility designed to study cybersecurity concepts, network protocols, and system defenses.

---

## 📌 Project Overview
A security research keylogger designed to demonstrate keyboard telemetry logging. It logs keystrokes in a background thread, encrypts the logged data using a symmetric XOR key, and implements process-name spoofing on Linux and cosmetic title spoofing on Windows.

### ⚙️ Specifications & Tech Stack
- **Category:** Ethical Hacking / Cyber Security Lab
- **Language:** Python / C (where applicable)
- **Tech Stack:** `Python 3`, `pynput`, `ctypes`, `XOR Cryptography`
- **Prerequisites:** `pynput`

---

## 🚀 Key Features
- Background thread key event logging using the pynput library.
- Real-time symmetric XOR encryption of log entries before writing to disk.
- Anti-detection process spoofing (overwriting `/proc/self/comm` on Linux) to mask keylogger presence.
- Cosmetic terminal window renaming on Windows to blend into standard services.
- Decoder scripts to decrypt the encrypted logs using the symmetric XOR key.

---

## 📖 Installation & Usage

### 1. Install Dependencies
Make sure you have Python 3 and the required libraries installed:
```bash
pip install -r requirements.txt
```
*(If a local `requirements.txt` is not present, install manually using `pip install pynput`)*

### 2. Execution Commands
Choose the command depending on your operating system:

**Windows Command Prompt / PowerShell:**
```cmd
python keylogger.py
```

**Linux / macOS Terminal:**
```bash
python3 keylogger.py
```

*Note: Some projects require administrative privileges (root/sudo) to bind to raw sockets, monitor network interfaces, or intercept system APIs.*

---

## ⚠️ Legal & Ethical Disclaimer
> **IMPORTANT WARNING:** This tool is created strictly for educational, defensive, and authorized security auditing purposes. Keyloggers must only be deployed on systems you own or have explicit written consent to monitor. Unauthorized installation of keyloggers is highly illegal and categorized as spyware. The developer (**Abdul Salam**) assumes no liability for misuse, damage, or legal consequences resulting from the deployment of this tool.

---

## 👤 Developer Profile
- **Developer:** [Abdul Salam](https://salamcs.app)
- **GitHub:** [salam.cyber1](https://github.com/abdulsalam401)
- **LinkedIn:** [Abdul Salam](https://www.linkedin.com/in/abdul-salam-39467a274)
- **Portfolio:** [salamcs.app](https://salamcs.app)
