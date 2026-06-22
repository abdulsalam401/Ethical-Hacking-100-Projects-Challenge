# 🛠️ Ransomware Encryption Simulator Lab

This project is part of the **[Ethical-Hacking-100-Projects-Challenge](https://github.com/abdulsalam401/Ethical-Hacking-100-Projects-Challenge)** challenge. It is an educational utility designed to study cybersecurity concepts, network protocols, and system defenses.

---

## 📌 Project Overview
An educational demonstration of cryptographic file locking and unlocking. It simulates file encryption processes by generating a local key, locking files, and providing a decryption script to restore them, illustrating ransomware mechanics.

### ⚙️ Specifications & Tech Stack
- **Category:** Ethical Hacking / Cyber Security Lab
- **Language:** Python / C (where applicable)
- **Tech Stack:** `Python 3`, `cryptography (cryptography.fernet)`
- **Prerequisites:** `cryptography`

---

## 🚀 Key Features
- Cryptographic file locking mechanisms using symmetric keys.
- Clear directory targeting: searches a specified local directory.
- Decryptor utility (`ransom_decrypt.py`) to fully restore encrypted files.
- Educational layout focusing on malware analysis, file structure alteration, and key recovery.

---

## 📖 Installation & Usage

### 1. Install Dependencies
Make sure you have Python 3 and the required libraries installed:
```bash
pip install -r requirements.txt
```
*(If a local `requirements.txt` is not present, install manually using `pip install cryptography`)*

### 2. Execution Commands
Choose the command depending on your operating system:

**Windows Command Prompt / PowerShell:**
```cmd
python ransom_decrypt.py
```

**Linux / macOS Terminal:**
```bash
python3 ransom_decrypt.py
```

*Note: Some projects require administrative privileges (root/sudo) to bind to raw sockets, monitor network interfaces, or intercept system APIs.*

---

## ⚠️ Legal & Ethical Disclaimer
> **IMPORTANT WARNING:** This tool is created strictly for educational, defensive, and authorized security auditing purposes. This is a basic simulator. Never attempt to run ransomware-like utilities in production or against directories that do not contain dedicated test dummy files. The developer (**Abdul Salam**) assumes no liability for misuse, damage, or legal consequences resulting from the deployment of this tool.

---

## 👤 Developer Profile
- **Developer:** [Abdul Salam](https://salamcs.app)
- **GitHub:** [salam.cyber1](https://github.com/abdulsalam401)
- **LinkedIn:** [Abdul Salam](https://www.linkedin.com/in/abdul-salam-39467a274)
- **Portfolio:** [salamcs.app](https://salamcs.app)
