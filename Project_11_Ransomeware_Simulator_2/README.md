# 🛠️ Advanced Ransomware Simulator with Safety Guards

This project is part of the **[Ethical-Hacking-100-Projects-Challenge](https://github.com/abdulsalam401/Ethical-Hacking-100-Projects-Challenge)** challenge. It is an educational utility designed to study cybersecurity concepts, network protocols, and system defenses.

---

## 📌 Project Overview
An advanced ransomware simulation environment. It includes rigorous safety checks (such as blocking root/home directories and requiring a custom path keyword) to prevent accidental data loss, encrypts a mock laboratory directory, generates ransom notes, and includes a full restoration decryptor.

### ⚙️ Specifications & Tech Stack
- **Category:** Ethical Hacking / Cyber Security Lab
- **Language:** Python / C (where applicable)
- **Tech Stack:** `Python 3`, `cryptography`, `json`, `os`
- **Prerequisites:** `cryptography`

---

## 🚀 Key Features
- Strict Safety Guards: will not encrypt directories unless they match a designated sandbox path and contain safety keywords.
- Recursive file discovery and Fernet-based symmetric encryption.
- Ransom note generation (`RESTORE_FILES_INFO.txt`) and encryption key management.
- File restoration script (`ransom_decrypt.py`) to reverse the encryption.
- Pre-checks to isolate execution within target folders and avoid system drives.

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
python ransom_sim.py
```

**Linux / macOS Terminal:**
```bash
python3 ransom_sim.py
```

*Note: Some projects require administrative privileges (root/sudo) to bind to raw sockets, monitor network interfaces, or intercept system APIs.*

---

## ⚠️ Legal & Ethical Disclaimer
> **IMPORTANT WARNING:** This tool is created strictly for educational, defensive, and authorized security auditing purposes. This simulator contains strict directory guard rails. Running ransomware simulations should only be done within dedicated virtual machines or isolated sandboxes. The developer (**Abdul Salam**) assumes no liability for misuse, damage, or legal consequences resulting from the deployment of this tool.

---

## 👤 Developer Profile
- **Developer:** [Abdul Salam](https://salamcs.app)
- **GitHub:** [salam.cyber1](https://github.com/abdulsalam401)
- **LinkedIn:** [Abdul Salam](https://www.linkedin.com/in/abdul-salam-39467a274)
- **Portfolio:** [salamcs.app](https://salamcs.app)
