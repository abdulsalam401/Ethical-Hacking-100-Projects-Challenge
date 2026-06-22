# 🛠️ SSH Credential Auditor with Transport Pooling

This project is part of the **[Ethical-Hacking-100-Projects-Challenge](https://github.com/abdulsalam401/Ethical-Hacking-100-Projects-Challenge)** challenge. It is an educational utility designed to study cybersecurity concepts, network protocols, and system defenses.

---

## 📌 Project Overview
An SSH credential strength auditor utilizing the Paramiko library. It optimizes performance by implementing SSH Connection Transport Pooling (reusing a single transport stream for multiple password attempts) and supports public-key credentials.

### ⚙️ Specifications & Tech Stack
- **Category:** Ethical Hacking / Cyber Security Lab
- **Language:** Python / C (where applicable)
- **Tech Stack:** `Python 3`, `Paramiko`, `Socket`, `colorama`
- **Prerequisites:** `paramiko`, `colorama`

---

## 🚀 Key Features
- SSH connection pooling: cycle SSH transport layers every 3 attempts to speed up testing.
- Credential testing using password dictionaries or private key files.
- Automatic banner grabbing on target SSH socket interfaces.
- Suppression of system library warning logs to maintain console clarity.
- Accurate socket timeout handling to detect dropped connections.

---

## 📖 Installation & Usage

### 1. Install Dependencies
Make sure you have Python 3 and the required libraries installed:
```bash
pip install -r requirements.txt
```
*(If a local `requirements.txt` is not present, install manually using `pip install paramiko colorama`)*

### 2. Execution Commands
Choose the command depending on your operating system:

**Windows Command Prompt / PowerShell:**
```cmd
python ssh_cracker.py
```

**Linux / macOS Terminal:**
```bash
python3 ssh_cracker.py
```

*Note: Some projects require administrative privileges (root/sudo) to bind to raw sockets, monitor network interfaces, or intercept system APIs.*

---

## ⚠️ Legal & Ethical Disclaimer
> **IMPORTANT WARNING:** This tool is created strictly for educational, defensive, and authorized security auditing purposes. Scanning and cracking SSH interfaces is highly intrusive. Ensure you have explicitly authorized permission before auditing remote authentication endpoints. The developer (**Abdul Salam**) assumes no liability for misuse, damage, or legal consequences resulting from the deployment of this tool.

---

## 👤 Developer Profile
- **Developer:** [Abdul Salam](https://salamcs.app)
- **GitHub:** [salam.cyber1](https://github.com/abdulsalam401)
- **LinkedIn:** [Abdul Salam](https://www.linkedin.com/in/abdul-salam-39467a274)
- **Portfolio:** [salamcs.app](https://salamcs.app)
