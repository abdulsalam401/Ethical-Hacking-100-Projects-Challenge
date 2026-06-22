# 🛠️ FTP Credential Cracker with Jitter & Horizontal Spraying

This project is part of the **[Ethical-Hacking-100-Projects-Challenge](https://github.com/abdulsalam401/Ethical-Hacking-100-Projects-Challenge)** challenge. It is an educational utility designed to study cybersecurity concepts, network protocols, and system defenses.

---

## 📌 Project Overview
A security auditing tool designed to test the strength of FTP credentials. It features a built-in dictionary and implements horizontal spraying (testing a single password across all accounts first) and randomized credential-jitter delays to evade simple detection thresholds.

### ⚙️ Specifications & Tech Stack
- **Category:** Ethical Hacking / Cyber Security Lab
- **Language:** Python / C (where applicable)
- **Tech Stack:** `Python 3`, `ftplib`, `random`, `time`
- **Prerequisites:** `None (Standard library ftplib)`

---

## 🚀 Key Features
- Horizontal spraying algorithm to prevent account lockouts on single accounts.
- Jitter engine adding random time-delays (e.g., 0.2 to 1.8 seconds) between login attempts.
- Built-in dictionary generator containing blank, numeric, and username-substituted values.
- Detailed auditing reports documenting credential hits and connection statuses.
- Socket-level verification prior to scanning to verify host availability.

---

## 📖 Installation & Usage

### 1. Install Dependencies
Make sure you have Python 3 and the required libraries installed:
```bash
pip install -r requirements.txt
```
*(If a local `requirements.txt` is not present, install manually using `pip install None (Standard library ftplib)`)*

### 2. Execution Commands
Choose the command depending on your operating system:

**Windows Command Prompt / PowerShell:**
```cmd
python ftpcracker.py
```

**Linux / macOS Terminal:**
```bash
python3 ftpcracker.py
```

*Note: Some projects require administrative privileges (root/sudo) to bind to raw sockets, monitor network interfaces, or intercept system APIs.*

---

## ⚠️ Legal & Ethical Disclaimer
> **IMPORTANT WARNING:** This tool is created strictly for educational, defensive, and authorized security auditing purposes. Brute-forcing or credential-stuffing FTP servers without authorization is illegal. Use this tool only on servers configured inside your local penetration testing lab. The developer (**Abdul Salam**) assumes no liability for misuse, damage, or legal consequences resulting from the deployment of this tool.

---

## 👤 Developer Profile
- **Developer:** [Abdul Salam](https://salamcs.app)
- **GitHub:** [salam.cyber1](https://github.com/abdulsalam401)
- **LinkedIn:** [Abdul Salam](https://www.linkedin.com/in/abdul-salam-39467a274)
- **Portfolio:** [salamcs.app](https://salamcs.app)
