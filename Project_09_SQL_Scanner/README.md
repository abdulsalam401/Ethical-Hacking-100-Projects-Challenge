# 🛠️ Blind SQL Injection Scanner & Automated Data Extractor

This project is part of the **[Ethical-Hacking-100-Projects-Challenge](https://github.com/abdulsalam401/Ethical-Hacking-100-Projects-Challenge)** challenge. It is an educational utility designed to study cybersecurity concepts, network protocols, and system defenses.

---

## 📌 Project Overview
A web vulnerability scanner specialized in detecting and exploiting SQL Injection. It tests input parameters with structural True/False payloads, identifies vulnerabilities through response-length differentials, and automatically extracts backend database names character-by-character.

### ⚙️ Specifications & Tech Stack
- **Category:** Ethical Hacking / Cyber Security Lab
- **Language:** Python / C (where applicable)
- **Tech Stack:** `Python 3`, `requests`, `SQLite3`, `Flask (for test lab)`
- **Prerequisites:** `requests`, `flask (for vulnerable app)`

---

## 🚀 Key Features
- Error-based and Blind Boolean SQL injection detection routines.
- Automated character extraction: character-by-character database name inference.
- Dynamic URL encoding to preserve complex structures inside target query strings.
- Built-in vulnerable web server (`vulnerable_app.py`) using SQLite for offline test validation.
- Baseline profiling to establish normal page conditions before injecting payloads.

---

## 📖 Installation & Usage

### 1. Install Dependencies
Make sure you have Python 3 and the required libraries installed:
```bash
pip install -r requirements.txt
```
*(If a local `requirements.txt` is not present, install manually using `pip install requests flask (for vulnerable app)`)*

### 2. Execution Commands
Choose the command depending on your operating system:

**Windows Command Prompt / PowerShell:**
```cmd
python sql_scanner.py
```

**Linux / macOS Terminal:**
```bash
python3 sql_scanner.py
```

*Note: Some projects require administrative privileges (root/sudo) to bind to raw sockets, monitor network interfaces, or intercept system APIs.*

---

## ⚠️ Legal & Ethical Disclaimer
> **IMPORTANT WARNING:** This tool is created strictly for educational, defensive, and authorized security auditing purposes. Testing web applications for SQL Injection without explicit written consent is illegal. Do not scan websites you do not own. The developer (**Abdul Salam**) assumes no liability for misuse, damage, or legal consequences resulting from the deployment of this tool.

---

## 👤 Developer Profile
- **Developer:** [Abdul Salam](https://salamcs.app)
- **GitHub:** [salam.cyber1](https://github.com/abdulsalam401)
- **LinkedIn:** [Abdul Salam](https://www.linkedin.com/in/abdul-salam-39467a274)
- **Portfolio:** [salamcs.app](https://salamcs.app)
