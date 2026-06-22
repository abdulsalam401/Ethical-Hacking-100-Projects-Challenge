# 🛠️ Real-Time File Integrity Monitor (FIM)

This project is part of the **[Ethical-Hacking-100-Projects-Challenge](https://github.com/abdulsalam401/Ethical-Hacking-100-Projects-Challenge)** challenge. It is an educational utility designed to study cybersecurity concepts, network protocols, and system defenses.

---

## 📌 Project Overview
A file integrity monitor. It calculates cryptographic hashes of target directories, monitors files for modifications, creations, or deletions, and outputs alerts to the console and detailed HTML logs.

### ⚙️ Specifications & Tech Stack
- **Category:** Ethical Hacking / Cyber Security Lab
- **Language:** Python / C (where applicable)
- **Tech Stack:** `Python 3`, `hashlib`, `json`, `time`, `colorama`
- **Prerequisites:** `colorama`

---

## 🚀 Key Features
- Generates baseline SHA-256 hashes of all files in a target directory.
- Real-time monitoring: detects modifications, creations, deletions, and metadata changes.
- Generates structured HTML integrity alerts.
- Saves configuration baselines to JSON files (`baseline.json`).

---

## 📖 Installation & Usage

### 1. Install Dependencies
Make sure you have Python 3 and the required libraries installed:
```bash
pip install -r requirements.txt
```
*(If a local `requirements.txt` is not present, install manually using `pip install colorama`)*

### 2. Execution Commands
Choose the command depending on your operating system:

**Windows Command Prompt / PowerShell:**
```cmd
python fim.py
```

**Linux / macOS Terminal:**
```bash
python3 fim.py
```

*Note: Some projects require administrative privileges (root/sudo) to bind to raw sockets, monitor network interfaces, or intercept system APIs.*

---

## ⚠️ Legal & Ethical Disclaimer
> **IMPORTANT WARNING:** This tool is created strictly for educational, defensive, and authorized security auditing purposes. FIMs are essential defensive tools used to protect system configurations and detect unauthorized modifications. Ensure target directories are configured correctly. The developer (**Abdul Salam**) assumes no liability for misuse, damage, or legal consequences resulting from the deployment of this tool.

---

## 👤 Developer Profile
- **Developer:** [Abdul Salam](https://salamcs.app)
- **GitHub:** [salam.cyber1](https://github.com/abdulsalam401)
- **LinkedIn:** [Abdul Salam](https://www.linkedin.com/in/abdul-salam-39467a274)
- **Portfolio:** [salamcs.app](https://salamcs.app)
