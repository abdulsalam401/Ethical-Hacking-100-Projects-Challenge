# 🛠️ Log Analyzer & SIEM Alert Simulator

This project is part of the **[Ethical-Hacking-100-Projects-Challenge](https://github.com/abdulsalam401/Ethical-Hacking-100-Projects-Challenge)** challenge. It is an educational utility designed to study cybersecurity concepts, network protocols, and system defenses.

---

## 📌 Project Overview
A Security Information and Event Management (SIEM) simulator. It parses web server access logs (like Apache/Nginx formats), evaluates requests against detection rules, and outputs colorized alerts for SQLi, XSS, and brute force attacks based on access thresholds.

### ⚙️ Specifications & Tech Stack
- **Category:** Ethical Hacking / Cyber Security Lab
- **Language:** Python / C (where applicable)
- **Tech Stack:** `Python 3`, `json`, `colorama`, `re`, `time`
- **Prerequisites:** `colorama`

---

## 🚀 Key Features
- Parses standard web server access logs in real-time.
- Threshold-based brute force detection (e.g. triggers alerts if more than 5 failed logins occur within 10 seconds).
- Regex-based detection rules for SQLi and XSS payloads.
- Outputs alerts sorted by severity (HIGH, MEDIUM, LOW) to help analysts prioritize.
- Customizable detection rules JSON template (`rules.json`).

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
python log_analyzer.py
```

**Linux / macOS Terminal:**
```bash
python3 log_analyzer.py
```

*Note: Some projects require administrative privileges (root/sudo) to bind to raw sockets, monitor network interfaces, or intercept system APIs.*

---

## ⚠️ Legal & Ethical Disclaimer
> **IMPORTANT WARNING:** This tool is created strictly for educational, defensive, and authorized security auditing purposes. This SIEM simulator is defensive, designed to help developers and analysts practice log monitoring and rule tuning. The developer (**Abdul Salam**) assumes no liability for misuse, damage, or legal consequences resulting from the deployment of this tool.

---

## 👤 Developer Profile
- **Developer:** [Abdul Salam](https://salamcs.app)
- **GitHub:** [salam.cyber1](https://github.com/abdulsalam401)
- **LinkedIn:** [Abdul Salam](https://www.linkedin.com/in/abdul-salam-39467a274)
- **Portfolio:** [salamcs.app](https://salamcs.app)
