# 🛠️ Reverse Proxy Web Application Firewall (WAF)

This project is part of the **[Ethical-Hacking-100-Projects-Challenge](https://github.com/abdulsalam401/Ethical-Hacking-100-Projects-Challenge)** challenge. It is an educational utility designed to study cybersecurity concepts, network protocols, and system defenses.

---

## 📌 Project Overview
An inline reverse proxy Web Application Firewall. It intercepts HTTP requests, evaluates them against rules to block SQLi, XSS, and path traversal, and enforces client rate limits, logging blocked requests with a custom block page.

### ⚙️ Specifications & Tech Stack
- **Category:** Ethical Hacking / Cyber Security Lab
- **Language:** Python / C (where applicable)
- **Tech Stack:** `Python 3`, `http.server`, `urllib.parse`, `json`, `time`
- **Prerequisites:** `colorama`

---

## 🚀 Key Features
- Reverse proxy architecture: intercepts and routes HTTP requests.
- Signature engine: blocks payloads matching SQLi, XSS, and path traversal patterns.
- Client rate-limiting: tracks IP request rates and blocks clients exceeding limits.
- Customizable rules template (`waf_rules.json`).
- Saves blocked events to WAF activity logs.

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
python waf_proxy.py
```

**Linux / macOS Terminal:**
```bash
python3 waf_proxy.py
```

*Note: Some projects require administrative privileges (root/sudo) to bind to raw sockets, monitor network interfaces, or intercept system APIs.*

---

## ⚠️ Legal & Ethical Disclaimer
> **IMPORTANT WARNING:** This tool is created strictly for educational, defensive, and authorized security auditing purposes. WAFs are standard defensive tools. Ensure proxy ports are properly secured and configured within your network lab. The developer (**Abdul Salam**) assumes no liability for misuse, damage, or legal consequences resulting from the deployment of this tool.

---

## 👤 Developer Profile
- **Developer:** [Abdul Salam](https://salamcs.app)
- **GitHub:** [salam.cyber1](https://github.com/abdulsalam401)
- **LinkedIn:** [Abdul Salam](https://www.linkedin.com/in/abdul-salam-39467a274)
- **Portfolio:** [salamcs.app](https://salamcs.app)
