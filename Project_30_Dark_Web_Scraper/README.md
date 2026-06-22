# 🛠️ Tor-Routed Dark Web Intelligence Scraper

This project is part of the **[Ethical-Hacking-100-Projects-Challenge](https://github.com/abdulsalam401/Ethical-Hacking-100-Projects-Challenge)** challenge. It is an educational utility designed to study cybersecurity concepts, network protocols, and system defenses.

---

## 📌 Project Overview
A threat intelligence scraper that routes requests through the local Tor network SOCKS5 proxy to search onion sites for keywords and compile results into HTML reports.

### ⚙️ Specifications & Tech Stack
- **Category:** Ethical Hacking / Cyber Security Lab
- **Language:** Python / C (where applicable)
- **Tech Stack:** `Python 3`, `requests`, `Tor SOCKS5 proxy`, `re`, `time`
- **Prerequisites:** `requests[socks]`, `colorama (Tor service must be running locally on 9050)`

---

## 🚀 Key Features
- Tor routing: routes all requests through the local Tor SOCKS5 daemon proxy.
- Keyword searching: scans onion pages for target threat keywords.
- Tor status verification checks prior to scanning.
- Outputs threat intelligence summaries in HTML reports.

---

## 📖 Installation & Usage

### 1. Install Dependencies
Make sure you have Python 3 and the required libraries installed:
```bash
pip install -r requirements.txt
```
*(If a local `requirements.txt` is not present, install manually using `pip install requests[socks] colorama (Tor service must be running locally on 9050)`)*

### 2. Execution Commands
Choose the command depending on your operating system:

**Windows Command Prompt / PowerShell:**
```cmd
python dark_scraper.py
```

**Linux / macOS Terminal:**
```bash
python3 dark_scraper.py
```

*Note: Some projects require administrative privileges (root/sudo) to bind to raw sockets, monitor network interfaces, or intercept system APIs.*

---

## ⚠️ Legal & Ethical Disclaimer
> **IMPORTANT WARNING:** This tool is created strictly for educational, defensive, and authorized security auditing purposes. Scraping onion sites should only be done for threat intelligence research. Always route requests securely and do not request illegal content. The developer (**Abdul Salam**) assumes no liability for misuse, damage, or legal consequences resulting from the deployment of this tool.

---

## 👤 Developer Profile
- **Developer:** [Abdul Salam](https://salamcs.app)
- **GitHub:** [salam.cyber1](https://github.com/abdulsalam401)
- **LinkedIn:** [Abdul Salam](https://www.linkedin.com/in/abdul-salam-39467a274)
- **Portfolio:** [salamcs.app](https://salamcs.app)
