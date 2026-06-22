# 🛠️ Asynchronous Multi-Threaded Web Directory Crawler

This project is part of the **[Ethical-Hacking-100-Projects-Challenge](https://github.com/abdulsalam401/Ethical-Hacking-100-Projects-Challenge)** challenge. It is an educational utility designed to study cybersecurity concepts, network protocols, and system defenses.

---

## 📌 Project Overview
A high-performance directory discovery and web crawler tool. It uses thread pooling to concurrently request pages, parses `robots.txt` instructions, and tests target directories using a built-in common endpoint dictionary to map out target web structures.

### ⚙️ Specifications & Tech Stack
- **Category:** Ethical Hacking / Cyber Security Lab
- **Language:** Python / C (where applicable)
- **Tech Stack:** `Python 3`, `requests`, `ThreadPoolExecutor`, `BeautifulSoup4 (optional)`
- **Prerequisites:** `requests`, `urllib3`

---

## 🚀 Key Features
- Asynchronous crawling using Python's ThreadPoolExecutor.
- Built-in wordlist of 60 common sensitive directories (e.g., admin, backup, config).
- Automatic parsing and compliance validation against target `robots.txt` files.
- Detailed HTML report output (`project6_crawler_report.html`) summarizing discovery details.
- HTTP response status-code filtering and colorized CLI reporting.

---

## 📖 Installation & Usage

### 1. Install Dependencies
Make sure you have Python 3 and the required libraries installed:
```bash
pip install -r requirements.txt
```
*(If a local `requirements.txt` is not present, install manually using `pip install requests urllib3`)*

### 2. Execution Commands
Choose the command depending on your operating system:

**Windows Command Prompt / PowerShell:**
```cmd
python crawler.py
```

**Linux / macOS Terminal:**
```bash
python3 crawler.py
```

*Note: Some projects require administrative privileges (root/sudo) to bind to raw sockets, monitor network interfaces, or intercept system APIs.*

---

## ⚠️ Legal & Ethical Disclaimer
> **IMPORTANT WARNING:** This tool is created strictly for educational, defensive, and authorized security auditing purposes. Ensure you have authorization to crawl target websites. Aggressive crawling can trigger Denials of Service (DoS) or alert Web Application Firewalls. Crawl responsibly. The developer (**Abdul Salam**) assumes no liability for misuse, damage, or legal consequences resulting from the deployment of this tool.

---

## 👤 Developer Profile
- **Developer:** [Abdul Salam](https://salamcs.app)
- **GitHub:** [salam.cyber1](https://github.com/abdulsalam401)
- **LinkedIn:** [Abdul Salam](https://www.linkedin.com/in/abdul-salam-39467a274)
- **Portfolio:** [salamcs.app](https://salamcs.app)
