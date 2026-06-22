# 🛠️ Remote Access Trojan (RAT) Simulator & C2 Dashboard

This project is part of the **[Ethical-Hacking-100-Projects-Challenge](https://github.com/abdulsalam401/Ethical-Hacking-100-Projects-Challenge)** challenge. It is an educational utility designed to study cybersecurity concepts, network protocols, and system defenses.

---

## 📌 Project Overview
A remote access tool simulation. It contains a secure TLS-encrypted agent (`rat_client.py`) and a Flask-based command-and-control server (`rat_server2.py`) with a web dashboard to issue commands and manage active agents.

### ⚙️ Specifications & Tech Stack
- **Category:** Ethical Hacking / Cyber Security Lab
- **Language:** Python / C (where applicable)
- **Tech Stack:** `Python 3`, `Flask`, `ssl`, `socket`, `threading`
- **Prerequisites:** `flask`, `colorama`

---

## 🚀 Key Features
- Secure communications: wraps client-server sockets in TLS/SSL.
- Web-based C2 Dashboard: Flask application to manage active agents and view system details.
- Remote command execution: executes commands on clients and returns results.
- Support for multiple concurrent agent connections.

---

## 📖 Installation & Usage

### 1. Install Dependencies
Make sure you have Python 3 and the required libraries installed:
```bash
pip install -r requirements.txt
```
*(If a local `requirements.txt` is not present, install manually using `pip install flask colorama`)*

### 2. Execution Commands
Choose the command depending on your operating system:

**Windows Command Prompt / PowerShell:**
```cmd
python rat_server2.py  (then in another terminal) python rat_client2.py
```

**Linux / macOS Terminal:**
```bash
python3 rat_server2.py (then in another terminal) python3 rat_client2.py
```

*Note: Some projects require administrative privileges (root/sudo) to bind to raw sockets, monitor network interfaces, or intercept system APIs.*

---

## ⚠️ Legal & Ethical Disclaimer
> **IMPORTANT WARNING:** This tool is created strictly for educational, defensive, and authorized security auditing purposes. RAT simulators are designed to study malware behavior and defense strategies. Running unauthorized remote agents is highly illegal. The developer (**Abdul Salam**) assumes no liability for misuse, damage, or legal consequences resulting from the deployment of this tool.

---

## 👤 Developer Profile
- **Developer:** [Abdul Salam](https://salamcs.app)
- **GitHub:** [salam.cyber1](https://github.com/abdulsalam401)
- **LinkedIn:** [Abdul Salam](https://www.linkedin.com/in/abdul-salam-39467a274)
- **Portfolio:** [salamcs.app](https://salamcs.app)
