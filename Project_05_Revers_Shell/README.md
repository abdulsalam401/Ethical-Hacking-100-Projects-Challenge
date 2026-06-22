# 🛠️ AES-Encrypted Reverse Shell with Tkinter C2 Visualizer

This project is part of the **[Ethical-Hacking-100-Projects-Challenge](https://github.com/abdulsalam401/Ethical-Hacking-100-Projects-Challenge)** challenge. It is an educational utility designed to study cybersecurity concepts, network protocols, and system defenses.

---

## 📌 Project Overview
A secure, encrypted Command and Control (C2) reverse shell simulation. It uses AES encryption in CBC mode to secure communications between the target agent and the listener. It also features a Tkinter GUI that visually explains the C2 handshake, command execution, and encryption workflows.

### ⚙️ Specifications & Tech Stack
- **Category:** Ethical Hacking / Cyber Security Lab
- **Language:** Python / C (where applicable)
- **Tech Stack:** `Python 3`, `pycryptodome`, `Socket`, `Tkinter / Customtkinter`
- **Prerequisites:** `pycryptodome`

---

## 🚀 Key Features
- Secure communication using AES-CBC encryption with custom big-endian length framing.
- Fully functional remote command execution with active working directory (`cd`) handling.
- Interactive Tkinter GUI visualizer (`gui_visualizer.py`) displaying animation-rich network packets and architectural pathways.
- Step-by-step graphical workflow highlighting the listener and client command loop.
- Cryptographic handshake and key management simulation.

---

## 📖 Installation & Usage

### 1. Install Dependencies
Make sure you have Python 3 and the required libraries installed:
```bash
pip install -r requirements.txt
```
*(If a local `requirements.txt` is not present, install manually using `pip install pycryptodome`)*

### 2. Execution Commands
Choose the command depending on your operating system:

**Windows Command Prompt / PowerShell:**
```cmd
python listener.py  (then in another terminal) python client.py
```

**Linux / macOS Terminal:**
```bash
python3 listener.py (then in another terminal) python3 client.py
```

*Note: Some projects require administrative privileges (root/sudo) to bind to raw sockets, monitor network interfaces, or intercept system APIs.*

---

## ⚠️ Legal & Ethical Disclaimer
> **IMPORTANT WARNING:** This tool is created strictly for educational, defensive, and authorized security auditing purposes. Reverse shells are common payloads for remote access. This simulator is strictly for studying secure shell communication. Unauthorized deployment constitutes a severe breach of cybersecurity laws. The developer (**Abdul Salam**) assumes no liability for misuse, damage, or legal consequences resulting from the deployment of this tool.

---

## 👤 Developer Profile
- **Developer:** [Abdul Salam](https://salamcs.app)
- **GitHub:** [salam.cyber1](https://github.com/abdulsalam401)
- **LinkedIn:** [Abdul Salam](https://www.linkedin.com/in/abdul-salam-39467a274)
- **Portfolio:** [salamcs.app](https://salamcs.app)
