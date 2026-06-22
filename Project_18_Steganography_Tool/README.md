# 🛠️ LSB Steganography Tool with PBKDF2 Password Encryption

This project is part of the **[Ethical-Hacking-100-Projects-Challenge](https://github.com/abdulsalam401/Ethical-Hacking-100-Projects-Challenge)** challenge. It is an educational utility designed to study cybersecurity concepts, network protocols, and system defenses.

---

## 📌 Project Overview
A steganography tool that embeds and extracts secret data inside PNG images. It uses Least Significant Bit (LSB) encoding and includes optional PBKDF2 password-based encryption to secure the hidden payload.

### ⚙️ Specifications & Tech Stack
- **Category:** Ethical Hacking / Cyber Security Lab
- **Language:** Python / C (where applicable)
- **Tech Stack:** `Python 3`, `Pillow (PIL)`, `cryptography (or hashlib/hmac)`
- **Prerequisites:** `pillow`, `cryptography`

---

## 🚀 Key Features
- LSB steganography: hides data inside the pixel values of PNG images.
- Strong encryption: encrypts the hidden payload using PBKDF2 and AES (or fallback XOR).
- Payload header: includes metadata (file sizes and format markers) to guide extraction.
- Verifies image capacity before hiding data.

---

## 📖 Installation & Usage

### 1. Install Dependencies
Make sure you have Python 3 and the required libraries installed:
```bash
pip install -r requirements.txt
```
*(If a local `requirements.txt` is not present, install manually using `pip install pillow cryptography`)*

### 2. Execution Commands
Choose the command depending on your operating system:

**Windows Command Prompt / PowerShell:**
```cmd
python stego_hide.py
```

**Linux / macOS Terminal:**
```bash
python3 stego_hide.py
```

*Note: Some projects require administrative privileges (root/sudo) to bind to raw sockets, monitor network interfaces, or intercept system APIs.*

---

## ⚠️ Legal & Ethical Disclaimer
> **IMPORTANT WARNING:** This tool is created strictly for educational, defensive, and authorized security auditing purposes. Use this tool to study data embedding and cryptographic packaging techniques. Ensure you do not violate intellectual property by modifying copyrighted images. The developer (**Abdul Salam**) assumes no liability for misuse, damage, or legal consequences resulting from the deployment of this tool.

---

## 👤 Developer Profile
- **Developer:** [Abdul Salam](https://salamcs.app)
- **GitHub:** [salam.cyber1](https://github.com/abdulsalam401)
- **LinkedIn:** [Abdul Salam](https://www.linkedin.com/in/abdul-salam-39467a274)
- **Portfolio:** [salamcs.app](https://salamcs.app)
