# 🔐 Project 33: Multi-Threaded Password Cracker & Hash Matcher

Part of the **Ethical Hacking 100 Projects Challenge**. This project is a cryptographic security auditing tool designed to benchmark hashing speed and match password hashes against dictionary words, common mutations, precomputed static rainbow tables, and multi-threaded character space brute forcing.

---

## 📖 Overview

Weak credentials remain a key vector for system compromise. This project provides a performance-optimized multi-threaded hash validator to verify password complexity and audit stored credentials.

It operates using three progressive verification phases:
1. **Precomputed Map Check**: Instantly queries static reference rainbow tables containing precalculated digests.
2. **Rule-Based Dictionary Mutation**: Mutates popular built-in passwords using rule-based transformations (e.g. casing, suffix insertion, and leet-speak substitutions).
3. **Multi-Threaded Exhaustive Search**: Spawns concurrent character permutation workers using `ThreadPoolExecutor` to crack any remaining unlisted short hashes.

---

## 🛠️ Features

- **Multi-Algorithm Support**: Standard implementation support for `MD5`, `SHA1`, `SHA256`, and cryptographically salted `bcrypt`.
- **Precomputed Hash Database**: Quick resolution of common digests using static lookups.
- **Dynamic Mutation Engine**: Generates structural mutations for vocabulary items including custom capitalization, leet-speak substitutions (e.g., `a` ➔ `@`, `s` ➔ `$`), and trailing sequences.
- **Concurrent Brute-Force Matrix**: Efficient parallelized permutation generation split into chunks and processed via thread pools.

---

## 📂 File Structure

- [password_cracker.py](file:///D:/100%20Projects%20Challenge/Project_33_Password_Cracker/password_cracker.py): Core implementation of the multi-threaded hash matching script.
- [password_cracker2.py](file:///D:/100%20Projects%20Challenge/Project_33_Password_Cracker/password_cracker2.py): Enhanced version featuring an interactive menu, configurable parameters, and additional statistics.
- [my_rainbow.txt](file:///D:/100%20Projects%20Challenge/Project_33_Password_Cracker/my_rainbow.txt): Sample precomputed rainbow lookup records.

---

## ⚙️ Setup & Installation

Ensure you have Python 3 installed. The application depends on `bcrypt` and `colorama` (optional, for CLI styling).

Install requirements:
```bash
pip install bcrypt colorama
```

---

## 🚀 Usage

### Run Password Cracker Verification
To audit a specific hash, run the main script pointing to the correct digest type:
```bash
python password_cracker.py --hash 5f4dcc3b5aa765d61d8327deb882cf99 --type md5
```

For the interactive GUI/CLI version:
```bash
python password_cracker2.py
```

---

## 🛡️ Defensive Remediation

To protect credentials from audit attacks:
1. **Use Slow Hashing Schemes**: Implement work-factored algorithms like `Argon2id`, `bcrypt`, or `PBKDF2`.
2. **Increase Salt Entropies**: Ensure every credential is salted uniquely using cryptographic random generators.
3. **Enforce Policy Complexity**: Require long passphrases (14+ characters) that resist mutation attacks and brute forcing.
4. **Deploy Multi-Factor Authentication (MFA)**: Mitigate compromised passwords by introducing external verification requirements.

---

## ⚠️ Disclaimer
This tool is for educational purposes and authorized credential auditing only. Running crackers against unauthorized systems is illegal.
