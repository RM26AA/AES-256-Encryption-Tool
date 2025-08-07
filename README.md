# 🔐 AES-256 Encryption Tool (Python GUI)

> **⚠️ Note:** AES-256 encryption is designed to be *computationally unbreakable* by brute force.  
> Decrypting an AES-256 encrypted message without the correct key and IV would require trying  
> `2^256 ≈ 1.16 x 10^77` possible keys. Even if a supercomputer could try **1 trillion keys per second**,  
> it would still take **longer than the age of the universe** to find the correct one.  
> **Conclusion:** Without the key and IV, decryption is practically impossible.

---

## 📦 Project Description

**AES-256 Encryption Tool** is a Python GUI application that allows users to:
- Encrypt and decrypt messages using AES-256 in CBC mode
- View and copy the AES key and IV in base64 format
- Choose whether or not to save the encrypted message, key, and IV to files
- Receive a warning if they choose not to save the sensitive data
- Input custom key/IV for decryption of externally encrypted messages

Built with the `cryptography` library and `tkinter`, this tool provides secure, user-friendly message encryption.

---

## 🧰 Features

- AES-256 encryption (32-byte key, 16-byte IV)
- GUI interface for message input/output
- Optional saving of:
  - Encrypted message
  - AES key (base64)
  - AES IV (base64)
- Base64 display of ciphertext, key, and IV for easy copying
- Decryption input panel:
  - Paste encrypted message
  - Paste base64 key and IV
- Error handling and user feedback messages

---

## 🚀 How to Run

1. Install dependencies:

```bash
pip install cryptography
```

2. Run the Python script:

```
python aes_gui_tool.py
```

## 📁 File Save Locations
When selected, files are saved through a save dialog where you can choose the directory and filename. If you don’t save, the app reminds you to copy the data manually.

- encrypted_message.txt
- aes_key.txt
- aes_iv.txt

## 🔐 Encryption Notes

- AES-256 uses a 256-bit secret key and a 128-bit IV.
- The same key and IV are required for successful decryption.
- Never reuse the same key/IV combination to encrypt different messages.
- Store your key and IV securely — losing them means losing access to your data permanently.

## 🧪 Example Output

```
Encrypted Message:
colyVxgOglEI/aEoGx4L5w47pDC+CrM23JDcX3kxbFWhZpcW4R9iP174NKIPu23l

AES Key (base64):
3nB6u0xd3Qk9Hn2N0IaKNuQkF81p2iDoF9OLrQ7VGuY=

AES IV (base64):
oE+6gEXaF4MvylnuyjENvA==
```

## ✅ License
This project is open source and free to use. Attribution is appreciated but not required.

## 💡 Author
Created by R.Maunick




















