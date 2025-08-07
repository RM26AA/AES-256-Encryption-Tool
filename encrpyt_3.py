import tkinter as tk
from tkinter import messagebox, filedialog
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os
import base64

# === AES Utilities ===
def generate_key():
    return os.urandom(32)

def generate_iv():
    return os.urandom(16)

def pad_message(message):
    padder = padding.PKCS7(128).padder()
    return padder.update(message.encode()) + padder.finalize()

def unpad_message(padded_data):
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded_data) + unpadder.finalize()

def encrypt_message(message, key, iv):
    padded = pad_message(message)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted = encryptor.update(padded) + encryptor.finalize()
    return base64.b64encode(encrypted).decode()

def decrypt_message(ciphertext_b64, key, iv):
    ciphertext = base64.b64decode(ciphertext_b64)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted = decryptor.update(ciphertext) + decryptor.finalize()
    return unpad_message(decrypted).decode()

# === GUI App ===
class AESApp:
    def __init__(self, root):
        self.root = root
        self.root.title("AES-256 Encryption Tool")
        self.build_gui()

    def build_gui(self):
        # Encryption Section
        tk.Label(self.root, text="Enter message to encrypt:").grid(row=0, column=0, sticky="w")
        self.message_entry = tk.Text(self.root, height=4, width=50)
        self.message_entry.grid(row=1, column=0, columnspan=2)

        self.encrypt_btn = tk.Button(self.root, text="Encrypt", command=self.encrypt)
        self.encrypt_btn.grid(row=2, column=0, pady=5)

        # Save options
        self.save_encrypted = tk.IntVar()
        self.save_key = tk.IntVar()
        self.save_iv = tk.IntVar()

        tk.Checkbutton(self.root, text="Save Encrypted Message", variable=self.save_encrypted).grid(row=3, column=0, sticky="w")
        tk.Checkbutton(self.root, text="Save AES Key", variable=self.save_key).grid(row=4, column=0, sticky="w")
        tk.Checkbutton(self.root, text="Save AES IV", variable=self.save_iv).grid(row=5, column=0, sticky="w")

        # Output
        self.output_text = tk.Text(self.root, height=8, width=60, wrap="word")
        self.output_text.grid(row=6, column=0, columnspan=2, pady=10)

        # Decryption Section
        tk.Label(self.root, text="Decrypt Message").grid(row=7, column=0, sticky="w", pady=(10, 0))
        tk.Label(self.root, text="Encrypted Message (base64):").grid(row=8, column=0, sticky="w")
        self.dec_msg_entry = tk.Text(self.root, height=2, width=50)
        self.dec_msg_entry.grid(row=9, column=0, columnspan=2)

        tk.Label(self.root, text="AES Key (base64):").grid(row=10, column=0, sticky="w")
        self.dec_key_entry = tk.Entry(self.root, width=60)
        self.dec_key_entry.grid(row=11, column=0, columnspan=2)

        tk.Label(self.root, text="AES IV (base64):").grid(row=12, column=0, sticky="w")
        self.dec_iv_entry = tk.Entry(self.root, width=60)
        self.dec_iv_entry.grid(row=13, column=0, columnspan=2)

        self.decrypt_btn = tk.Button(self.root, text="Decrypt", command=self.decrypt)
        self.decrypt_btn.grid(row=14, column=0, pady=10)

    def encrypt(self):
        msg = self.message_entry.get("1.0", tk.END).strip()
        if not msg:
            messagebox.showwarning("Input Required", "Please enter a message to encrypt.")
            return

        key = generate_key()
        iv = generate_iv()
        encrypted = encrypt_message(msg, key, iv)

        key_b64 = base64.b64encode(key).decode()
        iv_b64 = base64.b64encode(iv).decode()

        output = f"🔒 Encrypted Message:\n{encrypted}\n\n🔑 AES Key (base64):\n{key_b64}\n\n🧱 AES IV (base64):\n{iv_b64}"
        self.output_text.delete("1.0", tk.END)
        self.output_text.insert(tk.END, output)

        # Save options
        if self.save_encrypted.get():
            self.save_to_file("encrypted_message.txt", encrypted)
        if self.save_key.get():
            self.save_to_file("aes_key.txt", key_b64)
        if self.save_iv.get():
            self.save_to_file("aes_iv.txt", iv_b64)

        if not (self.save_encrypted.get() or self.save_key.get() or self.save_iv.get()):
            messagebox.showinfo("Reminder", "Make sure to copy and save the encrypted message, AES key, and IV somewhere safe (e.g. Notepad).")

    def decrypt(self):
        try:
            encrypted = self.dec_msg_entry.get("1.0", tk.END).strip()
            key_b64 = self.dec_key_entry.get().strip()
            iv_b64 = self.dec_iv_entry.get().strip()

            if not encrypted or not key_b64 or not iv_b64:
                messagebox.showwarning("Missing Data", "Please enter all fields for decryption.")
                return

            key = base64.b64decode(key_b64)
            iv = base64.b64decode(iv_b64)
            decrypted = decrypt_message(encrypted, key, iv)

            messagebox.showinfo("Decryption Successful", f"Decrypted Message:\n{decrypted}")
        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed:\n{str(e)}")

    def save_to_file(self, filename, content):
        path = filedialog.asksaveasfilename(defaultextension=".txt", initialfile=filename)
        if path:
            with open(path, "w") as f:
                f.write(content)

# === Launch the App ===
if __name__ == "__main__":
    root = tk.Tk()
    app = AESApp(root)
    root.mainloop()
