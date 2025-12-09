import threading
import os
import base64
import hashlib
import dotenv
import tkinter as tk
from tkinter import scrolledtext
import websocket
dotenv.load_dotenv()

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

WS_URL = os.getenv('URL')

key = None
private_key = None

# -----------------------------
#     CRYPTO
# -----------------------------

def derive_key(shared_secret):
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"messenger"
    ).derive(shared_secret)

def encrypt(key, plaintext):
    iv = os.urandom(12)
    encryptor = Cipher(algorithms.AES(key), modes.GCM(iv)).encryptor()
    ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()
    return base64.b64encode(iv + encryptor.tag + ciphertext).decode()

def decrypt(key, ciphertext):
    data = base64.b64decode(ciphertext)
    iv, tag, ciphertext = data[:12], data[12:28], data[28:]
    decryptor = Cipher(algorithms.AES(key), modes.GCM(iv, tag)).decryptor()
    return (decryptor.update(ciphertext) + decryptor.finalize()).decode()

def fingerprint(pub_key):
    pub_bytes = pub_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return hashlib.sha256(pub_bytes).hexdigest()[:16]

# -----------------------------
#     GUI
# -----------------------------

root = tk.Tk()
root.title("Secure Chat")
root.geometry("500x600")
root.configure(bg="#2c2c2c")

chat_log = scrolledtext.ScrolledText(root, wrap=tk.WORD, bg="#1e1e1e", fg="white", font=("Arial", 12))
chat_log.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

input_entry = tk.Entry(root, bg="#3c3c3c", fg="white", font=("Arial", 12))
input_entry.pack(padx=10, pady=10, fill=tk.X)

def gui_log(text):
    root.after(0, lambda: (chat_log.insert(tk.END, text + "\n"), chat_log.see(tk.END)))

def send_message(event=None):
    global key
    msg = input_entry.get()
    if msg and key:
        encrypted = encrypt(key, msg)
        ws.send(encrypted)
        gui_log("You: " + msg)
    input_entry.delete(0, tk.END)

input_entry.bind("<Return>", send_message)

# -----------------------------
#     WS CALLBACKS
# -----------------------------

def on_message(ws, message):
    global key, private_key

    # Server Ready
    if message == "ready":
        private_key = ec.generate_private_key(ec.SECP384R1())
        public_key = private_key.public_key()
        pub_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
        ws.send(pub_pem)
        return

    # Public key of partner
    if "-----BEGIN PUBLIC KEY-----" in message:
        peer_public_key = serialization.load_pem_public_key(message.encode())
        gui_log(f"Fingerprint of the interlocutor: {fingerprint(peer_public_key)}")
        gui_log("Verify fingerprints manually to rule out MITM.")

        shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)
        key = derive_key(shared_secret)
        gui_log("The encryption key has been installed.")
        return

    # crypt message
    try:
        decrypted = decrypt(key, message)
        gui_log("Interlocutor: " + decrypted)
    except:
        gui_log("Encryption error.")

def on_error(ws, error):
    gui_log("Error: " + str(error))

def on_close(ws, code, msg):
    gui_log("Connection closed.")

def on_open(ws):
    gui_log("Connected to Server.")


# -----------------------------
#     RUN WS IN THREAD
# -----------------------------

ws = websocket.WebSocketApp(
    WS_URL,
    on_open=on_open,
    on_message=on_message,
    on_error=on_error,
    on_close=on_close,
)

threading.Thread(target=ws.run_forever, daemon=True).start()

root.mainloop()