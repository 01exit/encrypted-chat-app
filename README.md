# 🔐 Secure WebSocket Messenger

A simple **end-to-end encrypted messenger** built with **WebSockets** for real-time communication.  
The project includes a **server** (aiohttp) and a **Python client** (websocket-client) and supports **two-party encrypted chats** using:

- ✅ **ECDH key exchange** (SECP384R1)
- ✅ **AES-256-GCM message encryption**
- ✅ **Public key fingerprint verification** to prevent MITM attacks

Designed for **easy deployment on platforms like Render.com**.

---

## 🚀 Features

- 🔒 **End-to-End Encryption**  
  Uses **ECDH (SECP384R1)** for secure key exchange and **AES-256-GCM** for message encryption.

- 🆔 **Fingerprint Verification**  
  Displays a **SHA-256 fingerprint** of the peer’s public key for manual out-of-band verification (e.g., phone call).

- ⚡ **Real-Time Messaging**  
  WebSocket-based instant message exchange.

- 🖥️ **Lightweight Server**  
  Supports **up to 2 connected clients**, sends `ready` when both connect, and relays messages + public keys.

- ☁️ **Deployment-Friendly**  
  Works locally via `ws://` and in production via `wss://` (Render, cloud VPS, etc.).

- 🔄 **Dynamic Key Management**  
  Clients generate and exchange cryptographic keys automatically on connection.

---

## 📦 Requirements

### Python
- **Python 3.8+**

### Server Dependencies (`server_requirements.txt`)
- `aiohttp`

### Client Dependencies (`client_requirements.txt`)
- `aiohttp==3.9.5`
- `cryptography==46.0.3`
- `python-dotenv==1.2.1`
- `websocket-client==1.8.0`

### Install Dependencies

```bash
# Server
pip install -r server_requirements.txt

# Client
pip install -r client_requirements.txt
```

## 🛠️ Setup & Installation
1️⃣ Clone the Repository
```
git clone https://github.com/01exit/encrypted-chat-app.git
cd encrypted-chat-app
```
2️⃣ Environment Configuration
Create a .env file in the project root:
`URL="wss://your-service.onrender.com"`

3️⃣ Run the Server

4️⃣ Run the Clients:
`client_gui.py`

