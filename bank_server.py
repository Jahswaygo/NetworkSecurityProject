import socket
import threading
import json
import hmac
import hashlib
import os
import bcrypt  # Add this import
from datetime import datetime
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.fernet import Fernet

HOST = '127.0.0.1'
PORT = 65432

# Mock database
users = {}  # Store hashed passwords
accounts = {}

# Audit log encryption key
audit_key = Fernet.generate_key()
audit_fernet = Fernet(audit_key)

def log_action(client_id, action):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"{client_id}\t{action}\t{timestamp}\n"
    encrypted_entry = audit_fernet.encrypt(log_entry.encode())
    with open("audit_log.enc", "ab") as f:
        f.write(encrypted_entry + b'\n')

def handle_client(conn, addr):
    print(f"[CONNECTED] {addr}")

    while True:
        data = conn.recv(4096)
        if not data:
            break

        request = json.loads(data.decode())
        action = request.get('action')

        if action == 'signup':
            username = request['username']
            password = request['password'].encode()  # Convert to bytes for bcrypt

            if username in users:
                conn.send("Username already exists".encode())
            else:
                # Hash the password and store it
                hashed_password = bcrypt.hashpw(password, bcrypt.gensalt())
                users[username] = hashed_password
                accounts[username] = 0  # Initialize account balance
                conn.send("Signup Successful".encode())

        elif action == 'login':
            username = request['username']
            password = request['password'].encode()  # Convert to bytes for bcrypt

            if username not in users or not bcrypt.checkpw(password, users[username]):
                conn.send("Authentication Failed".encode())
                continue

            conn.send("Authenticated".encode())

            # Generate Master Secret
            master_secret = os.urandom(32)
            conn.send(master_secret)

            # Derive encryption and MAC keys
            hkdf = HKDF(algorithm=SHA256(), length=64, salt=None, info=b'ATM Session Keys')
            derived_keys = hkdf.derive(master_secret)
            encryption_key = derived_keys[:32]
            mac_key = derived_keys[32:]

            fernet = Fernet(encryption_key)

            while True:
                data = conn.recv(4096)
                if not data:
                    break

                # Parse received data
                received = json.loads(data.decode())
                encrypted_payload = received['payload'].encode()
                received_mac = received['mac']

                # Verify MAC
                mac = hmac.new(mac_key, encrypted_payload, hashlib.sha256).hexdigest()
                if mac != received_mac:
                    conn.send(fernet.encrypt(b"MAC verification failed"))
                    continue

                # Decrypt payload
                payload = json.loads(fernet.decrypt(encrypted_payload).decode())
                action = payload['action']
                result = ""

                # Process action
                if action == 'deposit':
                    amount = payload['amount']
                    accounts[username] += amount
                    result = f"Deposited ${amount}. New Balance: ${accounts[username]}"
                elif action == 'withdraw':
                    amount = payload['amount']
                    if accounts[username] >= amount:
                        accounts[username] -= amount
                        result = f"Withdrew ${amount}. New Balance: ${accounts[username]}"
                    else:
                        result = "Insufficient funds"
                elif action == 'balance':
                    result = f"Current Balance: ${accounts[username]}"

                # Log action
                log_action(username, action)

                # Send encrypted response
                conn.send(fernet.encrypt(result.encode()))

    conn.close()

def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen()
    print(f"[LISTENING] on {HOST}:{PORT}")

    while True:
        conn, addr = server.accept()
        thread = threading.Thread(target=handle_client, args=(conn, addr))
        thread.start()

if __name__ == "__main__":
    start_server()
