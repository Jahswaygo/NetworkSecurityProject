import socket
import threading
import json
import hmac
import hashlib
import os
import bcrypt  # Add this import
import base64  # Add this import for key encoding
from datetime import datetime
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.fernet import Fernet

HOST = '127.0.0.1'
PORT = 65432

# Global database and lock
users = {}  # Store hashed passwords
accounts = {}
db_lock = threading.Lock()  # Lock for synchronizing access to shared resources

# Audit log encryption key
audit_key = Fernet.generate_key()
audit_fernet = Fernet(audit_key)

def log_action_encrypted(client_id, action):
    """Log actions in an encrypted format."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"{client_id}\t{action}\t{timestamp}\n"
    encrypted_entry = audit_fernet.encrypt(log_entry.encode())
    with open("audit_log.enc", "ab") as f:
        f.write(encrypted_entry + b'\n')


def log_action_plaintext(client_id, action):
    """Log actions in plaintext format."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"{client_id}\t{action}\t{timestamp}\n"
    with open("audit_log_unencrypted.txt", "a") as f:
        f.write(log_entry)


def log_action(client_id, action):
    """Call both logging functions for encrypted and plaintext logs."""
    log_action_encrypted(client_id, action)
    log_action_plaintext(client_id, action)

def handle_client(conn, addr):
    print(f"[CONNECTED] {addr}")

    try:
        while True:
            # Receive data from the client
            data = conn.recv(4096)
            if not data:
                print(f"[DISCONNECTED] {addr}")
                break

            # Parse the received data
            request = json.loads(data.decode())
            action = request.get('action')

            if action == 'signup':
                username = request['username']
                password = request['password'].encode()  # Convert to bytes for bcrypt

                with db_lock:  # Synchronize access to the shared resource
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

                with db_lock:  # Synchronize access to the shared resource
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
                encryption_key = base64.urlsafe_b64encode(derived_keys[:32])  # Encode the first 32 bytes
                mac_key = derived_keys[32:]  # Use the remaining 32 bytes for MAC

                fernet = Fernet(encryption_key)

                # Handle subsequent requests from the same client
                while True:
                    data = conn.recv(4096)
                    if not data:
                        print(f"[DISCONNECTED] {addr}")
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
                    with db_lock:  # Synchronize access to the shared resource
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
                            print(f"[DEBUG] Processing balance inquiry for {username}")
                            result = f"Current Balance: ${accounts[username]}"
                            log_action(username, action)

                    # Log action
                    log_action(username, action)

                    # Send encrypted response
                    conn.send(fernet.encrypt(result.encode()))

    except Exception as e:
        print(f"[ERROR] {addr}: {str(e)}")
    finally:
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
