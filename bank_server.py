import socket
import threading
import json
from datetime import datetime
from cryptography.fernet import Fernet

HOST = '127.0.0.1'
PORT = 65432

# Mock key storage (pre-shared key for simplicity)
shared_keys = {
    "client1": Fernet.generate_key(),
    "client2": Fernet.generate_key()
}

# Audit log encryption key
audit_key = Fernet.generate_key()
audit_fernet = Fernet(audit_key)

accounts = {"client1": 1000, "client2": 500}

def log_action(client_id, action):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"{client_id}\t{action}\t{timestamp}\n"
    encrypted_entry = audit_fernet.encrypt(log_entry.encode())
    with open("audit_log.enc", "ab") as f:
        f.write(encrypted_entry + b'\n')

def handle_client(conn, addr):
    print(f"[CONNECTED] {addr}")
    client_id = conn.recv(1024).decode()

    if client_id not in shared_keys:
        conn.send("Unauthorized client".encode())
        conn.close()
        return

    fernet = Fernet(shared_keys[client_id])
    conn.send("Authenticated".encode())

    while True:
        data = conn.recv(4096)
        if not data:
            break

        decrypted_data = fernet.decrypt(data)
        request = json.loads(decrypted_data.decode())
        action = request['action']
        result = ""

        if action == 'deposit':
            amount = request['amount']
            accounts[client_id] += amount
            result = f"Deposited ${amount}. New Balance: ${accounts[client_id]}"
        elif action == 'withdraw':
            amount = request['amount']
            if accounts[client_id] >= amount:
                accounts[client_id] -= amount
                result = f"Withdrew ${amount}. New Balance: ${accounts[client_id]}"
            else:
                result = "Insufficient funds"
        elif action == 'balance':
            result = f"Current Balance: ${accounts[client_id]}"

        log_action(client_id, action)
        response = fernet.encrypt(result.encode())
        conn.send(response)

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
