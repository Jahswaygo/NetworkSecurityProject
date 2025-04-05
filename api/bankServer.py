import socket
import threading
import hmac
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from datetime import datetime

class BankServer:
    def __init__(self, host="0.0.0.0", port=9999):
        self.host = host
        self.port = port
        self.K_shared = b'shared_secret_key'

    def derive_keys(self, master_secret):
        K_enc = hmac.new(master_secret, b"encryption", hashlib.sha256).digest()
        K_mac = hmac.new(master_secret, b"mac", hashlib.sha256).digest()
        return K_enc, K_mac

    def encrypt_data(self, key, plaintext):
        cipher = Cipher(algorithms.AES(key), modes.CFB(b'16_byte_iv_here'))
        encryptor = cipher.encryptor()
        return encryptor.update(plaintext) + encryptor.finalize()

    def decrypt_data(self, key, ciphertext):
        cipher = Cipher(algorithms.AES(key), modes.CFB(b'16_byte_iv_here'))
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()

    def log_transaction(self, transaction):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"{transaction} | {timestamp}"
        encrypted_log = self.encrypt_data(self.K_shared, log_entry.encode())
        with open("audit_log.txt", "ab") as log_file:
            log_file.write(encrypted_log + b"\n")

    def handle_client(self, client_socket):
        # Step 1: Perform authenticated key distribution
        # (Receive challenge, respond, derive Master Secret, etc.)
        # For simplicity, we'll use a static master secret here
        master_secret = b'master_secret_example'
        K_enc, K_mac = self.derive_keys(master_secret)

        # Step 2: Process transactions
        while True:
            # Receive encrypted data and MAC
            encrypted_data = client_socket.recv(1024)
            received_mac = client_socket.recv(64)

            # Verify MAC
            mac = hmac.new(K_mac, encrypted_data, hashlib.sha256).digest()
            if mac != received_mac:
                print("MAC verification failed!")
                break

            # Decrypt data
            data = self.decrypt_data(K_enc, encrypted_data)
            print(f"Received transaction: {data.decode()}")

            # Log the transaction
            self.log_transaction(data.decode())

            # Send response (encrypted and with MAC)
            response = "Transaction processed successfully."
            encrypted_response = self.encrypt_data(K_enc, response.encode())
            response_mac = hmac.new(K_mac, encrypted_response, hashlib.sha256).digest()
            client_socket.send(encrypted_response)
            client_socket.send(response_mac)

    def run(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind((self.host, self.port))
        server.listen(5)
        print(f"Server listening on {self.host}:{self.port}...")

        while True:
            client_socket, addr = server.accept()
            print(f"Accepted connection from {addr}")
            client_handler = threading.Thread(target=self.handle_client, args=(client_socket,))
            client_handler.start()