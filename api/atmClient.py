import socket
import hmac
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

class ATMClient:
    def __init__(self, server_host="127.0.0.1", server_port=9999):
        self.server_host = server_host
        self.server_port = server_port
        self.K_shared = b'shared_secret_key'
        self.K_enc = None
        self.K_mac = None

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

    def run(self):
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect((self.server_host, self.server_port))

        # Step 1: Perform authenticated key distribution
        # (Send challenge, receive response, derive Master Secret, etc.)
        # For simplicity, we'll use a static master secret here
        master_secret = b'master_secret_example'
        self.K_enc, self.K_mac = self.derive_keys(master_secret)

        # Step 2: Perform transactions
        transaction = "Deposit $100"
        encrypted_transaction = self.encrypt_data(self.K_enc, transaction.encode())
        mac = hmac.new(self.K_mac, encrypted_transaction, hashlib.sha256).digest()

        # Send encrypted transaction and MAC
        client.send(encrypted_transaction)
        client.send(mac)

        # Receive response
        encrypted_response = client.recv(1024)
        response_mac = client.recv(64)

        # Verify MAC
        mac = hmac.new(self.K_mac, encrypted_response, hashlib.sha256).digest()
        if mac != response_mac:
            print("MAC verification failed!")
            return

        # Decrypt response
        response = self.decrypt_data(self.K_enc, encrypted_response)
        print(f"Server response: {response.decode()}")

if __name__ == "__main__":
    atm_client = ATMClient()
    atm_client.run()