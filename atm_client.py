from flask import Flask, request, render_template
import socket
import json
import hmac
import hashlib
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.fernet import Fernet
import os
import sys
import base64


app = Flask(__name__)
DEFAULT_GATEWAY = '127.0.0.1'
SERVER_PORT = 65432

# Global variables for session keys, socket, and username
encryption_key = None
mac_key = None
client_socket = None  # Persistent socket connection
current_username = None  # Track the logged-in username

# Dynamically assign a port and client instance number
if len(sys.argv) > 1:
    client_number = int(sys.argv[1])  # Pass the client number as a command-line argument
else:
    print("Error: No client number provided. Please pass the client number as a command-line argument.")
    sys.exit(1)  # Exit the program with an error code

port = 5000 + client_number  # Increment the port based on the client number

# Check if the port is in use
def is_port_in_use(port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind((DEFAULT_GATEWAY, port))
        except OSError:
            return True
    return False

if is_port_in_use(port):
    print(f"Error: Port {port} is already in use. Please choose a different client number.")
    sys.exit(1)
#API Endpoints--------------------------------------------------------

print(f"Starting ATM Client {client_number} on port {port}...")

@app.route('/', methods=['GET'])
def home():
    return render_template("login.html", result="")

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'GET':
        return render_template("signup.html", result="")
    
    username = request.form['username']
    password = request.form['password']

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((DEFAULT_GATEWAY, SERVER_PORT))

            # Send signup request to server
            signup_data = {'action': 'signup', 'username': username, 'password': password}
            s.send(json.dumps(signup_data).encode())

            # Receive server's response
            response = s.recv(1024).decode()
            if response == "Signup Successful":
                return render_template("login.html", result="Signup Successful. Please log in.")
            else:
                return render_template("signup.html", result=response)
    except Exception as e:
        return render_template("signup.html", result=f"Error: {str(e)}")

@app.route('/login', methods=['POST'])
def login():
    global encryption_key, mac_key, client_socket, current_username
    username = request.form['username']
    password = request.form['password']

    try:
        # Establish a persistent socket connection
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((DEFAULT_GATEWAY, SERVER_PORT))

        # Send username and password to server
        credentials = {'action': 'login', 'username': username, 'password': password}
        client_socket.send(json.dumps(credentials).encode())

        # Receive server's response
        auth_resp = client_socket.recv(1024).decode()
        if auth_resp != "Authenticated":
            client_socket.close()
            client_socket = None
            return render_template("login.html", result="Authentication Failed")

        # Receive Master Secret from server
        master_secret = client_socket.recv(1024)

        # Derive encryption and MAC keys from Master Secret
        hkdf = HKDF(algorithm=SHA256(), length=64, salt=None, info=b'ATM Session Keys')
        derived_keys = hkdf.derive(master_secret)
        encryption_key = base64.urlsafe_b64encode(derived_keys[:32])  # Encode the first 32 bytes
        mac_key = derived_keys[32:]  # Use the remaining 32 bytes for MAC

        # Store the username in the global variable
        current_username = username
        return render_template("action.html", result="Login Successful", username=username)
    
    except Exception as e:
        if client_socket:
            client_socket.close()
            client_socket = None
        return render_template("login.html", result=f"Error: {str(e)}")

@app.route('/action', methods=['GET', 'POST'])
def do_action():
    global encryption_key, mac_key, client_socket, current_username
    action = request.form['action']
    amount = request.form.get('amount')

    if encryption_key is None or mac_key is None or client_socket is None:
        return render_template("login.html", result="Please log in first.")

    try:
        # Prepare payload
        payload = {'action': action}
        if amount:
            payload['amount'] = int(amount)

        # Encrypt payload
        fernet = Fernet(encryption_key)
        encrypted_payload = fernet.encrypt(json.dumps(payload).encode())

        # Generate MAC
        mac = hmac.new(mac_key, encrypted_payload, hashlib.sha256).hexdigest()

        # Send encrypted payload and MAC
        client_socket.send(json.dumps({'payload': encrypted_payload.decode(), 'mac': mac}).encode())

        # Receive and decrypt response
        response = client_socket.recv(4096)
        print(f"[DEBUG] Received encrypted response: {response}")
        decrypted_response = fernet.decrypt(response).decode()
        print(f"[DEBUG] Decrypted response: {decrypted_response}")
        return render_template("action.html", result=decrypted_response, username=current_username)
    except Exception as e:
        return render_template("action.html", result=f"Error: {str(e)}", username=current_username)
#---------------------------------------------------------
if __name__ == "__main__":
    app.run(port=port)
