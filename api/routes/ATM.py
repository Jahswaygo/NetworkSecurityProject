import socket
from flask import Blueprint, jsonify, request
import threading
from api.atmClient import ATMClient
from bson import ObjectId
from flask import Blueprint, jsonify, request
from flask_pymongo import PyMongo
from flask_bcrypt import Bcrypt
import globals

def ATM(mongo: PyMongo, bcrypt: Bcrypt):
    # Create a blueprint for the ATM client
    atm_client_bp = Blueprint("atm_client", __name__)
    
        # Function to check if a port is available
    def is_port_available(host, port):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind((host, port))
                return True
            except OSError:
                return False

    # Function to start an ATM client in a separate thread
    def start_atm_client(server_host, server_port):
        # Increment the port if it's already in use
        while not is_port_available(server_host, server_port):
            server_port += 1

        atm = ATMClient(server_host=server_host, server_port=server_port)
        atm_thread = threading.Thread(target=atm.run)
        atm_thread.start()
        return server_port  # Return the final port used

    def verify_password(mongo: PyMongo, bcrypt: Bcrypt, username: str, password: str):
        # Query the database for the user
        user = mongo.db.Users.find_one({'username': username})

        if user:
            # Get the stored hashed password
            stored_password = user.get('password')

            # Debugging: Print the stored password and the provided password
            print(f"Stored password: {stored_password}")
            print(f"Provided password: {password}")

            # Verify the provided password against the stored hashed password
            if bcrypt.check_password_hash(stored_password, password):
                return True, "Login successful"
            else:
                return False, "Invalid password"
        else:
            return False, "User not found"

    @atm_client_bp.route("/api/username", methods=['GET'])
    def get_username():
        if globals.logged_in_username:
            return jsonify({'username': globals.logged_in_username}), 200
        else:
            return jsonify({'message': 'No username found'}), 404
        
    @atm_client_bp.route("/api/login", methods=['POST'])
    def reqLogin():
        data = request.json
        username = data.get('username')
        password = data.get('password')

        # Verify the password using the function from services
        is_valid, message = verify_password(mongo, bcrypt, username, password)

        if is_valid:
            return jsonify({'message': message}), 200
        else:
            return jsonify({'message': message}), 401

    # Route to trigger an ATM client transaction
    @atm_client_bp.route("/start-atm", methods=["POST"])
    def start_atm():
        data = request.get_json()
        server_host = data.get("server_host", "127.0.0.1")
        server_port = data.get("server_port", 9090)
        final_port = start_atm_client(server_host, server_port)
        return jsonify({"message": "ATM client started!", "server_host": server_host, "server_port": final_port})
    
    @atm_client_bp.route('/api/database', methods=['POST'])
    def add_data():
        new_data = request.json

        # Extract the fields from the incoming data
        fullname = new_data.get('fullname')
        username = new_data.get('username')
        email = new_data.get('email')
        password = new_data.get('password')
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')  # Hash the password using Flask-Bcrypt

        # Debugging: Print the hashed password
        print(f"Hashed password: {hashed_password}")

        # Create the new entry
        entry = {
            'fullname': fullname,
            'username': username,
            'email': email,
            'password': hashed_password
        }

        # Insert the new entry into the database
        mongo.db.Users.insert_one(entry)
        globals.logged_in_username = username
        return jsonify({'message': 'Data added successfully'}), 201

    @atm_client_bp.route('/api/database/<id>', methods=['PUT'])
    def update_data(id):
        updated_data = request.json
        mongo.db.Users.update_one({'_id': ObjectId(id)}, {'$set': updated_data})
        return jsonify({'message': 'Data updated successfully'}), 200

    @atm_client_bp.route('/api/database/<id>', methods=['DELETE'])
    def delete_data(id):
        mongo.db.Users.delete_one({'_id': ObjectId(id)})
        return jsonify({'message': 'Data deleted successfully'}), 200

    @atm_client_bp.route('/api/database/companies', methods=['GET'])
    def get_unique_companies():
        companies = mongo.db.Users.distinct('company')
        return jsonify({'companies': companies}), 200

    return atm_client_bp