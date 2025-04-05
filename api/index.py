import threading
from flask import Flask
from flask_cors import CORS
from flask_pymongo import PyMongo
from flask_bcrypt import Bcrypt
from api.bankServer import BankServer
from routes.home import home_bp  # Import the home blueprint
from routes.python import python_bp
from routes.ATM import ATM  # Import the ATM client blueprint

# Function to start the bank server in a separate thread
def start_bank_server():
    server = BankServer()
    server_thread = threading.Thread(target=server.run, daemon=True)
    server_thread.start()
# Instance of App
app = Flask(__name__)

# Enable CORS for all routes, allowing requests from http://localhost:3000
CORS(app, resources={r"/*": {"origins": "http://localhost:3000"}})

# MongoDB configuration
app.config["MONGO_URI"] = "mongodb://localhost:27017/COE817"
mongo = PyMongo(app)
bcrypt = Bcrypt(app)

# Register Blueprints
app.register_blueprint(home_bp)
app.register_blueprint(python_bp)
app.register_blueprint(ATM(mongo,bcrypt))  # Pass the PyMongo and Bcrypt instances to the blueprint # Register the ATM client blueprint

# Start the bank server automatically when the Flask app starts
with app.app_context():
    start_bank_server()

if __name__ == '__main__':  # To enable debug mode
    app.run(port=8080, debug=True)