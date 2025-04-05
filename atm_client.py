from flask import Flask, request, render_template_string
import socket
import json
from cryptography.fernet import Fernet

app = Flask(__name__)
client_id = "client1"
shared_key = Fernet.generate_key()
fernet = Fernet(shared_key)

HTML = """
<h2>ATM Client</h2>
<form action="/action" method="post">
  Action:
  <select name="action">
    <option value="balance">Balance Inquiry</option>
    <option value="deposit">Deposit</option>
    <option value="withdraw">Withdraw</option>
  </select><br>
  Amount (if any): <input type="number" name="amount"><br>
  <input type="submit" value="Send">
</form>
<p>{{ result }}</p>
"""

@app.route('/', methods=['GET'])
def home():
    return render_template_string(HTML, result="")

@app.route('/action', methods=['POST'])
def do_action():
    action = request.form['action']
    amount = request.form.get('amount')
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect(('127.0.0.1', 65432))
            s.send(client_id.encode())

            auth_resp = s.recv(1024).decode()
            if auth_resp != "Authenticated":
                return render_template_string(HTML, result="Authentication Failed")

            payload = {'action': action}
            if amount:
                payload['amount'] = int(amount)

            encrypted_payload = fernet.encrypt(json.dumps(payload).encode())
            s.send(encrypted_payload)

            response = s.recv(4096)
            result = fernet.decrypt(response).decode()
            return render_template_string(HTML, result=result)
    except Exception as e:
        return render_template_string(HTML, result=f"Error: {str(e)}")

if __name__ == "__main__":
    app.run(port=5000)
