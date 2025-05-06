# **Secure Banking ATM System**

## **Overview**
The Secure Banking ATM System is a client-server application designed to simulate the functionality of an ATM service while emphasizing network security principles. The project implements secure communication protocols to protect sensitive financial transactions, ensuring confidentiality, integrity, and authenticity of data exchanged between the ATM client and the bank server. The system supports essential banking operations such as account registration, deposits, withdrawals, and balance inquiries, while maintaining a robust security layer to prevent unauthorized access and tampering.

---

## **Features**
1. **Account Registration**:
   - Users can register with a username and password, which are securely stored on the server using hashed passwords.

2. **ATM Login**:
   - Users log in with their credentials, which are authenticated by the server.

3. **Secure Authentication and Key Exchange**:
   - A pre-shared key is used to establish trust between the client and server.
   - A `Master Secret` is generated and securely shared between the client and server.
   - Two session keys are derived from the `Master Secret`:
     - **Encryption Key**: Ensures confidentiality of data.
     - **MAC Key**: Ensures integrity and authenticity of messages.

4. **Secure Transactions**:
   - Supports deposits, withdrawals, and balance inquiries.
   - Transactions are encrypted and authenticated using the derived keys.
   - A Message Authentication Code (MAC) is generated and verified for every transaction to prevent tampering.

5. **Audit Logging**:
   - All transactions are logged in both plaintext and encrypted formats for auditing purposes.
   - Logs include timestamps for each transaction.

6. **Concurrency**:
   - The server supports multiple concurrent clients using threading.

7. **User-Friendly GUI**:
   - The ATM client provides a simple and intuitive interface for users to interact with the system.

---

## **System Components**

### **1. Bank Server (`bank_server.py`)**
The bank server is a multi-threaded application that listens for incoming client connections, authenticates users, and processes transactions securely.

#### **Key Features**:
- **Authentication**:
  - Passwords are hashed using [`bcrypt`](https://pypi.org/project/bcrypt/).
  - Users are authenticated through a secure key exchange protocol.
- **Key Derivation**:
  - Uses HKDF with SHA-256 to derive session keys from the `Master Secret`.
- **Secure Transactions**:
  - Processes deposits, withdrawals, and balance inquiries.
  - Verifies MACs to ensure data integrity.
- **Audit Logging**:
  - Logs transactions in both plaintext and encrypted formats.

---

### **2. ATM Client (`atm_client.py`)**
The ATM client is a Flask-based web application that acts as the user interface for the ATM service.

#### **Key Features**:
- **GUI**:
  - Provides pages for signup, login, and transactions.
- **Secure Communication**:
  - Encrypts transaction data using the derived encryption key.
  - Generates MACs for data integrity.
- **Persistent Connection**:
  - Maintains a persistent socket connection with the server during a session.

---

## **Security Features**
1. **Confidentiality**:
   - All transaction data is encrypted using the encryption key derived from the `Master Secret`.

2. **Integrity**:
   - MACs are used to ensure that transaction data has not been tampered with.

3. **Authentication**:
   - The client and server authenticate each other during the key distribution phase.

4. **Replay Protection**:
   - The use of a unique `Master Secret` for each session prevents replay attacks.

5. **Audit Logging**:
   - Transactions are logged in both plaintext and encrypted formats for accountability and debugging.

---

## **Setup Instructions**

### **1. Prerequisites**
- Python 3.8 or higher
- Required Python libraries:
  - `bcrypt`
  - `cryptography`
  - `Flask`

Install the required libraries using:
```bash
pip install bcrypt cryptography Flask
```

---

### **2. Running the Bank Server**
1. Navigate to the project directory.
2. Run the bank_server.py file:
   ```bash
   python bank_server.py
   ```
3. The server will start listening on `127.0.0.1:65432`.

---

### **3. Running the ATM Client**
1. Navigate to the project directory.
2. Run the atm_client.py file with a unique client number:
   ```bash
   python atm_client.py <client_number>
   ```
   Replace `<client_number>` with a unique number for each client (e.g., `1`, `2`, etc.).
3. Open the client in a web browser at `http://127.0.0.1:<port>`, where `<port>` is `5000 + client_number`.

---

## **Usage**

### **1. Signup**
- Navigate to the signup page.
- Enter a username and password to create an account.

### **2. Login**
- Navigate to the login page.
- Enter your credentials to log in.

### **3. Transactions**
- After logging in, navigate to the transaction page.
- Perform deposits, withdrawals, or balance inquiries.

## **Conclusion**
The Secure Banking ATM System successfully demonstrated the implementation of secure communication protocols in a client-server architecture. By integrating advanced cryptographic techniques and adhering to best practices in network security, the system ensured the confidentiality, integrity, and authenticity of sensitive financial data. This project serves as a practical application of network security principles, providing a strong foundation for further exploration and innovation in cybersecurity.
