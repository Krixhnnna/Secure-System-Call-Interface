# 🔐 Secure System Call Interface

A secure simulation layer for system calls with **authentication**, **role-based access control (RBAC)**, and **audit logging**.

---

## ✨ Features

### 🛡️ Secure File Operations
- Safe wrappers for:
  - Read  
  - Write  
  - Delete  
- All operations pass through security validation

### 🔑 Authentication System
- Admin approval required for new accounts  
- Account lockout after **3 failed login attempts**  
- Role-based access:
  - **Admin**
  - **User**

### 📜 Audit Logging
- Every action is logged for traceability  
- Logs stored locally in `system_calls.log`

---

## 🚀 How to Run

This project has been consolidated for simplicity. It features two ways to interact with the system: a native C Console Application or a Node.js Web Interface!

### 💻 1. Run the C Console Application

Since the code is unified into a single file, compilation is very straightforward:

```bash
# 1. Compile the C code
gcc main.c -Wall -o secure_posix.exe

# 2. Run the executable
# On Mac/Linux:
./secure_posix.exe

# On Windows:
secure_posix.exe
```

### 🌐 2. Run the Web Interface (Node.js)

The project also includes a sleek web simulation backend.

```bash
# 1. Install dependencies (if you haven't)
npm install

# 2. Start the web server
node server.js
```

Once the server says it's running, open your browser and navigate to:
👉 **[http://localhost:8000](http://localhost:8000)**

---
### 📂 Clean Directory Structure
```
.
├── main.c              # Unified core C logic
├── secure_posix.exe    # Compiled executable
├── server.js           # Node.js backend
├── public/             # Web interface files
├── system_calls.log    # Audit log
└── package.json        # Node dependencies
```