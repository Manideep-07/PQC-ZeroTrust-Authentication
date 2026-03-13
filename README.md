![Python](https://img.shields.io/badge/Python-3.8+-blue)
![Framework](https://img.shields.io/badge/FastAPI-Async-green)
![Crypto](https://img.shields.io/badge/Cryptography-Post--Quantum-purple)
![License](https://img.shields.io/badge/License-MIT-yellow)

# Post-Quantum Cryptography (PQC) Secure Communication System

## What is this project?
This project is an advanced, high-security communication system that uses **Post-Quantum Cryptography (PQC)**. 
In simple terms, it is a chat/communication system built to be completely secure against future **Quantum Computers**. Quantum computers are incredibly powerful upcoming machines that will easily break today's normal security and passwords. This project uses the security of tomorrow, today.

It implements a **Zero Trust Architecture**, treating every connection as potentially dangerous until it proves its identity using state-of-the-art quantum-safe algorithms.

### The Core Technology
Instead of older security like RSA or ECC, we use the official **NIST-standardized Post-Quantum algorithms**:
- **Kyber768 (Key Exchange)**: Used to safely share a secret password over the internet without anyone else being able to read it.
- **Dilithium3 (Digital Signatures)**: Used like an unforgeable digital fingerprint to prove the identity of the client connecting.
- **AES-256-GCM (Data Encryption)**: Used to lock the actual messages being sent back and forth so no hacker can read them.
- **Redis (Session Storage)**: Used by our server to quickly and safely remember logged-in users, allowing multiple clients to connect at the same time.

---

## How it works (The Quantum-Safe Handshake)
When a client tries to connect to the server, an ultra-secure "handshake" happens in milliseconds:

1. **Client says Hello:** The client generates its Kyber and Dilithium keys and sends a request to the server.
2. **Server Verifies Identity:** The server checks the client's Dilithium signature to make sure they are exactly who they claim to be.
3. **Key Exchange (The Secret):** The server creates a mathematical "challenge", encrypts it using the client's Kyber public key, and sends it back. 
4. **The Secret Tunnel:** The client successfully decrypts it. Now, both the client and server combine this shared secret to create a master **AES-256** key.
5. **Secure Chat:** From this point on, every single message sent is locked inside AES-256-GCM encryption. Even a quantum computer listening in cannot read the messages!

---

## Technical Details & Architecture
This system is built using modern infrastructure and key libraries:
- **FastAPI / Uvicorn (Python)**: The fast, asynchronous web framework running our core Server.
- **liboqs**: The official Open Quantum Safe C-library that provides us with the Kyber and Dilithium mathematical algorithms.
- **Redis**: An external, extremely fast database used to store active client sessions securely.
- **Cryptography**: Used for the AES-256-GCM symmetric encryption to secure all chat messages after the handshake.
- **Pytest**: A testing library used to run all of our automated tests to ensure the system is stable and secure over time.

### Development Best Practices (.venv and Test Environments)
When working on this project (or setting it up yourself), you will notice a `.venv` folder and test systems in place. 

- **The `.venv` (Virtual Environment)**: This is an isolated "sandbox" for our project's dependencies. By installing all of our libraries (`FastAPI`, `redis`, `cryptography`, etc.) inside this `.venv` folder, we guarantee they won't conflict with any other Python projects on your computer. It keeps your system clean and ensures anyone else running the code gets the exact same correct versions of every library.
- **The Test Environment**: When dealing with advanced security software, it must be completely flawless. We use a dedicated test environment (like `tests/system_test.py`) to safely test our code without breaking the real running server or messing up real user sessions. It allows us to simulate multiple clients connecting at once to verify that our Kyber/Dilithium algorithms work perfectly under stress before ever seeing "real" use.

---

## How to Run It!

### 1. Prerequisites
- **Python 3.8+** installed on your computer.
- **Redis Server** installed and running on your active machine.
- The `liboqs.dll` (for Windows) must be downloaded or compiled and placed in the project's root folder.

### 2. Install Packages
Open your terminal inside the project folder and run:
```bash
pip install -r requirements.txt
```

### 3. Start the Server
Open your terminal and start the Post-Quantum backend server:
```bash
python -m uvicorn server.main:app --host 0.0.0.0 --port 8000
```
*(Remember, your Redis server must be running in the background for sessions to work!)*

### 4. Run the Client
Open a **second terminal window** (leave the server running) and start the client:
```bash
python client/client.py
```
Watch the console as the client successfully performs the PQC handshake, verifies its Dilithium signature with the server, and establishes a quantum-safe connection!

### 5. Running Tests
Want to make sure everything works perfectly? The system comes with an automated testing pipeline.
```bash
python tests/system_test.py
```
This will test the Kyber encapsulation, Dilithium signatures, AES encryption, Redis connectivity, and multi-client latency.

---

## Sample Outputs

### 1. Server Output
When you start the server and a client connects, you will see a secure handshake process happening in real-time:
```text
INFO:     Started server process [12345]
INFO:     Waiting for application startup.
INFO:     Application startup complete.
INFO:     Uvicorn running on http://0.0.0.0:8000
INFO:     127.0.0.1:54321 - "POST /auth/request HTTP/1.1" 200 OK
INFO:     Zero Trust: Client Dilithium signature authenticated successfully!
INFO:     127.0.0.1:54321 - "POST /auth/exchange HTTP/1.1" 200 OK
INFO:     Zero Trust: Kyber Key exchange completed & Shared Secret Generated.
```

### 2. Client Output
When you run the client script (`python client/client.py`), it initiates a multi-client concurrent load test to see how the server handles multiple PQC handshakes at once:
```text
Starting Multi-Client Concurrent Load Test...
[client_001] Starting PQC Client Handshake...
[client_001] Sending handshake request to http://127.0.0.1:8000/auth/handshake
[client_002] Starting PQC Client Handshake...
[client_002] Sending handshake request to http://127.0.0.1:8000/auth/handshake
[client_003] Starting PQC Client Handshake...
[client_003] Sending handshake request to http://127.0.0.1:8000/auth/handshake
[client_004] Starting PQC Client Handshake...
[client_004] Sending handshake request to http://127.0.0.1:8000/auth/handshake
[client_005] Starting PQC Client Handshake...
[client_005] Sending handshake request to http://127.0.0.1:8000/auth/handshake
[client_002] Handshake Successful. Shared AES Key Derived! Total time: 4.9059s
[client_004] Handshake Successful. Shared AES Key Derived! Total time: 2.4850s
[client_001] Handshake Successful. Shared AES Key Derived! Total time: 6.3426s
[client_003] Handshake Successful. Shared AES Key Derived! Total time: 3.7279s
[client_005] Handshake Successful. Shared AES Key Derived! Total time: 1.2885s
[client_002] Received Ack: Ack: Hello from client_002, here is highly sensitive data.
[client_004] Received Ack: Ack: Hello from client_004, here is highly sensitive data.
[client_001] Received Ack: Ack: Hello from client_001, here is highly sensitive data.
[client_003] Received Ack: Ack: Hello from client_003, here is highly sensitive data.
[client_005] Received Ack: Ack: Hello from client_005, here is highly sensitive data.
All clients finished!
```

### 3. Comprehensive System Test Output
When you run the automated system test (`python tests/system_test.py`), it automatically verifies all cryptography components, simulates multiple concurrent clients to check server load, and generates exact latency logging metrics:

```text
--- Running Functional Tests ---
[test_client_0] Kyber Verification PASS: Shared secrets match.
[test_client_0] Dilithium Verification PASS: Signature verified and rejected bad signature.
[test_client_0] Identity Verification PASS.
[test_client_0] AES Verification PASS: Data encrypted/decrypted successfully and integrity verified.
[test_client_0] Redis Session Verification PASS: Session stored and expiry enforced.

Starting Concurrency Test...
[concurrent_client_1] Kyber Verification PASS: Shared secrets match.
[concurrent_client_2] Kyber Verification PASS: Shared secrets match.
[concurrent_client_3] Kyber Verification PASS: Shared secrets match.
[concurrent_client_4] Kyber Verification PASS: Shared secrets match.
[concurrent_client_5] Kyber Verification PASS: Shared secrets match.
... 
Concurrency Verification PASS: 5 clients handled concurrently with isolated sessions.
Latency Logging Verification PASS: Benchmarking file populated correctly.

=====================================
FINAL RESULT
=====================================
Kyber Test: PASS
Dilithium Test: PASS
AES Test: PASS
Redis Test: PASS
Concurrency Test: PASS
Latency Logging Test: PASS

=====================================
PERFORMANCE METRICS
=====================================
Average Handshake Time:  0.082415 s
Min Handshake Time:      0.071249 s
Max Handshake Time:      0.095112 s
Kyber Encapsulation Avg: 0.006241 s
Dilithium Signing Avg:   0.009182 s
AES Encryption Avg:      0.000142 s
Total Simulation Time:   0.812450 s
```

---
## Why is this important?
As quantum computers become a reality over the next 5 to 10 years, almost all modern internet encryption (like the HTTPS lock in your browser today) will become easily breakable. Projects like this are critical steps forward, implementing the newly officially standardized algorithms (Kyber and Dilithium) to ensure our data internet infrastructure remains safe against "harvest now, decrypt later" attacks.

---

### How This GitHub Distribution ZIP Was Prepared
The project was analyzed before creating this ZIP version. Some files were detected as heavy or system-dependent (e.g., C-library binaries, virtual environments, cache, and logs). Those files were intentionally excluded from the ZIP distribution version to keep the repository lightweight and uploadable. During the preparation process, Antigravity analyzed how those files were used in the original project environment. **Antigravity recreated the required setup locally during testing to ensure the project works correctly even though those files are not bundled in the ZIP.** The instructions below explain exactly how Antigravity configured the environment and how users can reproduce the same setup.

---

### Important Note for Downloaders (Missing Heavy Files)
To keep this GitHub repository fast and lightweight, certain large binaries and environment artifacts were excluded.
Here is exactly what was removed and why:
- `.venv/` and `test_env/`: Python virtual environment folders, excluded because they are system-dependent caching systems that vary across computers.
- `logs/`, `*.csv`, `project_test_output.txt`: Generated runtime metrics and test outputs, removed to preserve a clean starting state.
- `.vscode/`: IDE configuration cache, safely excluded as it is local workspace config.
- `liboqs.dll`: The core Post-Quantum cryptographic library. This is a heavy compiled C-library binary (approx. 2.8 MB) explicitly built for a specific OS and CPU architecture. Thus, it cannot be safely bundled directly inside a cross-platform ZIP.

**How Antigravity handled this locally:**
During repository preparation, Antigravity evaluated the project logic. It identified transient artifacts safely capable of being ignored. More importantly, it determined that `liboqs.dll` was a critical, mandatory runtime component, mapped out its loading path, and verified it actively within the local environment before generating this ZIP.

---

### Environment Setup and Recreation
To recreate the exact same development environment used by the original author and verified by Antigravity, follow these steps step-by-step:

#### 1. Creating the Virtual Environment
First, you must create an isolated workspace to avoid Python package conflicts across your system:
```bash
python -m venv .venv

# On Windows:
.venv\Scripts\activate

# On Linux/Mac:
source .venv/bin/activate
```

#### 2. Installing Dependencies
With the standard `.venv` activated, install all required Python packages mapped inside `requirements.txt`:
```bash
pip install -r requirements.txt
```

#### 3. Ensuring Redis is Running
The server requires a local database instance of **Redis Server** actively running in the background. It serves as an ultra-fast backend for safely managing PQC user session tokens dynamically. Ensure Redis is installed on your OS and the service is actively running on its default port.

#### 4. The `liboqs.dll` Shared Library Requirement (Mandatory)
**What it is:** `liboqs.dll` is the official compiled Open Quantum Safe C-library. It calculates the underlying mathematical algorithms making Kyber768 (KEM) and Dilithium3 (Signatures) operate.
**Compatible Version:** The project requires a robust build compatible with `pyoqs` (such as the liboqs 0.8.0 / 0.9.x series).
**Where to download:** You can securely download, compile or retrieve an official compiled release directly from the [Open Quantum Safe GitHub repository](https://github.com/open-quantum-safe/liboqs/releases).
**How to install:** Download the binary file targeting your OS.
**Exact folder location:** You MUST copy the `liboqs.dll` (or `.so`/`.dylib` equivalent) file explicitly into the **project root directory** (the exact same folder holding `server`, `client`, `crypto` folders, and this `README.md`).

**Validation completed:**
**During preparation of the GitHub distribution ZIP, Antigravity verified the project locally by placing the `liboqs.dll` file in the project root directory so that the PQC cryptographic algorithms could load correctly at runtime.**

---

### How Antigravity Fixed the `liboqs.dll` Dependency During Local Development

When the project was first executed during development, the runtime attempted to load the PQC cryptographic algorithms through the `liboqs` shared library. Because the `liboqs.dll` library was not yet present in the development environment, the Python runtime produced a shared library loading error when attempting to initialize the PQC algorithms. 

During the initial setup of the project environment, Antigravity analyzed the dependency requirements of the PQC implementation and determined that the Open Quantum Safe `liboqs` shared library must be available locally for the algorithms (Kyber and Dilithium) to work. 

Users downloading this repository must reproduce this exact same step before running the server. You must download and place `liboqs.dll` directly into the **project root directory**. 

**What is the project root directory?**
The "root directory" is the main, top-level project folder that contains all the foundational files and directories. Specifically, it is the folder that contains:
- `README.md`
- `requirements.txt`
- `server/` (folder)
- `client/` (folder)

You must place `liboqs.dll` inside this exact same directory alongside these files before starting the server. This is **the exact same dependency fix applied during the original local development and testing of the project**, which keeps this GitHub repository lightweight and portable by intentionally opting not to include the heavy, system-dependent binary file in the download.

---

### Running the Project
Once the `.venv` is active, dependencies are installed, Redis is running, and `liboqs.dll` is placed in the project root directory:

1. **Start the server first:**
```bash
python -m uvicorn server.main:app --host 0.0.0.0 --port 8000
```
2. **Start the client (in a separate terminal):**
```bash
python client/client.py
```
3. **Run the tests (optional):**
```bash
python tests/system_test.py
```

---

### Notes for AI Agents
This version of the project is intentionally structured and simplified so that AI assistants such as ChatGPT, Gemini, Claude, and other code analysis tools can easily analyze the repository structure, review the integration points, and read the components (such as Kyber KEM, Dilithium Signatures, AES-GCM integration, and FastAPI backend) effectively without getting stuck on environment cache files or large generated logs.


---

## Project Directory Structure

```
project/
│
├── client/          # Client implementation for PQC handshake
├── server/          # FastAPI-based secure communication server
├── crypto/          # Kyber, Dilithium and AES encryption modules
├── benchmarking/    # Performance metrics and latency logging
├── tests/           # Automated system and concurrency tests
│
├── requirements.txt
├── README.md
├── architecture.md
└── CUDA_INTEGRATION.md
```


---

## GitHub Topics / Tags

post-quantum-cryptography  
pqc  
kyber  
dilithium  
cryptography  
cybersecurity  
fastapi  
zero-trust  
python  
