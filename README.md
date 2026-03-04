Post-Quantum Zero Trust Authentication System
📌 Project Overview
This project implements a Post-Quantum Cryptography (PQC) based Zero-Trust Authentication Framework using modern cryptographic primitives resistant to quantum attacks.

It is developed as a Level 2 Research Prototype, supporting:

Multi-client authentication
Post-Quantum secure key exchange
Digital signature verification
Secure AES session encryption
Redis-backed session management
Concurrency & latency benchmarking
CUDA-ready build environment
🔐 Cryptographic Stack
Component Algorithm Purpose

Key Exchange Kyber768 Post-Quantum shared secret generation Digital Signature Dilithium Server authentication & integrity Symmetric Encryption AES-256-GCM Secure session communication

All PQC primitives are powered by liboqs (Open Quantum Safe).

🏗 System Architecture
Client → PQC Handshake → Server
Kyber → Shared Secret
Dilithium → Signature Verification
AES-GCM → Secure Data Channel
Redis → Session Storage & Zero-Trust Tracking

🚀 Features
✔ Multi-client concurrent handshake simulation
✔ Redis session persistence
✔ Zero-trust challenge-response validation
✔ Latency logging & benchmarking
✔ Secure token reuse mechanism
✔ Modular crypto wrappers
✔ CUDA integration ready
🧪 How To Run
1️⃣ Create Virtual Environment
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
2️⃣ Start Redis Server
Ensure Redis is running on:

localhost:6379
3️⃣ Start FastAPI Server
uvicorn server.server:app --host 127.0.0.1 --port 8000 --workers 4
4️⃣ Run System Test
python tests/system_test.py
Expected Final Output:

FINAL RESULT
Kyber Test: PASS
Dilithium Test: PASS
AES Test: PASS
Redis Test: PASS
Concurrency Test: PASS
Latency Logging Test: PASS
📊 Research Level Implementation
✔ Level 1 -- Academic Prototype
✔ Level 2 -- Advanced Multi-Client Research Prototype
✔ Post-Quantum Secure Handshake
✔ Redis-backed Zero Trust Model
✔ Latency Benchmarking
✔ CUDA Ready Build

🔮 Future Scope
GPU Acceleration using CUDA
Distributed multi-node PQC authentication
Hardware Security Module (HSM) integration
Post-Quantum TLS integration
ML-based anomaly detection
📚 Technologies Used
Python 3.12+
FastAPI
liboqs
Redis
asyncio
cryptography
CMake + MSVC (for liboqs build)
CUDA (optional integration)
👨‍💻 Author
Final Year Research Project
Post-Quantum Zero Trust Authentication Framework
