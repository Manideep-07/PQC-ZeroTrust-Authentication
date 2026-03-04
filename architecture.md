# Post-Quantum Zero Trust Architecture

## System Overview
This project implements a **Zero Trust Authentication System** secured by **Post-Quantum Cryptography (PQC)**. It uses a hybrid approach combining next-generation NIST-standard algorithms (Kyber, Dilithium) with classical symmetric encryption (AES-GCM) to ensure security against both classical and quantum threats.

The architecture is a **Client-Server** model where the server adheres to "Never Trust, Always Verify" principles.

### Key Features
- **PQC Authentication**: Identity verification using **Dilithium2** signatures.
- **PQC Key Exchange**: Secure key establishment using **Kyber512** Key Encapsulation Mechanism (KEM).
- **Zero Trust Verification**: Challenge-response mechanism to prove possession of the negotiated key before granting access.
- **Low Latency Resumption**: Session token-based resumption for fast 0-RTT-like re-connection (currently implemented in v2.0).

---

## Cryptographic Stack

| Component | Algorithm | Purpose | Implementation |
| :--- | :--- | :--- | :--- |
| **KEM** | **Kyber512** | Key Exchange / Shared Secret Establishment | `liboqs` (or simulation) |
| **Signature** | **Dilithium2** | Identity Authentication / Non-repudiation | `liboqs` (or simulation) |
| **Symmetric** | **AES-256-GCM** | Secure Channel / Data Encryption | `cryptography` (Python) |

---

## Architecture Diagrams

### 1. System Components
```mermaid
graph TD
    subgraph Client ["Client (Untrusted)"]
        C_Auth[Authenticator]
        C_KEM[Kyber Decapsulator]
        C_Sign[Dilithium Signer]
        C_Store[Session Store]
    end

    subgraph Server ["Zero Trust Server (FastAPI)"]
        API[API Layer]
        ZT_Core[Zero Trust Core]
        S_KEM[Kyber Encapsulator]
        S_Ver[Dilithium Verifier]
        KM[Key Manager]
        DB[(In-Memory Session Store)]
    end

    C_Sign -->|Sign Request| API
    API -->|Verify| S_Ver
    API -->|Encap Secret| S_KEM
    S_KEM -->|Ciphertext| C_KEM
    C_KEM -->|Shared Secret| C_Auth
    C_Auth -->|Encrypted Challenge| API
    API -->|Validate| ZT_Core
    ZT_Core -->|Session Token| DB
```

### 2. Full Handshake Flow (PQC Heavy)
This flow runs when a client connects for the first time or after a session expires.

```mermaid
sequenceDiagram
    participant C as Client
    participant S as Server
    
    Note over C,S: Phase 1: Authentication (Dilithium)
    C->>C: Generate Ephemeral Kyber Keys
    C->>C: Sign(ClientID + KyberPub + Timestamp) using Dilithium
    C->>S: POST /auth/request (Keys + Signature)
    S->>S: Verify Dilithium Signature
    S->>S: Check Timestamp (Replay Protection)
    S-->>C: 200 OK (Authenticated)

    Note over C,S: Phase 2: Key Exchange (Kyber)
    C->>S: POST /auth/exchange
    S->>S: Generate Shared Secret
    S->>S: Kyber Encapsulate -> Ciphertext
    S->>S: Encrypt Challenge (AES-GCM derived from Secret)
    S-->>C: 200 OK (Ciphertext + Encrypted Challenge)

    Note over C,S: Phase 3: Zero Trust Verification
    C->>C: Kyber Decapsulate(Ciphertext) -> Shared Secret
    C->>C: Derive AES Key
    C->>C: Decrypt Challenge & Re-Encrypt
    C->>S: POST /auth/challenge (Encrypted Proof)
    S->>S: Decrypt & Verify Challenge Match
    S->>S: Generate Session Token
    S-->>C: 200 OK (Session Token)

    Note over C,S: Secure Channel Established
    C->>S: POST /secure/message (AES-GCM Encrypted)
    S-->>C: 200 OK (Encrypted Response)
```

### 3. Session Resumption Flow (Low Latency)
This flow is used when a valid `session_token` exists. It avoids the heavy PQC math.

```mermaid
sequenceDiagram
    participant C as Client
    participant S as Server

    C->>C: Load Session Token & AES Key
    C->>S: POST /auth/resume (Token + ClientID)
    S->>S: Lookup Token in Store
    S->>S: Check Expiry
    alt Valid Session
        S-->>C: 200 OK (Session Resumed)
        Note over C,S: Immediate Secure Channel
        C->>S: POST /secure/message
    else Invalid/Expired
        S-->>C: 401 Unauthorized
        C->>C: Fallback to Full Handshake
    end
```

## Directory Structure Analysis
- `client/`: Contains the client implementation logic.
- `server/`: Contains the FastAPI application (`main.py`) and the core logic (`zero_trust.py`).
- `crypto/`: Wrappers for PQC algorithms (`pqc_kem.py`, `pqc_signer.py`) and standard crypto (`aes_gcm.py`).
- `liboqs/`: The underlying C library binding for Post-Quantum algorithms.
