import time
import binascii
from fastapi import FastAPI, HTTPException, Request, Header
from pydantic import BaseModel
from typing import Optional
from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware
import uvicorn
import sys
import os
import json
import logging
import traceback
import hashlib
from datetime import datetime
import secrets

# Add parent dir to path so we can import modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from server.redis_store import RedisStore
from server.session_manager import SessionManager
from server.pqc_handshake import PQCHandshakeServer
from crypto.aes_gcm import AESGCMWrapper
from crypto.dilithium import DilithiumWrapper

os.makedirs("logs", exist_ok=True)

class SecureJSONLogger:
    def __init__(self, filename="logs/authentication.log"):
        self.filename = filename
        self.last_hash = "0000000000000000000000000000000000000000000000000000000000000000"
        if os.path.exists(self.filename):
            try:
                with open(self.filename, 'r') as f:
                    lines = f.readlines()
                    if lines:
                        last_log = json.loads(lines[-1].strip())
                        self.last_hash = last_log.get("log_hash", self.last_hash)
            except Exception:
                pass

    def log(self, event: dict):
        event["timestamp"] = datetime.utcnow().isoformat()
        log_str = json.dumps(event, sort_keys=True)
        current_hash = hashlib.sha256((self.last_hash + log_str).encode()).hexdigest()
        event["log_hash"] = current_hash
        self.last_hash = current_hash
        with open(self.filename, 'a') as f:
            f.write(json.dumps(event) + "\n")

secure_logger = SecureJSONLogger()

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(message)s")

app = FastAPI(title="PQC Level 2 Prototype Server")
# Support for HTTPS Reverse Proxy Deployment
app.add_middleware(ProxyHeadersMiddleware, trusted_hosts="*")

redis_store = RedisStore(host="localhost", port=6379, db=0)
session_manager = SessionManager(redis_store)
pqc_handshake = PQCHandshakeServer()
identity_verifier = DilithiumWrapper("Dilithium3")

@app.on_event("startup")
async def startup_event():
    try:
        # Ensure Redis connection is established before handshake
        await redis_store.redis_client.ping()
        logging.info("Redis connection established successfully.")
    except Exception as e:
        logging.error(f"Redis connection failed. Ensure Redis is running: {e}")

class HandshakeRequest(BaseModel):
    client_id: str
    kyber_public_key: str  # hex string
    challenge: str         # hex string
    session_token: Optional[str] = None
    device_hash: str = "unknown"
    os_identifier: str = "unknown"

class VerifyRequest(BaseModel):
    session_token: str
    client_dilithium_pk: str
    signed_challenge: str

class SecureDataRequest(BaseModel):
    session_token: str
    nonce: str             # hex string
    ciphertext: str        # hex string
    timestamp: float = 0.0 # Replay protection timestamp

@app.post("/auth/handshake")
async def auth_handshake(req: HandshakeRequest, request: Request):
    t_start = time.perf_counter()
    ip_address = request.client.host if request.client else "unknown"
    device_fingerprint = f"{req.client_id}:{req.device_hash}:{ip_address}:{req.os_identifier}"
    
    # Rate Limiting
    if not await session_manager.check_rate_limit(req.client_id):
        secure_logger.log({"event": "rate_limit_exceeded", "client_id": req.client_id})
        raise HTTPException(status_code=429, detail="Rate limit exceeded")
    
    # Anomaly Detection check
    is_blocked = await session_manager.check_anomaly(req.client_id)
    if is_blocked:
        secure_logger.log({"event": "client_blocked", "client_id": req.client_id})
        raise HTTPException(status_code=403, detail="Too many failed attempts")

    # Level 1: Active Session Check
    if req.session_token:
        session = await session_manager.get_session(req.session_token)
        if session:
            secure_logger.log({"event": "level1_reuse", "client_id": req.client_id})
            # Legacy clients might break if we just send session_token back, but the flow accepts it.
            # We return reused: True so the client knows it skipped Kyber computation
            return {"session_token": req.session_token, "reused": True}
        
        # Level 2: Session Refresh
        client_state = await session_manager.get_client_state(req.client_id)
        if client_state and client_state.get("identity_verified"):
            if client_state.get("device_fingerprint") == device_fingerprint:
                new_token = await session_manager.create_session(req.client_id, bytes.fromhex(client_state["shared_secret"]))
                secure_logger.log({"event": "level2_refresh", "client_id": req.client_id})
                return {"session_token": new_token, "reused": True}

    # Level 3: Full Handshake Check for Challenge Replay
    if not await session_manager.store_challenge(req.challenge):
        secure_logger.log({"event": "replay_attack_detected", "client_id": req.client_id, "challenge": req.challenge})
        raise HTTPException(status_code=400, detail="Replay attack detected")
    
    # Anomaly Detection check
    is_blocked = await session_manager.check_anomaly(req.client_id)
    if is_blocked:
        logging.warning(f"BLOCKED: Client {req.client_id} has too many failed attempts.")
        raise HTTPException(status_code=403, detail="Too many failed attempts")

    try:
        pk_bytes = bytes.fromhex(req.kyber_public_key)
        challenge_bytes = bytes.fromhex(req.challenge)
    except Exception:
        await session_manager.record_failed_attempt(req.client_id)
        raise HTTPException(status_code=400, detail="Invalid hex encoding")

    try:
        # Process PQC Handshake
        ciphertext, shared_secret, signature, latencies = pqc_handshake.process_handshake(pk_bytes, challenge_bytes)
        
        # Create Session in Redis
        session_token = await session_manager.create_session(req.client_id, shared_secret)
        
        verify_challenge = secrets.token_hex(32)
        await session_manager.create_client_state(req.client_id, shared_secret, device_fingerprint)
        session_data = await session_manager.get_session(session_token)
        if session_data:
            session_data["verify_challenge"] = verify_challenge
            await session_manager.update_session(session_token, session_data)
        
        transcript = f"{req.client_id}:{req.challenge}:{ciphertext.hex()}:{signature.hex()}:{session_token}"
        handshake_hash = hashlib.sha256(transcript.encode()).hexdigest()
        
        t_total = time.perf_counter() - t_start
        secure_logger.log({"event": "handshake_success", "client_id": req.client_id, "latency": t_total})
        
        return {
            "ciphertext": ciphertext.hex(),
            "signature": signature.hex(),
            "server_dilithium_public_key": pqc_handshake.get_public_key().hex(),
            "session_token": session_token,
            "verify_challenge": verify_challenge,
            "handshake_hash": handshake_hash,
            "server_latencies": latencies
        }
    except Exception as e:
        await session_manager.record_failed_attempt(req.client_id)
        logging.error(f"Handshake failed: {traceback.format_exc()}")
        raise HTTPException(status_code=500, detail="Handshake error")

@app.post("/auth/verify")
async def auth_verify(req: VerifyRequest):
    session_data = await session_manager.get_session(req.session_token)
    if not session_data:
        raise HTTPException(status_code=401, detail="Invalid session")

    client_id = session_data["client_id"]
    verify_challenge = session_data.get("verify_challenge")
    if not verify_challenge:
        return {"status": "legacy"}
        
    try:
        pk_bytes = bytes.fromhex(req.client_dilithium_pk)
        sign_bytes = bytes.fromhex(req.signed_challenge)
        challenge_bytes = bytes.fromhex(verify_challenge)
        
        is_valid = identity_verifier.verify(pk_bytes, challenge_bytes, sign_bytes)
        if is_valid:
            await session_manager.update_client_state(client_id, {"identity_verified": True})
            secure_logger.log({"event": "identity_verified", "client_id": client_id})
            return {"status": "verified"}
        else:
            await session_manager.record_failed_attempt(client_id)
            raise HTTPException(status_code=401, detail="Verification failed")
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid payload")

@app.post("/secure/data")
async def secure_data(req: SecureDataRequest):
    """
    Receives AES-GCM encrypted data, decrypts it, and returns an encrypted ack.
    """
    # Token Replay Protection (Freshness window 30s)
    current_time = time.time()
    if req.timestamp and abs(current_time - req.timestamp) > 30:
        secure_logger.log({"event": "stale_request", "session": req.session_token})
        raise HTTPException(status_code=400, detail="Request timestamp outside freshness window")
        
    if req.nonce and not await session_manager.store_challenge(f"nonce:{req.nonce}"):
        secure_logger.log({"event": "nonce_replay", "session": req.session_token})
        raise HTTPException(status_code=400, detail="Nonce already used")

    # Verify session
    session_data = await session_manager.get_session(req.session_token)
    if not session_data:
        raise HTTPException(status_code=401, detail="Invalid or expired session token")

    client_id = session_data["client_id"]
    shared_secret = bytes.fromhex(session_data["shared_secret"])
    request_count = session_data.get("request_count", 0) + 1
    session_data["request_count"] = request_count
    
    # Key Rotation Policy
    # Uses HKDF with a fresh random salt so each rotation produces a non-deterministic key.
    # This prevents a recovered old key from being used to derive all future keys.
    created_at = session_data.get("created_at", current_time)
    key_rotated = False
    if request_count >= 100 or (current_time - created_at) > 600:
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
        from cryptography.hazmat.primitives import hashes as crypto_hashes
        rotation_salt = secrets.token_bytes(32)
        hkdf = HKDF(algorithm=crypto_hashes.SHA256(), length=32, salt=rotation_salt, info=b"pqc-key-rotation")
        new_secret = hkdf.derive(shared_secret)
        session_data["shared_secret"] = new_secret.hex()
        session_data["request_count"] = 0
        session_data["created_at"] = current_time
        key_rotated = True
        
    await session_manager.update_session(req.session_token, session_data)
    
    try:
        nonce = bytes.fromhex(req.nonce)
        ciphertext = bytes.fromhex(req.ciphertext)
        
        aes = AESGCMWrapper(shared_secret)
        
        # Decrypt to ensure data confidentiality and integrity (Auth Tag is verified here)
        plaintext = aes.decrypt(nonce, ciphertext)
        
        # Encrypt Ack response
        ack_message = f"Ack: {plaintext.decode()}".encode()
        new_nonce, new_ciphertext = aes.encrypt(ack_message)
        
        return {
            "nonce": new_nonce.hex(),
            "ciphertext": new_ciphertext.hex(),
            "key_rotated": key_rotated
        }
    except Exception as e:
        logging.error(f"Data decryption failed for {client_id}: {traceback.format_exc()}")
        raise HTTPException(status_code=400, detail="Decryption failed")

if __name__ == "__main__":
    uvicorn.run("server:app", host="0.0.0.0", port=8000, reload=True)
