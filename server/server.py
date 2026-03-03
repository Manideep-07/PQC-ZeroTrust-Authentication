import time
import binascii
from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel
import uvicorn
import sys
import os

# Add parent dir to path so we can import modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from server.redis_store import RedisStore
from server.session_manager import SessionManager
from server.pqc_handshake import PQCHandshakeServer
from crypto.aes_gcm import AESGCMWrapper
import logging
import traceback

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(message)s")

app = FastAPI(title="PQC Level 2 Prototype Server")

redis_store = RedisStore(host="localhost", port=6379, db=0)
session_manager = SessionManager(redis_store)
pqc_handshake = PQCHandshakeServer()

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

class SecureDataRequest(BaseModel):
    session_token: str
    nonce: str             # hex string
    ciphertext: str        # hex string

@app.post("/auth/handshake")
async def auth_handshake(req: HandshakeRequest):
    t_start = time.time()
    
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
        
        t_total = time.time() - t_start
        logging.info(f"Handshake successful for client {req.client_id} in {t_total:.4f}s")
        
        return {
            "ciphertext": ciphertext.hex(),
            "signature": signature.hex(),
            "server_dilithium_public_key": pqc_handshake.get_public_key().hex(),
            "session_token": session_token,
            # Returning latencies to the client so the client can log them along with client-side latencies
            "server_latencies": latencies
        }
    except Exception as e:
        await session_manager.record_failed_attempt(req.client_id)
        logging.error(f"Handshake failed: {traceback.format_exc()}")
        raise HTTPException(status_code=500, detail="Handshake error")

@app.post("/secure/data")
async def secure_data(req: SecureDataRequest):
    """
    Receives AES-GCM encrypted data, decrypts it, and returns an encrypted ack.
    """
    # Verify session
    session_data = await session_manager.get_session(req.session_token)
    if not session_data:
        raise HTTPException(status_code=401, detail="Invalid or expired session token")

    client_id = session_data["client_id"]
    shared_secret = bytes.fromhex(session_data["shared_secret"])
    
    try:
        nonce = bytes.fromhex(req.nonce)
        ciphertext = bytes.fromhex(req.ciphertext)
        
        aes = AESGCMWrapper(shared_secret)
        
        # Decrypt to ensure data confidentiality and integrity (Auth Tag is verified here)
        plaintext = aes.decrypt(nonce, ciphertext)
        logging.info(f"Received secure message from {client_id}: {plaintext.decode()}")
        
        # Encrypt Ack response
        ack_message = f"Ack: {plaintext.decode()}".encode()
        new_nonce, new_ciphertext = aes.encrypt(ack_message)
        
        return {
            "nonce": new_nonce.hex(),
            "ciphertext": new_ciphertext.hex()
        }
    except Exception as e:
        logging.error(f"Data decryption failed for {client_id}: {traceback.format_exc()}")
        raise HTTPException(status_code=400, detail="Decryption failed")

if __name__ == "__main__":
    uvicorn.run("server:app", host="0.0.0.0", port=8000, reload=True)
