import asyncio
import httpx
import time
import os
import secrets
import sys

# Add parent dir to path so we can import modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from crypto.kyber import KyberWrapper
from crypto.dilithium import DilithiumWrapper
from crypto.aes_gcm import AESGCMWrapper
from benchmarking.latency_logger import LatencyLogger

async def run_client(client_id: str, logger: LatencyLogger):
    print(f"[{client_id}] Starting PQC Client Handshake...")
    base_url = "http://127.0.0.1:8000"
    
    t_handshake_start = time.time()
    
    # Initialize Wrappers
    kyber = KyberWrapper("Kyber768")
    dilithium = DilithiumWrapper("Dilithium3")
    
    # 1. Generate Kyber Key Pair
    t_start_keygen = time.time()
    kyber_pk, kyber_sk = kyber.generate_keypair()
    t_keygen = time.time() - t_start_keygen
    
    # 2. Challenge
    challenge = secrets.token_bytes(32)

    async with httpx.AsyncClient() as client:
        # Send Handshake Request
        payload = {
            "client_id": client_id,
            "kyber_public_key": kyber_pk.hex(),
            "challenge": challenge.hex()
        }
        
        print(f"[{client_id}] Sending handshake request to {base_url}/auth/handshake")
        try:
            resp = await client.post(f"{base_url}/auth/handshake", json=payload, timeout=10.0)
            resp.raise_for_status()
        except Exception as e:
            print(f"[{client_id}] Handshake failed: {e}")
            return
            
        data = resp.json()
        ciphertext = bytes.fromhex(data["ciphertext"])
        signature = bytes.fromhex(data["signature"])
        server_dilithium_pk = bytes.fromhex(data["server_dilithium_public_key"])
        session_token = data["session_token"]
        server_latencies = data["server_latencies"]
        
        # 3. Verify Server Signature
        message_to_verify = challenge + ciphertext
        t_start_verify = time.time()
        is_valid = dilithium.verify(server_dilithium_pk, message_to_verify, signature)
        t_verify = time.time() - t_start_verify
        
        if not is_valid:
            print(f"[{client_id}] MITM Error! Signature verification failed.")
            return
            
        # 4. Decapsulate Shared Secret
        t_start_decap = time.time()
        shared_secret = kyber.decapsulate(ciphertext)
        t_decap = time.time() - t_start_decap

        t_handshake_end = time.time()
        total_time = t_handshake_end - t_handshake_start
        print(f"[{client_id}] Handshake Successful. Shared AES Key Derived! Total time: {total_time:.4f}s")
        
        # 5. Encrypt data and send
        aes = AESGCMWrapper(shared_secret)
        secret_msg = f"Hello from {client_id}, here is highly sensitive data."
        
        t_start_encrypt = time.time()
        nonce, ct = aes.encrypt(secret_msg.encode())
        t_encrypt = time.time() - t_start_encrypt

        # Send encrypted data
        secure_payload = {
            "session_token": session_token,
            "nonce": nonce.hex(),
            "ciphertext": ct.hex()
        }
        try:
            secure_resp = await client.post(f"{base_url}/secure/data", json=secure_payload, timeout=5.0)
            secure_resp.raise_for_status()
            s_data = secure_resp.json()
            decrypted_ack = aes.decrypt(bytes.fromhex(s_data["nonce"]), bytes.fromhex(s_data["ciphertext"]))
            print(f"[{client_id}] Received Ack: {decrypted_ack.decode()}")
        except Exception as e:
            print(f"[{client_id}] Secure data sending failed: {e}")

        # Log Metrics
        metrics = {
            "client_id": client_id,
            "kyber_keygen_time": t_keygen,
            "kyber_encap_time": server_latencies["kyber_encap_time"],
            "kyber_decap_time": t_decap,
            "dilithium_sign_time": server_latencies["dilithium_sign_time"],
            "dilithium_verify_time": t_verify,
            "aes_encryption_time": t_encrypt,
            "total_handshake_time": total_time
        }
        logger.log_metrics(metrics)

async def main():
    logger = LatencyLogger()
    print("Starting Multi-Client Concurrent Load Test...")
    
    # Create 5 concurrent clients
    tasks = []
    for i in range(1, 6):
        client_id = f"client_00{i}"
        tasks.append(run_client(client_id, logger))
        
    await asyncio.gather(*tasks)
    print("All clients finished!")

if __name__ == "__main__":
    asyncio.run(main())
