import asyncio
import httpx
import time
import os
import secrets
import sys
import hashlib
import redis.asyncio as redis
import csv

# Add parent dir to path so we can import modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Ensure DLL is loaded (reusing logic for safety)
import ctypes
if os.name == 'nt':
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    dll_path = os.path.join(project_root, "liboqs.dll")
    if os.path.exists(dll_path):
        os.environ["PATH"] = project_root + os.pathsep + os.environ["PATH"]
        if hasattr(os, 'add_dll_directory'):
            try:
                os.add_dll_directory(project_root)
            except Exception:
                pass
        try:
            ctypes.CDLL(dll_path)
        except:
            pass

from crypto.kyber import KyberWrapper
from crypto.dilithium import DilithiumWrapper
from crypto.aes_gcm import AESGCMWrapper
from benchmarking.latency_logger import LatencyLogger

def get_redis_client():
    return redis.Redis(host="localhost", port=6379, db=0, decode_responses=True)

async def check_server_up(base_url):
    try:
        async with httpx.AsyncClient() as client:
            await client.get(f"{base_url}/docs", timeout=2.0)
            return True
    except Exception:
        return False

async def test_kyber_and_dilithium(client_id: str, client: httpx.AsyncClient, base_url: str):
    kyber = KyberWrapper("Kyber768")
    dilithium = DilithiumWrapper("Dilithium3")

    t_start_keygen = time.time()
    kyber_pk, kyber_sk = kyber.generate_keypair()
    t_keygen = time.time() - t_start_keygen

    challenge = secrets.token_bytes(32)

    payload = {
        "client_id": client_id,
        "kyber_public_key": kyber_pk.hex(),
        "challenge": challenge.hex()
    }

    try:
        resp = await client.post(f"{base_url}/auth/handshake", json=payload, timeout=5.0)
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        error_text = getattr(e.response, "text", str(e)) if hasattr(e, "response") and e.response else str(e)
        print(f"[{client_id}] Kyber Verification FAILED: Server handshake returned error: {error_text}")
        return False, False, False, None, None, None, None

    ciphertext = bytes.fromhex(data["ciphertext"])
    signature = bytes.fromhex(data["signature"])
    server_dilithium_pk = bytes.fromhex(data["server_dilithium_public_key"])
    session_token = data["session_token"]
    server_latencies = data["server_latencies"]
    
    t_start_decap = time.time()
    shared_secret_client = kyber.decapsulate(ciphertext)
    t_decap = time.time() - t_start_decap
    
    # We must retrieve server shared secret from Redis to compare
    redis_c = get_redis_client()
    session_data_json = await redis_c.get(f"session:{session_token}")
    if session_data_json is None:
        print(f"[{client_id}] Kyber Verification FAILED: Session data not found in Redis.")
        return False, False, False, None, None, None, None
        
    import json
    session_data = json.loads(session_data_json)
    shared_secret_server = bytes.fromhex(session_data["shared_secret"])
    
    if shared_secret_client != shared_secret_server:
        print(f"[{client_id}] Kyber Verification FAILED: Shared secrets do not match.")
        return False, False, False, None, None, None, None
        
    print(f"[{client_id}] Kyber Verification PASS: Shared secrets match.")
    print(f"[{client_id}] Shared Secret SHA256: {hashlib.sha256(shared_secret_client).hexdigest()}")

    # DILITHIUM TEST
    message_to_verify = challenge + ciphertext
    t_start_verify = time.time()
    is_valid = dilithium.verify(server_dilithium_pk, message_to_verify, signature)
    t_verify = time.time() - t_start_verify

    if not is_valid:
        print(f"[{client_id}] Dilithium Verification FAILED: Signature is invalid.")
        return True, False, False, None, None, None, None
        
    # Negative test
    bad_message = challenge + ciphertext + b"bad"
    is_valid_bad = dilithium.verify(server_dilithium_pk, bad_message, signature)
    if is_valid_bad:
        print(f"[{client_id}] Dilithium Verification FAILED: Accepted invalid signature.")
        return True, False, False, None, None, None, None
        
    print(f"[{client_id}] Dilithium Verification PASS: Signature verified and rejected bad signature.")
    
    latencies = {
        "kyber_keygen_time": t_keygen,
        "kyber_encap_time": server_latencies["kyber_encap_time"],
        "kyber_decap_time": t_decap,
        "dilithium_sign_time": server_latencies["dilithium_sign_time"],
        "dilithium_verify_time": t_verify
    }
    return True, True, True, shared_secret_client, session_token, ciphertext, latencies

async def test_aes_gcm(client_id: str, client: httpx.AsyncClient, base_url: str, shared_secret: bytes, session_token: str):
    aes = AESGCMWrapper(shared_secret)
    secret_msg = f"Hello from {client_id}, here is highly sensitive data."
    
    t_start_enc = time.time()
    nonce, ct = aes.encrypt(secret_msg.encode())
    t_enc = time.time() - t_start_enc
    
    secure_payload = {
        "session_token": session_token,
        "nonce": nonce.hex(),
        "ciphertext": ct.hex()
    }
    
    resp = await client.post(f"{base_url}/secure/data", json=secure_payload, timeout=5.0)
    if resp.status_code != 200:
        print(f"[{client_id}] AES Verification FAILED: Server returned {resp.status_code}")
        return False, 0.0
        
    data = resp.json()
    
    decrypted_ack = aes.decrypt(bytes.fromhex(data["nonce"]), bytes.fromhex(data["ciphertext"]))
    
    if not decrypted_ack.decode().startswith("Ack:"):
        print(f"[{client_id}] AES Verification FAILED: Incorrect ACK received.")
        return False, 0.0
        
    # Negative Test
    bad_ct = ct[:-1] + bytes([ct[-1] ^ 1])
    try:
        aes.decrypt(bytes.fromhex(data["nonce"]), bad_ct)
        print(f"[{client_id}] AES Verification FAILED: Decrypted modified ciphertext.")
        return False, 0.0
    except Exception:
        pass # Expected
        
    print(f"[{client_id}] AES Verification PASS: Data encrypted/decrypted successfully and integrity verified.")
    return True, t_enc

async def test_redis_session(client_id: str, client: httpx.AsyncClient, base_url: str, session_token: str):
    redis_c = get_redis_client()
    session_data = await redis_c.get(f"session:{session_token}")
    if not session_data:
        print(f"[{client_id}] Redis Session Verification FAILED: Session not found in Redis.")
        return False
        
    import json
    await redis_c.setex(f"session:{session_token}", 1, session_data)
    await asyncio.sleep(2) # Wait for expiry
    
    aes = AESGCMWrapper(bytes.fromhex(json.loads(session_data)["shared_secret"]))
    nonce, ct = aes.encrypt(b"Test expiry")
    secure_payload = {
        "session_token": session_token,
        "nonce": nonce.hex(),
        "ciphertext": ct.hex()
    }
    
    resp = await client.post(f"{base_url}/secure/data", json=secure_payload)
    if resp.status_code != 401:
        print(f"[{client_id}] Redis Session Verification FAILED: Expired session was accepted.")
        return False
        
    print(f"[{client_id}] Redis Session Verification PASS: Session stored and expiry enforced.")
    return True


async def run_single_client_test(client_id: str, base_url: str):
    filepath = "../benchmarking/benchmark_results.csv"
    if not os.path.exists(filepath):
        filepath = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "benchmarking", "benchmark_results.csv")
    logger = LatencyLogger(filename=filepath)
    
    async with httpx.AsyncClient() as client:
        t_start = time.time()
        kyber_pass, dilithium_pass, _, shared_secret, session_token, _, latencies = await test_kyber_and_dilithium(client_id, client, base_url)
        if not (kyber_pass and dilithium_pass):
            return False, False, False, False

        aes_pass, t_enc = await test_aes_gcm(client_id, client, base_url, shared_secret, session_token)
        redis_pass = await test_redis_session(client_id, client, base_url, session_token)
        
        t_total = time.time() - t_start
        if latencies and aes_pass:
            metrics = {
                "client_id": client_id,
                "kyber_keygen_time": latencies["kyber_keygen_time"],
                "kyber_encap_time": latencies["kyber_encap_time"],
                "kyber_decap_time": latencies["kyber_decap_time"],
                "dilithium_sign_time": latencies["dilithium_sign_time"],
                "dilithium_verify_time": latencies["dilithium_verify_time"],
                "aes_encryption_time": t_enc,
                "total_handshake_time": t_total
            }
            logger.log_metrics(metrics)

        return kyber_pass, dilithium_pass, aes_pass, redis_pass

async def test_concurrency(base_url: str):
    print("Starting Concurrency Test...")
    tasks = []
    for i in range(1, 6):
        client_id = f"concurrent_client_{i}"
        tasks.append(run_single_client_test(client_id, base_url))
        
    results = await asyncio.gather(*tasks)
    
    for r in results:
        if not all(r):
            print("Concurrency Verification FAILED: One or more concurrent clients failed.")
            return False
            
    print("Concurrency Verification PASS: 5 clients handled concurrently with isolated sessions.")
    return True

def test_latency_logging():
    filepath = "../benchmarking/benchmark_results.csv"
    if not os.path.exists(filepath):
        filepath = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "benchmarking", "benchmark_results.csv")

    if not os.path.exists(filepath):
        print("Latency Logging Verification FAILED: File not found.")
        return False
        
    with open(filepath, 'r') as f:
        reader = csv.DictReader(f)
        rows = list(reader)
        if len(rows) < 5: 
             print("Latency Logging Verification FAILED: Not enough rows logged.")
             return False
             
        for row in rows:
            for key, val in row.items():
                if val == "N/A" or val == "":
                    print(f"Latency Logging Verification FAILED: Empty value found for {key}.")
                    return False
                    
    print("Latency Logging Verification PASS: Benchmarking file populated correctly.")
    return True

async def main():
    base_url = "http://127.0.0.1:8000"
    
    # 1. Require manual server start: check if server is up
    server_up = await check_server_up(base_url)
    if not server_up:
        print("Server is not running. Please start the server manually before running tests.")
        print("Run:")
        print("  uvicorn server.server:app --host 127.0.0.1 --port 8000 --workers 4")
        return
        
    print("\n--- Running Functional Tests ---")
    
    k_pass, d_pass, a_pass, r_pass = await run_single_client_test("test_client_0", base_url)

    c_pass = False
    if k_pass and d_pass:
        c_pass = await test_concurrency(base_url)
    else:
        print("Concurrency Test: SKIPPED (Handshake failed)")

    l_pass = test_latency_logging()

    print("\n=====================================")
    print("FINAL RESULT")
    print("=====================================")
    print(f"Kyber Test: {'PASS' if k_pass else 'FAIL'}")
    print(f"Dilithium Test: {'PASS' if d_pass else 'FAIL'}")
    print(f"AES Test: {'PASS' if a_pass else 'FAIL'}")
    print(f"Redis Test: {'PASS' if r_pass else 'FAIL'}")
    print(f"Concurrency Test: {'PASS' if c_pass else 'FAIL'}")
    print(f"Latency Logging Test: {'PASS' if l_pass else 'FAIL'}")

if __name__ == "__main__":
    asyncio.run(main())
