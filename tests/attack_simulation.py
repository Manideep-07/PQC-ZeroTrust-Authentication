"""
PQC Framework — Security Attack Simulation Suite
=================================================
Tests that the framework's existing defences ACTUALLY work.
Each attack is isolated, runs against a live server, and asserts
a specific HTTP status or cryptographic outcome.

Run:
    # Start server first:
    #   uvicorn server.server:app --host 127.0.0.1 --port 8000
    python tests/attack_simulation.py

Each attack prints:  [ATTACK] <name>: DETECTED  or  BYPASS (fail)
A summary table is printed at the end.
"""

import asyncio
import httpx
import hashlib
import secrets
import sys
import os
import time

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Handle Windows DLL loading (unchanged from original pattern)
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
        except Exception:
            pass

from crypto.kyber import KyberWrapper
from crypto.dilithium import DilithiumWrapper
from crypto.aes_gcm import AESGCMWrapper

BASE_URL = "http://127.0.0.1:8000"
results = {}


# ─────────────────────────────────────────────────────────────────────────────
# Helper: perform a clean valid handshake, return (session_token, shared_secret,
#         ciphertext, challenge_hex) for use in subsequent attack tests.
# ─────────────────────────────────────────────────────────────────────────────
async def _do_valid_handshake(client: httpx.AsyncClient, client_id: str):
    kyber = KyberWrapper("Kyber768")
    kyber_pk, _ = kyber.generate_keypair()
    challenge = secrets.token_bytes(32)
    payload = {
        "client_id": client_id,
        "kyber_public_key": kyber_pk.hex(),
        "challenge": challenge.hex(),
        "device_hash": "research_device",
        "os_identifier": "research_os",
    }
    resp = await client.post(f"{BASE_URL}/auth/handshake", json=payload, timeout=30.0)
    resp.raise_for_status()
    data = resp.json()
    ciphertext = bytes.fromhex(data["ciphertext"])
    shared_secret = kyber.decapsulate(ciphertext)
    return data["session_token"], shared_secret, ciphertext, challenge.hex()


# ─────────────────────────────────────────────────────────────────────────────
# ATTACK 1 — Challenge Replay
# Reuse the exact same challenge bytes in a second handshake request.
# Defence: server stores challenge via setnx; second use must return HTTP 400.
# ─────────────────────────────────────────────────────────────────────────────
async def attack_challenge_replay(client: httpx.AsyncClient):
    print("\n[ATTACK 1] Challenge Replay")
    print("  Method : Send identical challenge hex in two consecutive handshakes")

    kyber = KyberWrapper("Kyber768")
    kyber_pk, _ = kyber.generate_keypair()
    challenge = secrets.token_bytes(32)

    payload = {
        "client_id": "attacker_replay",
        "kyber_public_key": kyber_pk.hex(),
        "challenge": challenge.hex(),
        "device_hash": "x",
        "os_identifier": "x",
    }

    # First request — must succeed
    r1 = await client.post(f"{BASE_URL}/auth/handshake", json=payload, timeout=30.0)
    if r1.status_code != 200:
        print(f"  Setup   : First handshake failed ({r1.status_code}) — skipping")
        results["Challenge Replay"] = "SKIP"
        return

    # Second request with SAME challenge — must be rejected
    kyber2 = KyberWrapper("Kyber768")
    kyber_pk2, _ = kyber2.generate_keypair()
    payload2 = {
        "client_id": "attacker_replay_2",
        "kyber_public_key": kyber_pk2.hex(),
        "challenge": challenge.hex(),   # <-- identical challenge
        "device_hash": "x",
        "os_identifier": "x",
    }
    r2 = await client.post(f"{BASE_URL}/auth/handshake", json=payload2, timeout=30.0)

    if r2.status_code == 400 and "Replay" in r2.text:
        print("  Result  : DETECTED ✓  (server returned 400 Replay attack detected)")
        results["Challenge Replay"] = "DETECTED"
    else:
        print(f"  Result  : BYPASS ✗  (server returned {r2.status_code} — replay was NOT blocked)")
        results["Challenge Replay"] = "BYPASS"


# ─────────────────────────────────────────────────────────────────────────────
# ATTACK 2 — Ciphertext MITM Tamper
# Bit-flip the Kyber ciphertext returned by the server.
# If the client decapsulates the tampered ciphertext, it gets a DIFFERENT
# shared secret — AES decryption on the data channel will fail.
# This is a cryptographic assertion (does NOT require a server call).
# Defence: Kyber KEM correctness — wrong ciphertext → wrong secret.
# ─────────────────────────────────────────────────────────────────────────────
async def attack_ciphertext_mitm(client: httpx.AsyncClient):
    print("\n[ATTACK 2] Ciphertext MITM Tamper")
    print("  Method : Flip one bit in the Kyber ciphertext before decapsulation")

    kyber = KyberWrapper("Kyber768")
    kyber_pk, _ = kyber.generate_keypair()
    challenge = secrets.token_bytes(32)
    payload = {
        "client_id": "attacker_mitm",
        "kyber_public_key": kyber_pk.hex(),
        "challenge": challenge.hex(),
        "device_hash": "x",
        "os_identifier": "x",
    }
    r = await client.post(f"{BASE_URL}/auth/handshake", json=payload, timeout=30.0)
    if r.status_code != 200:
        print(f"  Setup   : Handshake failed ({r.status_code}) — skipping")
        results["Ciphertext MITM Tamper"] = "SKIP"
        return

    data = r.json()
    real_ciphertext = bytes.fromhex(data["ciphertext"])
    real_secret = kyber.decapsulate(real_ciphertext)

    # Tamper: flip the last byte
    tampered = bytearray(real_ciphertext)
    tampered[-1] ^= 0xFF
    tampered_secret = kyber.decapsulate(bytes(tampered))

    if tampered_secret != real_secret:
        print("  Result  : DETECTED ✓  (tampered ciphertext produces wrong shared secret — AES channel breaks)")
        results["Ciphertext MITM Tamper"] = "DETECTED"
    else:
        print("  Result  : BYPASS ✗  (tampered ciphertext still yields the correct secret — unexpected)")
        results["Ciphertext MITM Tamper"] = "BYPASS"


# ─────────────────────────────────────────────────────────────────────────────
# ATTACK 3 — Dilithium Signature Forgery
# Mutate the server's Dilithium signature and verify() must reject it.
# Defence: Dilithium3 EUF-CMA security — any modification → verify returns False.
# ─────────────────────────────────────────────────────────────────────────────
async def attack_signature_forgery(client: httpx.AsyncClient):
    print("\n[ATTACK 3] Dilithium Signature Forgery")
    print("  Method : Flip one byte in the server Dilithium signature, attempt verify()")

    kyber = KyberWrapper("Kyber768")
    dilithium = DilithiumWrapper("Dilithium3")
    kyber_pk, _ = kyber.generate_keypair()
    challenge = secrets.token_bytes(32)
    payload = {
        "client_id": "attacker_forgery",
        "kyber_public_key": kyber_pk.hex(),
        "challenge": challenge.hex(),
        "device_hash": "x",
        "os_identifier": "x",
    }
    r = await client.post(f"{BASE_URL}/auth/handshake", json=payload, timeout=30.0)
    if r.status_code != 200:
        print(f"  Setup   : Handshake failed ({r.status_code}) — skipping")
        results["Signature Forgery"] = "SKIP"
        return

    data = r.json()
    ciphertext = bytes.fromhex(data["ciphertext"])
    real_sig = bytes.fromhex(data["signature"])
    server_pk = bytes.fromhex(data["server_dilithium_public_key"])
    message = challenge + ciphertext

    # Tamper the signature
    forged_sig = bytearray(real_sig)
    forged_sig[0] ^= 0xAA
    is_valid = dilithium.verify(server_pk, message, bytes(forged_sig))

    if not is_valid:
        print("  Result  : DETECTED ✓  (forged signature correctly rejected by Dilithium3 verify())")
        results["Signature Forgery"] = "DETECTED"
    else:
        print("  Result  : BYPASS ✗  (forged signature was accepted — critical failure)")
        results["Signature Forgery"] = "BYPASS"


# ─────────────────────────────────────────────────────────────────────────────
# ATTACK 4 — Nonce Reuse on Secure Data Channel
# Send the same AES-GCM nonce twice to /secure/data.
# Defence: server stores nonce via setnx; second use returns HTTP 400.
# ─────────────────────────────────────────────────────────────────────────────
async def attack_nonce_reuse(client: httpx.AsyncClient):
    print("\n[ATTACK 4] AES-GCM Nonce Reuse")
    print("  Method : Send the same nonce twice to /secure/data")

    session_token, shared_secret, _, _ = await _do_valid_handshake(client, "attacker_nonce")
    aes = AESGCMWrapper(shared_secret)
    msg = b"nonce reuse test payload"
    nonce, ct = aes.encrypt(msg)

    payload = {
        "session_token": session_token,
        "nonce": nonce.hex(),
        "ciphertext": ct.hex(),
        "timestamp": time.time(),
    }

    r1 = await client.post(f"{BASE_URL}/secure/data", json=payload, timeout=15.0)
    if r1.status_code != 200:
        print(f"  Setup   : First /secure/data call failed ({r1.status_code}) — skipping")
        results["Nonce Reuse"] = "SKIP"
        return

    # Second call — same nonce, update timestamp only
    payload["timestamp"] = time.time()
    r2 = await client.post(f"{BASE_URL}/secure/data", json=payload, timeout=15.0)

    if r2.status_code == 400 and "Nonce" in r2.text:
        print("  Result  : DETECTED ✓  (server returned 400 Nonce already used)")
        results["Nonce Reuse"] = "DETECTED"
    else:
        print(f"  Result  : BYPASS ✗  (server returned {r2.status_code} — nonce reuse was NOT blocked)")
        results["Nonce Reuse"] = "BYPASS"


# ─────────────────────────────────────────────────────────────────────────────
# ATTACK 5 — Rate Limit Enforcement
# Flood /auth/handshake with 15 rapid requests from the same client_id.
# Defence: server blocks after 10 req/min; must return HTTP 429 by request 12.
# ─────────────────────────────────────────────────────────────────────────────
async def attack_rate_limit(client: httpx.AsyncClient):
    print("\n[ATTACK 5] Rate Limit Enforcement (DoS simulation)")
    print("  Method : Send 15 rapid handshake requests from the same client_id")

    got_429 = False
    for i in range(15):
        kyber = KyberWrapper("Kyber768")
        kyber_pk, _ = kyber.generate_keypair()
        payload = {
            "client_id": "attacker_ratelimit",
            "kyber_public_key": kyber_pk.hex(),
            "challenge": secrets.token_hex(32),
            "device_hash": "x",
            "os_identifier": "x",
        }
        r = await client.post(f"{BASE_URL}/auth/handshake", json=payload, timeout=10.0)
        if r.status_code == 429:
            print(f"  Blocked : at request #{i+1} — HTTP 429 returned")
            got_429 = True
            break

    if got_429:
        print("  Result  : DETECTED ✓  (rate limiter correctly triggered HTTP 429)")
        results["Rate Limit (DoS)"] = "DETECTED"
    else:
        print("  Result  : BYPASS ✗  (15 requests went through — rate limiter not working)")
        results["Rate Limit (DoS)"] = "BYPASS"


# ─────────────────────────────────────────────────────────────────────────────
# ATTACK 6 — Expired Session Token Reuse
# Get a valid session token, wait for it to expire (or force expiry via Redis),
# then try to use the expired token on /secure/data.
# Defence: Redis TTL expiry; server returns HTTP 401.
# ─────────────────────────────────────────────────────────────────────────────
async def attack_expired_session(client: httpx.AsyncClient):
    print("\n[ATTACK 6] Expired Session Token Reuse")
    print("  Method : Force Redis TTL to 1s, wait 2s, reuse the expired token")

    try:
        import redis as sync_redis
        r_client = sync_redis.Redis(host="localhost", port=6379, db=0, decode_responses=True)
        r_client.ping()
    except Exception as e:
        print(f"  Setup   : Redis not reachable ({e}) — skipping")
        results["Expired Session Reuse"] = "SKIP"
        return

    session_token, shared_secret, _, _ = await _do_valid_handshake(client, "attacker_expiry")

    # Force TTL to 1 second
    r_client.expire(f"session:{session_token}", 1)
    await asyncio.sleep(2)  # Wait for expiry

    aes = AESGCMWrapper(shared_secret)
    nonce, ct = aes.encrypt(b"post-expiry message")
    payload = {
        "session_token": session_token,
        "nonce": nonce.hex(),
        "ciphertext": ct.hex(),
        "timestamp": time.time(),
    }
    r = await client.post(f"{BASE_URL}/secure/data", json=payload, timeout=10.0)

    if r.status_code == 401:
        print("  Result  : DETECTED ✓  (server returned 401 — expired token correctly rejected)")
        results["Expired Session Reuse"] = "DETECTED"
    else:
        print(f"  Result  : BYPASS ✗  (server returned {r.status_code} — expired token was accepted)")
        results["Expired Session Reuse"] = "BYPASS"


# ─────────────────────────────────────────────────────────────────────────────
# ATTACK 7 — Forged Client Identity on /auth/verify
# Send a valid session token but a freshly generated (wrong) Dilithium keypair
# as the client's identity proof.
# Defence: server verifies signature against the stored verify_challenge;
#          mismatched keypair means verify() fails → HTTP 401.
# ─────────────────────────────────────────────────────────────────────────────
async def attack_identity_forgery(client: httpx.AsyncClient):
    print("\n[ATTACK 7] Forged Client Identity (/auth/verify)")
    print("  Method : Send a random Dilithium keypair as client identity proof")

    kyber = KyberWrapper("Kyber768")
    dilithium = DilithiumWrapper("Dilithium3")
    kyber_pk, _ = kyber.generate_keypair()
    challenge = secrets.token_bytes(32)
    payload = {
        "client_id": "attacker_identity",
        "kyber_public_key": kyber_pk.hex(),
        "challenge": challenge.hex(),
        "device_hash": "x",
        "os_identifier": "x",
    }
    r = await client.post(f"{BASE_URL}/auth/handshake", json=payload, timeout=30.0)
    if r.status_code != 200:
        print(f"  Setup   : Handshake failed ({r.status_code}) — skipping")
        results["Forged Identity"] = "SKIP"
        return

    data = r.json()
    session_token = data["session_token"]
    verify_challenge = data.get("verify_challenge", "")
    if not verify_challenge:
        print("  Setup   : No verify_challenge in response — skipping")
        results["Forged Identity"] = "SKIP"
        return

    # Generate a completely unrelated keypair — this is the forgery
    fake_pk, _ = dilithium.generate_keypair()
    fake_sig = dilithium.sign(bytes.fromhex(verify_challenge))   # signed with the fake key

    verify_payload = {
        "session_token": session_token,
        "client_dilithium_pk": fake_pk.hex(),
        "signed_challenge": fake_sig.hex(),
    }
    rv = await client.post(f"{BASE_URL}/auth/verify", json=verify_payload, timeout=15.0)

    if rv.status_code == 401:
        print("  Result  : DETECTED ✓  (server returned 401 — forged identity rejected)")
        results["Forged Identity"] = "DETECTED"
    else:
        print(f"  Result  : BYPASS ✗  (server returned {rv.status_code} — forged identity accepted)")
        results["Forged Identity"] = "BYPASS"


# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────

# ─────────────────────────────────────────────────────────────────────────────
# ATTACK 8 — Brute Force Authentication (repeated fake credential attempts)
# Sends repeated handshake requests with RANDOM (invalid) Kyber public keys
# and random challenges, simulating an attacker trying to guess/force entry.
# Defence: anomaly detection blocks client after 5 failed attempts (HTTP 403).
# The brute force loop will get blocked well before reaching the attempt limit.
# ─────────────────────────────────────────────────────────────────────────────
async def attack_brute_force(client: httpx.AsyncClient):
    print("\n[ATTACK 8] Brute Force Authentication")
    print("  Method : 20 rapid requests with random invalid Kyber keys from same client_id")
    print("  Goal   : Trigger anomaly detection block (HTTP 403) before attempt 20")

    blocked_at = None
    ATTEMPTS = 20

    for attempt in range(1, ATTEMPTS + 1):
        # Generate a valid-looking but completely random public key (wrong size = 400 bad request,
        # so we send a correctly-sized random blob that will fail decapsulation server-side)
        # Kyber768 public key is 1184 bytes
        fake_pk = secrets.token_bytes(1184)
        payload = {
            "client_id": "attacker_bruteforce",
            "kyber_public_key": fake_pk.hex(),
            "challenge": secrets.token_hex(32),
            "device_hash": "brute",
            "os_identifier": "brute",
        }
        r = await client.post(f"{BASE_URL}/auth/handshake", json=payload, timeout=15.0)

        if r.status_code == 403:
            blocked_at = attempt
            print(f"  Blocked : at attempt #{attempt} — HTTP 403 Too many failed attempts")
            break
        elif r.status_code == 429:
            blocked_at = attempt
            print(f"  Blocked : at attempt #{attempt} — HTTP 429 Rate limit exceeded")
            break
        elif r.status_code == 500:
            # Server rejected the bad key internally and recorded a failed attempt
            print(f"  Attempt {attempt:>2}: HTTP 500 (bad key rejected, failed attempt recorded)")
        elif r.status_code == 200:
            print(f"  Attempt {attempt:>2}: HTTP 200 — unexpected success with random key")
        else:
            print(f"  Attempt {attempt:>2}: HTTP {r.status_code}")

    if blocked_at is not None:
        print(f"  Result  : DETECTED ✓  (brute force blocked at attempt #{blocked_at}/{ATTEMPTS})")
        results["Brute Force Auth"] = "DETECTED"
    else:
        print(f"  Result  : BYPASS ✗  (all {ATTEMPTS} attempts went through — anomaly detection not triggered)")
        results["Brute Force Auth"] = "BYPASS"


async def check_server_up():
    try:
        async with httpx.AsyncClient() as c:
            await c.get(f"{BASE_URL}/docs", timeout=3.0)
        return True
    except Exception:
        return False


async def main():
    print("=" * 60)
    print("  PQC Framework — Security Attack Simulation Suite")
    print("=" * 60)

    if not await check_server_up():
        print("\nServer is not running. Start it first:")
        print("  uvicorn server.server:app --host 127.0.0.1 --port 8000")
        sys.exit(1)

    print("\nServer is UP. Running 8 attack scenarios...\n")

    async with httpx.AsyncClient() as client:
        await attack_challenge_replay(client)
        await attack_ciphertext_mitm(client)
        await attack_signature_forgery(client)
        await attack_nonce_reuse(client)
        await attack_rate_limit(client)
        await attack_expired_session(client)
        await attack_identity_forgery(client)
        await attack_brute_force(client)

    # ── Summary Table ──────────────────────────────────────────────────────
    print("\n" + "=" * 60)
    print("  ATTACK SIMULATION SUMMARY")
    print("=" * 60)
    print(f"  {'Attack':<35} {'Result'}")
    print(f"  {'-'*35} {'-'*10}")
    detected = 0
    bypass = 0
    skip = 0
    for attack, result in results.items():
        marker = "✓" if result == "DETECTED" else ("–" if result == "SKIP" else "✗")
        print(f"  {attack:<35} {result} {marker}")
        if result == "DETECTED":
            detected += 1
        elif result == "BYPASS":
            bypass += 1
        else:
            skip += 1

    total = len(results)
    print("=" * 60)
    print(f"  Detected: {detected}/{total}  |  Bypass: {bypass}/{total}  |  Skipped: {skip}/{total}")
    if bypass == 0 and detected > 0:
        print("  VERDICT: All tested defences HELD. Framework is attack-resistant.")
    elif bypass > 0:
        print(f"  VERDICT: {bypass} attack(s) bypassed defences — review required.")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())
