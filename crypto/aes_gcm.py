import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class AESGCMWrapper:
    def __init__(self, key: bytes):
        # Kyber768 shared secret is 32 bytes (256 bits), perfect for AES-256
        if len(key) != 32:
            raise ValueError("AES key must be exactly 32 bytes for AES-256")
        self.aesgcm = AESGCM(key)

    def encrypt(self, plaintext: bytes, associated_data: bytes = None) -> (bytes, bytes):
        """Encrypts data and returns (nonce, ciphertext)"""
        nonce = os.urandom(12)  # 96-bit nonce for GCM
        ciphertext = self.aesgcm.encrypt(nonce, plaintext, associated_data)
        return nonce, ciphertext

    def decrypt(self, nonce: bytes, ciphertext: bytes, associated_data: bytes = None) -> bytes:
        """Decrypts data and returns plaintext. Raises Crypto error if authentication fails."""
        plaintext = self.aesgcm.decrypt(nonce, ciphertext, associated_data)
        return plaintext
