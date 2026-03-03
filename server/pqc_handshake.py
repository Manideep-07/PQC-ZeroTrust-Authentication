import time
from crypto.kyber import KyberWrapper
from crypto.dilithium import DilithiumWrapper

class PQCHandshakeServer:
    def __init__(self):
        self.kyber = KyberWrapper("Kyber768")
        self.dilithium = DilithiumWrapper("Dilithium3")
        # Generate the server's long-term identity key
        self.server_dilithium_pk, self.server_dilithium_sk = self.dilithium.generate_keypair()

    def process_handshake(self, kyber_client_pk: bytes, challenge: bytes) -> tuple:
        """
        Takes the client's public Kyber key and a challenge.
        Encapsulates a shared secret.
        Signs the challenge and the ciphertext with Dilithium.
        Returns (ciphertext, shared_secret, signature, dict containing latencies)
        """
        # Measure Encap Time
        t_start_encap = time.time()
        ciphertext, shared_secret = self.kyber.encapsulate(kyber_client_pk)
        t_encap = time.time() - t_start_encap

        # Sign the challenge + ciphertext to prove identity and prevent MITM/Replay
        message_to_sign = challenge + ciphertext
        
        # Measure Sign Time
        t_start_sign = time.time()
        signature = self.dilithium.sign(message_to_sign)
        t_sign = time.time() - t_start_sign

        latencies = {
            "kyber_encap_time": t_encap,
            "dilithium_sign_time": t_sign
        }

        return ciphertext, shared_secret, signature, latencies

    def get_public_key(self) -> bytes:
        return self.server_dilithium_pk
