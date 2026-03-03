import os
import ctypes
import sys

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

import oqs

class DilithiumWrapper:
    def __init__(self, alg_name="Dilithium3"):
        self.alg_name = alg_name
        # Fallback to NIST standardized name if Dilithium3 was renamed in this liboqs build
        try:
            with oqs.Signature(self.alg_name): pass
        except oqs.MechanismNotSupportedError:
            if alg_name == "Dilithium3":
                self.alg_name = "ML-DSA-65"
        
        # Internally manage the signer object so that the keypair state persists
        self._signer = oqs.Signature(self.alg_name)

    def generate_keypair(self):
        public_key = self._signer.generate_keypair()
        secret_key = self._signer.export_secret_key()
        return public_key, secret_key

    def sign(self, message: bytes) -> bytes:
        # The object stores sk internally, no manual injection needed
        signature = self._signer.sign(message)
        return signature

    def verify(self, public_key, message: bytes, signature: bytes) -> bool:
        with oqs.Signature(self.alg_name) as verifier:
            is_valid = verifier.verify(message, signature, public_key)
            return is_valid
            
    def __del__(self):
        if hasattr(self, '_signer') and self._signer is not None:
            self._signer.free()
