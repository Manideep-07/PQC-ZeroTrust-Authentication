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

class KyberWrapper:
    def __init__(self, alg_name="Kyber768"):
        self.alg_name = alg_name
        try:
            with oqs.KeyEncapsulation(self.alg_name): pass
        except oqs.MechanismNotSupportedError:
            if alg_name == "Kyber768":
                self.alg_name = "ML-KEM-768"
        self._kem = oqs.KeyEncapsulation(self.alg_name)
        
    def generate_keypair(self):
        public_key = self._kem.generate_keypair()
        secret_key = self._kem.export_secret_key()
        return public_key, secret_key

    def encapsulate(self, public_key):
        ciphertext, shared_secret = self._kem.encap_secret(public_key)
        return ciphertext, shared_secret

    def decapsulate(self, ciphertext):
        shared_secret = self._kem.decap_secret(ciphertext)
        return shared_secret

    def __del__(self):
        if hasattr(self, '_kem') and self._kem is not None:
            self._kem.free()
