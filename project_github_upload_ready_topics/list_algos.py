
import oqs
import os
import ctypes

# Ensure DLL is loaded (reusing logic for safety)
if os.name == 'nt':
    project_root = os.path.dirname(os.path.abspath(__file__))
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

print("--- Enabled KEMs ---")
try:
    kems = oqs.get_enabled_kem_mechanisms()
    for kem in kems:
        print(kem)
except Exception as e:
    print(f"Error getting KEMs: {e}")

print("\n--- Enabled Signatures ---")
try:
    sigs = oqs.get_enabled_sig_mechanisms()
    for sig in sigs:
        print(sig)
except Exception as e:
    print(f"Error getting Signatures: {e}")
