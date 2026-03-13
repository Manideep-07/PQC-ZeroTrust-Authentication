
import ctypes
import os
import sys

def test_dll_load():
    dll_name = "liboqs.dll"
    # Try current directory
    dll_path = os.path.abspath(dll_name)
    
    print(f"--- Debugging DLL Load: {dll_path} ---")
    
    if not os.path.exists(dll_path):
        print(f"[ERROR] file {dll_path} does not exist.")
        return

    print(f"[INFO] File exists. Size: {os.path.getsize(dll_path)} bytes")
    
    # 1. Try loading directly
    try:
        print("[INFO] Attempting ctypes.CDLL load...")
        lib = ctypes.CDLL(dll_path)
        print("[SUCCESS] DLL loaded successfully!")
        return
    except OSError as e:
        print(f"[FAIL] ctypes.CDLL failed: {e}")
        print("       This usually means a missing dependency (like MSVC Runtime).")

    # 2. Try adding directory to DLL path (Python 3.8+)
    if hasattr(os, 'add_dll_directory'):
        try:
            print(f"[INFO] Adding {os.getcwd()} to DLL directory...")
            os.add_dll_directory(os.getcwd())
            lib = ctypes.CDLL(dll_name)
            print("[SUCCESS] DLL loaded after add_dll_directory!")
            return
        except Exception as e:
            print(f"[FAIL] Failed after add_dll_directory: {e}")

if __name__ == "__main__":
    test_dll_load()
