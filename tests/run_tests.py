import subprocess
import sys
import os

# Run system_test.py using the current Python interpreter
test_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "system_test.py")
result = subprocess.run([sys.executable, test_path], capture_output=False)
sys.exit(result.returncode)
