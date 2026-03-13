import subprocess

with open('test_clean.txt', 'w', encoding='utf-8') as f:
    result = subprocess.run(['.venv\\\\Scripts\\\\python', 'tests/system_test.py'], capture_output=True, text=True)
    f.write(result.stdout)
    if result.stderr:
        f.write("\nSTDERR:\n")
        f.write(result.stderr)
