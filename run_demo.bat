@echo off
set PYTHONPATH=C:\Users\yksk7\PQC

echo Starting Post-Quantum Zero Trust Server...
start /B python -m uvicorn server.main:app --host 0.0.0.0 --port 8000

echo Waiting for server to start...
timeout /t 4 /nobreak >nul

echo.
echo === Running Client ===
echo.
python client\client.py

echo.
echo Demo completed!
pause












