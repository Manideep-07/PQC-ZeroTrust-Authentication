# Post-Quantum Zero Trust Demo Script
$env:PYTHONPATH = "C:\Users\yksk7\PQC"

Write-Host "Starting Post-Quantum Zero Trust Server..." -ForegroundColor Green
Start-Process python -ArgumentList "-m","uvicorn","server.main:app","--host","0.0.0.0","--port","8000" -WindowStyle Hidden

Write-Host "Waiting for server to start..." -ForegroundColor Yellow
Start-Sleep -Seconds 4

Write-Host "`n=== Running Client ===`n" -ForegroundColor Cyan
python client\client.py

Write-Host "`nPress any key to stop the server..."
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")














