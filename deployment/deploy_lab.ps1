<#
.SYNOPSIS
    Deploys the Wazuh SIEM & FIM Lab using Docker Compose on Windows.
#>

Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "      DEPLOYING WAZUH HOST-BASED IDS & FIM LAB ENVIRONMENT" -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor Cyan

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    Write-Host "[-] Docker Desktop is not detected on PATH. Ensure Docker Desktop is running." -ForegroundColor Red
    Write-Host "[*] Tip: You can run the zero-dependency Python simulator without Docker:" -ForegroundColor Yellow
    Write-Host "    python simulator/run_simulator.py --demo" -ForegroundColor White
    exit 1
}

Write-Host "[*] Launching Wazuh Docker stack..." -ForegroundColor Yellow
docker compose up -d

Write-Host "`n[+] Wazuh Lab successfully initialized!" -ForegroundColor Green
Write-Host "    - Wazuh Dashboard:  https://localhost:443  (User: admin / admin)" -ForegroundColor White
Write-Host "    - Wazuh Manager:    localhost:1514 (Secure Agent Channel)" -ForegroundColor White
Write-Host "    - Wazuh API:        https://localhost:55000" -ForegroundColor White
