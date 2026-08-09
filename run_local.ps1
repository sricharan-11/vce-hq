# ═══════════════════════════════════════════════════════════════════════════
# VCE-HQ Fast-track Local Development Script
# ═══════════════════════════════════════════════════════════════════════════

# Make sure we are in the script's directory
Set-Location $PSScriptRoot

Write-Host "Checking for virtual environment..." -ForegroundColor Cyan
if (-not (Test-Path ".venv")) {
    Write-Host "Creating Python virtual environment..." -ForegroundColor Yellow
    python -m venv .venv
}

Write-Host "Activating virtual environment..." -ForegroundColor Cyan
$env:VIRTUAL_ENV = "$PSScriptRoot\.venv"
$env:Path = "$PSScriptRoot\.venv\Scripts;$env:Path"

Write-Host "Installing dependencies in editable mode..." -ForegroundColor Cyan
python -m pip install --upgrade pip
pip install -e .

Write-Host "Starting FastAPI with hot-reloading..." -ForegroundColor Green
Write-Host "Access the UI at: http://localhost:8000/ui/" -ForegroundColor Green
Write-Host ""
python -m uvicorn vce_hq.api.app:create_app --port 8000 --factory --reload
