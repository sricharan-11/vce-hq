#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════
# VCE-HQ Fast-track Local Development Script
# ═══════════════════════════════════════════════════════════════════════════
set -e

cd "$(dirname "$0")"

echo -e "\033[1;36mChecking for virtual environment...\033[0m"
if [ ! -d ".venv" ]; then
    echo -e "\033[1;33mCreating Python virtual environment...\033[0m"
    python3 -m venv .venv
fi

echo -e "\033[1;36mActivating virtual environment...\033[0m"
source .venv/bin/activate

echo -e "\033[1;36mInstalling dependencies in editable mode...\033[0m"
pip install --upgrade pip
pip install -e .

echo -e "\033[1;32mStarting FastAPI with hot-reloading...\033[0m"
echo -e "\033[1;32mAccess the UI at: http://localhost:8000/ui/\033[0m"
echo ""
uvicorn vce_hq.api.app:create_app --port 8000 --factory --reload
