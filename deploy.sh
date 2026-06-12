#!/bin/bash
set -e

APP_DIR="$HOME/VCE-HQ"
cd "$APP_DIR"

echo "=== VCE-HQ Deploy ==="

# Pull latest code
echo "[1/5] Pulling latest from git..."
git pull

# Activate venv (create if missing)
echo "[2/5] Activating virtual environment..."
if [ ! -d "venv" ]; then
    python3 -m venv venv
fi
source venv/bin/activate

# Install / update dependencies
echo "[3/5] Installing dependencies..."
pip install -e . --quiet

# Copy .env.prod -> .env (runtime config)
echo "[4/5] Loading .env.prod..."
cp .env.prod .env

# Restart server
echo "[5/5] Restarting VCE-HQ server on port 80..."
set -a
source .env
set +a

sudo pkill -9 -f uvicorn || true
sleep 2

sudo GOOGLE_API_KEY="$GOOGLE_API_KEY" \
     VCE_LLM_MODEL="$VCE_LLM_MODEL" \
     VCE_PORT="${VCE_PORT:-80}" \
     VCE_HOST="${VCE_HOST:-0.0.0.0}" \
     VCE_LOG_LEVEL="${VCE_LOG_LEVEL:-INFO}" \
     nohup ./venv/bin/python -m uvicorn vce_hq.api.app:create_app \
         --factory --host 0.0.0.0 --port "${VCE_PORT:-80}" > server.log 2>&1 &

echo "=== Deploy complete! Server running on port ${VCE_PORT:-80} ==="
echo "    Logs: $APP_DIR/server.log"
