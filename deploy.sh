#!/bin/bash
set -e

echo "Updating system..."
sudo apt-get update -y

echo "Installing Python 3.12 and dependencies..."
sudo apt-get install -y python3-pip python3-venv software-properties-common sqlite3 libsqlite3-dev build-essential

echo "Setting up app directory..."
cd /home/$USER/VCE-HQ

echo "Creating virtual environment..."
python3 -m venv venv
source venv/bin/activate

echo "Installing dependencies..."
pip install -e .

echo "Setting up .env file..."
cp .env.prod .env

echo "Starting VCE-HQ server on port 80..."
# Source environment variables and pass explicitly to sudo
set -a
source .env
set +a
sudo pkill -9 -f uvicorn || true
sleep 2
sudo GOOGLE_API_KEY="$GOOGLE_API_KEY" VCE_LLM_MODEL="$VCE_LLM_MODEL" nohup ./venv/bin/python -m uvicorn vce_hq.api.app:create_app --factory --host 0.0.0.0 --port 80 > server.log 2>&1 &

echo "Deployment complete! Server should be accessible on port 80."
