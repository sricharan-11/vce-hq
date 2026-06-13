#!/bin/bash
set -e

PAT="$1"
echo "=== VCE-HQ VM Setup ==="

# Check if already cloned
if [ -d "$HOME/VCE-HQ/.git" ]; then
    echo "Repo already cloned. Pulling latest..."
    cd "$HOME/VCE-HQ"
    git pull
else
    echo "Cloning repo..."
    git clone "https://${PAT}@github.com/sricharan-11/vce-hq.git" "$HOME/VCE-HQ"
fi

# Store git credentials for future pulls
cd "$HOME/VCE-HQ"
git config credential.helper "store --file $HOME/.git-credentials"
echo "https://${PAT}@github.com" > "$HOME/.git-credentials"
chmod 600 "$HOME/.git-credentials"

# Remove PAT from remote URL (use credential store instead)
git remote set-url origin https://github.com/sricharan-11/vce-hq.git

# Restore .env.prod from backup if it exists
if [ -f "$HOME/env_prod_backup" ] && [ ! -f "$HOME/VCE-HQ/.env.prod" ]; then
    cp "$HOME/env_prod_backup" "$HOME/VCE-HQ/.env.prod"
    echo "Restored .env.prod from backup"
fi

# Restore data dir from backup if it exists
if [ -d "$HOME/data_backup" ] && [ ! -d "$HOME/VCE-HQ/data" ]; then
    sudo cp -r "$HOME/data_backup" "$HOME/VCE-HQ/data"
    echo "Restored data/ from backup"
fi

# Setup venv if missing
if [ ! -d "$HOME/VCE-HQ/venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv "$HOME/VCE-HQ/venv"
fi

echo "=== Setup complete ==="
echo "Repo: $(cd $HOME/VCE-HQ && git remote -v | head -1)"
echo "Branch: $(cd $HOME/VCE-HQ && git branch --show-current)"
echo "Latest commit: $(cd $HOME/VCE-HQ && git log --oneline -1)"
ls -la "$HOME/VCE-HQ/"
