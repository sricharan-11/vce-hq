# VCE-HQ — Git & CD (Deployment Guide)

> **Last Updated:** 2026-06-12
> **VM:** `instance-20260426-224222` · `us-central1-a` · `isolated-lab-for-testing`

---

## 1. Infrastructure

| Item | Value |
|------|-------|
| **GCP Project** | `isolated-lab-for-testing` |
| **VM Name** | `instance-20260426-224222` |
| **Zone** | `us-central1-a` |
| **Console** | [VM Instance Page](https://console.cloud.google.com/compute/instancesDetail/zones/us-central1-a/instances/instance-20260426-224222?project=isolated-lab-for-testing&supportedpurview=project,folder) |
| **Git Repo** | `https://github.com/sricharan-11/vce-hq` (private) |
| **Git PAT** | Stored locally in `.env.git` (gitignored) |
| **AI API Key** | Stored locally in `.env.prod` (gitignored) |

---

## 2. Prerequisites (Local Machine)

- `gcloud` CLI authenticated (`gcloud auth login` — already done in IDE)
- Project set: `gcloud config set project isolated-lab-for-testing`
- SSH access works: `gcloud compute ssh instance-20260426-224222 --zone=us-central1-a`

---

## 3. One-Time VM Setup

Run these **once** to bootstrap the VM with Git credentials and the repo clone.

### 3.1 SSH into the VM

```bash
gcloud compute ssh instance-20260426-224222 --zone=us-central1-a --project=isolated-lab-for-testing
```

### 3.2 Install system dependencies

```bash
sudo apt-get update -y
sudo apt-get install -y python3-pip python3-venv software-properties-common \
    sqlite3 libsqlite3-dev build-essential git
```

### 3.3 Clone the repo (with PAT for private access)

Use the PAT from `.env.git` to clone:

```bash
git clone https://<GIT_PAT>@github.com/sricharan-11/vce-hq.git ~/VCE-HQ
```

### 3.4 Configure Git credential caching on the VM

So subsequent `git pull` commands don't need the PAT every time:

```bash
cd ~/VCE-HQ
git config credential.helper 'store --file ~/.git-credentials'
# The credentials are already embedded from the clone URL above.
# Alternatively, store them explicitly:
echo "https://<GIT_PAT>@github.com" > ~/.git-credentials
chmod 600 ~/.git-credentials
```

### 3.5 Upload `.env.prod` to the VM (one-time)

From your **local machine**:

```bash
gcloud compute scp .env.prod instance-20260426-224222:~/VCE-HQ/.env.prod \
    --zone=us-central1-a --project=isolated-lab-for-testing
```

> `.env.prod` is gitignored and contains the API key. This only needs to be re-uploaded if the key changes.

### 3.6 Create venv and install (first time)

```bash
cd ~/VCE-HQ
python3 -m venv venv
source venv/bin/activate
pip install -e .
```

---

## 4. Day-to-Day Deployment (Git Pull)

### From your local machine — single command:

```bash
gcloud compute ssh instance-20260426-224222 --zone=us-central1-a \
    --project=isolated-lab-for-testing \
    --command="cd ~/VCE-HQ && git pull && source venv/bin/activate && pip install -e . && bash deploy.sh"
```

### Or SSH in and run manually:

```bash
# 1. SSH in
gcloud compute ssh instance-20260426-224222 --zone=us-central1-a --project=isolated-lab-for-testing

# 2. Pull latest code
cd ~/VCE-HQ
git pull

# 3. Re-install (picks up new dependencies)
source venv/bin/activate
pip install -e .

# 4. Deploy (restarts the server)
bash deploy.sh
```

---

## 5. `deploy.sh` — What It Does

The deploy script ([deploy.sh](./deploy.sh)) handles:

1. ~~System updates~~ (skipped if deps already installed)
2. Activates the Python venv
3. Installs/updates Python dependencies
4. Copies `.env.prod` → `.env`
5. Kills any existing uvicorn process
6. Starts uvicorn on **port 80** with `nohup` (runs in background)
7. Logs output to `~/VCE-HQ/server.log`

---

## 6. Quick Reference Commands

### Push & Deploy (full flow from local machine)

```bash
# 1. Commit and push your changes locally
git add -A && git commit -m "your message" && git push

# 2. Deploy to VM (git pull + restart)
gcloud compute ssh instance-20260426-224222 --zone=us-central1-a \
    --project=isolated-lab-for-testing \
    --command="cd ~/VCE-HQ && git pull && source venv/bin/activate && pip install -e . && bash deploy.sh"
```

### Check server status

```bash
gcloud compute ssh instance-20260426-224222 --zone=us-central1-a \
    --project=isolated-lab-for-testing \
    --command="sudo pgrep -fa uvicorn"
```

### Tail server logs

```bash
gcloud compute ssh instance-20260426-224222 --zone=us-central1-a \
    --project=isolated-lab-for-testing \
    --command="tail -50 ~/VCE-HQ/server.log"
```

### Kill the server

```bash
gcloud compute ssh instance-20260426-224222 --zone=us-central1-a \
    --project=isolated-lab-for-testing \
    --command="sudo pkill -9 -f uvicorn"
```

### Re-upload `.env.prod` (if API key changes)

```bash
gcloud compute scp .env.prod instance-20260426-224222:~/VCE-HQ/.env.prod \
    --zone=us-central1-a --project=isolated-lab-for-testing
```

---

## 7. File Sensitivity Reminder

| File | Gitignored? | Contains |
|------|:-----------:|----------|
| `.env` | ✅ | Runtime env (copied from `.env.prod` by `deploy.sh`) |
| `.env.prod` | ✅ | Google API key, model config |
| `.env.git` | ✅ | GitHub PAT token |
| `.env.example` | ❌ | Template with placeholder values (safe to commit) |

> **Never commit `.env.prod` or `.env.git`.** They are covered by `.gitignore` pattern `.env.*`.

---

## 8. Troubleshooting

| Problem | Fix |
|---------|-----|
| `git pull` asks for credentials | Re-run credential store setup (Section 3.4) |
| `Permission denied` on port 80 | `deploy.sh` uses `sudo` for port 80 — ensure the user has sudo |
| Server not responding | Check `server.log`, check firewall allows HTTP (port 80) in GCP console |
| `pip install` fails | Ensure `build-essential` and `libsqlite3-dev` are installed |
| Old code still running | `sudo pkill -9 -f uvicorn` then re-run `deploy.sh` |
