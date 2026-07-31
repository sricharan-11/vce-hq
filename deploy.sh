#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════════
#  VCE-HQ fresh-deploy bootstrap
# ──────────────────────────────────────────────────────────────────────
#  Idempotently brings up the full stack on any Linux host with Docker.
#
#    * verifies Docker Engine + Compose v2 are installed
#    * seeds .env from .env.example on first run
#    * auto-generates strong secrets for VCE_CREDENTIAL_SECRET,
#      VCE_JWT_SECRET_KEY, and VCE_ADMIN_PASSWORD if left as defaults
#    * builds the image and starts the container
#    * waits for /health to return 200 before exiting
#
#  Re-run any time — safe to invoke on updates (does not overwrite .env).
# ══════════════════════════════════════════════════════════════════════
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# ─── pretty output ────────────────────────────────────────────────────
c_reset='\033[0m'; c_bold='\033[1m'; c_green='\033[32m'
c_yellow='\033[33m'; c_red='\033[31m'; c_dim='\033[2m'
info()  { printf "${c_bold}${c_green}==>${c_reset} %s\n" "$*"; }
warn()  { printf "${c_bold}${c_yellow}!!${c_reset}  %s\n" "$*"; }
die()   { printf "${c_bold}${c_red}xx${c_reset}  %s\n" "$*" >&2; exit 1; }
step()  { printf "${c_dim}    %s${c_reset}\n" "$*"; }

# ─── 1/6  preflight ───────────────────────────────────────────────────
info "Checking prerequisites..."
command -v docker >/dev/null 2>&1 || die "Docker Engine is not installed. See https://docs.docker.com/engine/install/"
docker compose version >/dev/null 2>&1 || die "Docker Compose v2 plugin is missing (need 'docker compose', not 'docker-compose')."
docker info >/dev/null 2>&1 || die "Docker daemon is not reachable. Start it or add your user to the 'docker' group."
step "docker $(docker --version | awk '{print $3}' | tr -d ',')"
step "compose $(docker compose version --short)"

# ─── 2/6  seed .env  ──────────────────────────────────────────────────
info "Preparing .env..."
if [[ ! -f .env ]]; then
    [[ -f .env.example ]] || die ".env.example is missing — cannot bootstrap config."
    cp .env.example .env
    step "created .env from .env.example"
else
    step ".env already exists — leaving untouched"
fi

# ─── 3/6  generate strong secrets  ────────────────────────────────────
info "Rotating any placeholder secrets..."
gen_secret() { python3 -c 'import secrets; print(secrets.token_urlsafe(48))' 2>/dev/null \
              || openssl rand -base64 36 | tr -d '\n=' | tr '/+' '_-'; }

# Replace a KEY=... line in-place only when its value matches a placeholder pattern.
rotate() {
    local key="$1" placeholder_regex="$2" new_value
    if grep -Eq "^${key}=${placeholder_regex}\s*$" .env; then
        new_value="$(gen_secret)"
        # BSD/GNU sed compatibility: write to a temp file
        awk -v k="$key" -v v="$new_value" \
            'BEGIN{FS=OFS="="} $1==k {print k"="v; next} {print}' .env > .env.tmp
        mv .env.tmp .env
        step "generated $key"
    fi
}

rotate VCE_CREDENTIAL_SECRET 'change-me-.*'
rotate VCE_JWT_SECRET_KEY    'change-me-.*'
rotate VCE_ADMIN_PASSWORD    'change-me-.*'

# ─── 4/6  sanity-check that at least one LLM key is present  ──────────
info "Checking LLM configuration..."
set -a; source .env; set +a
provider="${VCE_LLM_PROVIDER:-google_genai}"
case "$provider" in
    google_genai) key="${GOOGLE_API_KEY:-}";    key_name="GOOGLE_API_KEY" ;;
    openai)       key="${OPENAI_API_KEY:-}";    key_name="OPENAI_API_KEY" ;;
    anthropic)    key="${ANTHROPIC_API_KEY:-}"; key_name="ANTHROPIC_API_KEY" ;;
    deepseek)     key="${DEEPSEEK_API_KEY:-}";  key_name="DEEPSEEK_API_KEY" ;;
    qwen)         key="${QWEN_API_KEY:-}";      key_name="QWEN_API_KEY" ;;
    *)            key="";                       key_name="(unknown provider)" ;;
esac
if [[ -z "$key" ]]; then
    warn "$key_name is not set in .env — the app will start but agent calls will fail."
    warn "Edit .env, add the key, then run:  docker compose restart vce-hq"
else
    step "$key_name detected for provider '$provider'"
fi

# ─── 5/6  build & start  ──────────────────────────────────────────────
info "Building image and starting container..."
docker compose up -d --build --remove-orphans

# ─── 6/6  wait for healthy  ───────────────────────────────────────────
info "Waiting for /health to become ready..."
host_port="${VCE_HOST_PORT:-8000}"
deadline=$(( $(date +%s) + 90 ))
while (( $(date +%s) < deadline )); do
    if curl -fsS "http://localhost:${host_port}/health" >/dev/null 2>&1; then
        info "VCE-HQ is up: http://localhost:${host_port}"
        step "UI:   http://localhost:${host_port}/ui/"
        step "Docs: http://localhost:${host_port}/docs"
        step "Logs: docker compose logs -f vce-hq"
        exit 0
    fi
    sleep 2
done

warn "Health check did not pass within 90s. Recent logs:"
docker compose logs --tail=50 vce-hq || true
die "Deployment did not reach a healthy state."
