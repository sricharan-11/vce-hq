# VCE-HQ

**Multi-tenant AI-powered infrastructure operations advisor.**

VCE-HQ ingests observability signals (Datadog, CloudWatch, custom webhooks), routes them through specialized LLM agents, and delivers root-cause analyses and remediation playbooks — all without touching your infrastructure.

## Architecture

```
Webhook/Query → Event Normalizer → Router (LLM)
                                      │
                          ┌───────────┴───────────┐
                          ▼                       ▼
                   OS Engineer Agent      Cloud Engineer Agent
                    (LLM + RAG)            (LLM + RAG)
                          │                       │
                          └───────────┬───────────┘
                                      ▼
                            Security Review (mandatory)
                              (LLM + RAG)
                                      │
                                      ▼
                            Analysis & Playbook → Web UI
```

Each tenant runs in complete isolation with its own SQLite database (+ sqlite-vec for vector search), credentials vault, and agent context.

## Quick Start

### Using Docker (Recommended)

1. Clone the repository:
   ```bash
   git clone https://github.com/sricharan-11/vce-hq.git
   cd vce-hq
   ```

2. Configure the environment:
   ```bash
   cp .env.example .env
   # Edit .env with your GOOGLE_API_KEY
   ```

3. Run the application:
   ```bash
   docker compose up -d
   ```

The API will be available at `http://localhost:80`. Interactive docs at `/docs`.

### Bare Metal Installation

```bash
# 1. Clone and install
git clone <repo-url> && cd VCE-HQ
python -m venv venv
source venv/bin/activate
pip install -e ".[dev]"

# 2. Configure
cp .env.example .env
# Edit .env with your GOOGLE_API_KEY

# 3. Run
python -m vce_hq
# or: uvicorn vce_hq.api.app:create_app --factory --host 0.0.0.0 --port 80
```

The API will be available at `http://localhost:80`. Interactive docs at `/docs`.

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Health check |
| `POST` | `/webhooks/datadog` | Receive Datadog alert |
| `POST` | `/webhooks/cloudwatch` | Receive CloudWatch/SNS alert |
| `POST` | `/webhooks/custom` | Receive custom JSON alert |
| `POST` | `/analyze/` | Submit a free-text query |
| `POST` | `/knowledge/ingest` | Ingest a knowledge document |
| `POST` | `/credentials/` | Store a credential (hashed) |
| `GET` | `/credentials/` | List credentials (metadata only) |
| `POST` | `/credentials/{name}/verify` | Verify a credential |
| `PUT` | `/credentials/{name}/rotate` | Rotate a credential |
| `DELETE` | `/credentials/{name}` | Delete a credential |

All endpoints (except `/health`) require the `X-Tenant-ID` header.

## Project Structure

```
src/vce_hq/
├── config.py               # Centralized config (env vars)
├── db/                      # SQLite + sqlite-vec persistence
│   ├── connection.py        # Connection factory
│   ├── models.py            # Pydantic models
│   ├── migrations.py        # Schema migrations
│   ├── short_term.py        # Session/conversation CRUD
│   └── long_term.py         # Vector store operations
├── embeddings/service.py    # Google text-embedding-005 client
├── ingestion/               # Knowledge ingestion pipeline
│   ├── chunker.py           # Text splitting
│   └── pipeline.py          # Chunk → embed → store
├── agents/                  # LangGraph agent swarm
│   ├── state.py             # Shared state schema
│   ├── router.py            # Main Router agent
│   ├── os_engineer.py       # OS Engineer + RAG
│   ├── cloud_engineer.py    # Cloud Engineer + RAG
│   ├── security_review.py   # Security Review + RAG
│   ├── rag.py               # Shared RAG utility
│   └── graph.py             # LangGraph graph definition
├── webhooks/                # Event ingestion & normalization
├── vault/manager.py         # Hashed credential storage
└── api/                     # FastAPI application
    ├── app.py               # App factory
    ├── dependencies.py      # Dependency injection
    ├── middleware.py         # Request logging
    └── routes/              # API endpoints
```

## Running Tests

```bash
pytest -v
```

## Tech Stack

- **Python 3.12+** / **FastAPI** / **LangGraph**
- **SQLite + sqlite-vec** — per-tenant vector-capable database
- **Google Gemini** — LLM reasoning + `text-embedding-005` embeddings
- **Pydantic** — validation at all boundaries

## License

Released under the **Apache 2.0 License**.
