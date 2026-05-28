# Team Cyber — Autonomous Multi-Agent Cybersecurity Platform

> An AI-powered, containerised cybersecurity operating system that autonomously scans source code repositories, detects vulnerabilities, explains root causes, and generates enterprise-grade security reports — using a coordinated swarm of specialised AI agents.

---

## Table of Contents

- [Vision](#vision)
- [Architecture](#architecture)
- [Container Map](#container-map)
- [Tech Stack](#tech-stack)
- [Prerequisites](#prerequisites)
- [Project Structure](#project-structure)
- [Environment Setup](#environment-setup)
- [Running the Platform](#running-the-platform)
- [Accessing the Platform](#accessing-the-platform)
- [API Reference](#api-reference)
- [Agent Pipeline](#agent-pipeline)
- [Security Tools](#security-tools)
- [LLM Strategy](#llm-strategy)
- [Development Roadmap](#development-roadmap)
- [Troubleshooting](#troubleshooting)

---

## Vision

Team Cyber is not a simple vulnerability scanner. It is an **Autonomous Multi-Agent Cybersecurity Operating System** that coordinates specialised AI agents in parallel — a Red Team for offensive analysis and a Blue Team for defensive analysis — with a dedicated Verification and Consensus layer that validates every finding before it reaches the report.

**Core capabilities:**

| Capability | Description |
|---|---|
| Static Analysis (SAST) | Semgrep + Bandit — detect injection, hardcoded secrets, insecure patterns |
| Dependency Scanning | Trivy + pip-audit — CVE mapping across all package managers |
| AI Root Cause Analysis | Groq Llama3-70B explains *why* each vulnerability exists |
| Verification Layer | Filter → Deduplicate → LLM Reflection → Consensus scoring |
| OWASP Compliance | Automatic mapping to OWASP Top 10 2021 with pass/fail scoring |
| PDF Reporting | Enterprise-grade PDF with all findings, fixes, and compliance breakdown |
| Real-time Dashboard | WebSocket-powered live scan progress and vulnerability dashboard |
| RAG Memory | Qdrant vector DB indexes findings for cross-scan similarity recall |

---

## Architecture

```
                         BROWSER
                            │
                            ▼
                    ┌───────────────┐
                    │  Nginx :80    │  ← Public entry point
                    │  (Proxy)      │
                    └──────┬────────┘
                           │
                           ▼
                    ┌───────────────┐
                    │  Backend :5000│  ← Flask API Gateway
                    │  JWT + WS     │     HTML, Auth, WebSocket
                    └──────┬────────┘
                           │  HTTP
                           ▼
                 ┌─────────────────────┐
                 │  Orchestrator :8000 │  ← Main Supervisor Agent
                 │  LangGraph Pipeline │     Task scheduling, monitoring
                 └────────┬────────────┘
                          │
          ┌───────────────┴───────────────┐
          │  (parallel)                   │
          ▼                               ▼
 ┌─────────────────┐             ┌─────────────────┐
 │  Red Team :8001 │             │ Blue Team :8002  │
 │  Supervisor     │             │ Supervisor       │
 │  ─────────────  │             │ ──────────────── │
 │  Recon Agent    │             │ SAST Agent       │
 │  Web Agent      │             │ Dependency Agent │
 │  API Agent      │             │ Fix Agent        │
 │  Exploit Agent  │             │ Compliance Agent │
 └────────┬────────┘             └────────┬─────────┘
          │                               │
          └───────────────┬───────────────┘
                          │
                          ▼
              ┌───────────────────────┐
              │   Verifier :8003      │  ← Verification + Reflection
              │   Filter → Dedup      │     + Consensus Layer
              │   → LLM Reflection    │
              │   → Consensus Score   │
              └───────────┬───────────┘
                          │
                          ▼
              ┌───────────────────────┐
              │   Reporter :8004      │  ← Report Generator
              │   PDF + Dashboard     │     + Dashboard Engine
              └───────────────────────┘
                          │
          ┌───────────────┼───────────────┐
          ▼               ▼               ▼
      MongoDB           Redis           Qdrant
   (scan data)      (pub/sub +       (embeddings
                      cache)           + RAG)
```

### Event Flow (Real-time)

```
Orchestrator → Redis (publish scan:events)
                  ↓
Backend → subscribes → emits WebSocket events → Browser updates live
```

---

## Container Map

| Container | Port | Role | Phase |
|---|---|---|---|
| `tc-nginx` | 80 | Public entry point, proxy, static file serving | 1 |
| `tc-backend` | 5000 | Flask API Gateway, JWT auth, HTML, WebSocket | 1 |
| `tc-orchestrator` | 8000 | Main Supervisor (LangGraph), task scheduling, monitoring | 1 |
| `tc-red-team` | 8001 | Red Team: Recon, Web, API, Exploit agents | 2 active |
| `tc-blue-team` | 8002 | Blue Team: SAST, Dependency, Fix, Compliance agents | 1 |
| `tc-verifier` | 8003 | Verification + Reflection + Consensus layer | 1 |
| `tc-reporter` | 8004 | PDF Report Generator + Dashboard Engine | 1 |
| `tc-mongo` | 27017 | MongoDB — users, scans, findings | 1 |
| `tc-redis` | 6379 | Redis — pub/sub event bus + caching | 1 |
| `tc-qdrant` | 6333 | Qdrant — vector DB for RAG | 1 |
| `tc-ollama` | 11434 | Ollama — local LLM inference (NVIDIA GPU) | 1 |
| `tc-ollama-init` | — | One-shot model puller (exits after pull) | 1 |

---

## Tech Stack

### Frontend
| Technology | Purpose |
|---|---|
| HTML5 + CSS3 | UI structure and dark cybersecurity theme |
| Vanilla JavaScript | Auth, API calls, real-time WebSocket updates |
| Jinja2 (via Flask) | Server-side HTML rendering |
| Socket.IO (CDN) | Real-time scan progress on the detail page |

### Backend
| Technology | Purpose |
|---|---|
| Flask | API Gateway + HTML serving |
| Flask-JWT-Extended | JWT authentication |
| Flask-SocketIO + gevent | WebSocket server |
| Flask-PyMongo | MongoDB integration |

### Agent Orchestration
| Technology | Purpose |
|---|---|
| LangGraph | Main Supervisor pipeline graph |
| httpx | Inter-container HTTP communication |
| Python threading | Parallel Red + Blue Team execution |

### AI / LLM
| Model | Provider | Used For |
|---|---|---|
| `llama3-8b-8192` | Groq (cloud, fast) | Lightweight tasks, false-positive reflection |
| `llama3-70b-8192` | Groq (cloud) | Root cause analysis, fix recommendations |
| `qwen2.5-coder:7b` | Ollama (local, GPU) | Code-level security analysis |

### Databases
| Database | Purpose |
|---|---|
| MongoDB 7.0 | Users, scans, findings |
| Redis 7.2 | Scan event pub/sub + caching |
| Qdrant | Finding embeddings + RAG recall |

### Security Tools (Blue Team container)
| Tool | Purpose |
|---|---|
| Semgrep | Multi-language static analysis (all languages) |
| Bandit | Python-specific security analysis |
| Trivy | Dependency CVE scanning (all package managers) |
| pip-audit | Python dependency vulnerability audit |

### Infrastructure
| Technology | Purpose |
|---|---|
| Docker + Docker Compose | Container orchestration |
| Nginx | Reverse proxy + static file serving |
| NVIDIA Container Toolkit | GPU passthrough for Ollama |

---

## Prerequisites

| Requirement | Notes |
|---|---|
| **Docker Desktop** | With WSL2 backend enabled on Windows |
| **NVIDIA GPU** | GTX 1650 or better, with latest drivers |
| **`nvidia-smi`** | Must work in terminal before starting |
| **Groq API Key** | Free at [console.groq.com](https://console.groq.com) |
| **Git** | For cloning and GitHub scan input |

> No Python, Node.js, or any language runtime needed locally. Everything runs inside Docker.

---

## Project Structure

```
team-cyber/
│
├── backend/                  # Flask API Gateway
│   ├── app.py                # Entry point (gevent + SocketIO)
│   ├── config.py             # Config + internal service URLs
│   ├── extensions.py         # mongo, jwt, socketio instances
│   ├── requirements.txt
│   ├── api/
│   │   ├── auth.py           # Register / Login / Me
│   │   ├── scans.py          # Upload ZIP / GitHub scan dispatch
│   │   ├── reports.py        # PDF proxy to reporter service
│   │   └── views.py          # HTML page routes
│   └── db/
│       ├── users.py          # User CRUD (MongoDB)
│       ├── scans.py          # Scan CRUD (MongoDB)
│       └── findings.py       # Finding CRUD (MongoDB)
│
├── orchestrator/             # Main Supervisor Agent
│   ├── app.py                # Flask microservice (:8000)
│   ├── supervisor.py         # LangGraph pipeline (5 nodes)
│   ├── scheduler.py          # Redis event publishing + health monitor
│   ├── requirements.txt
│   ├── db/                   # MongoDB helpers (scans, findings)
│   └── memory/
│       └── rag.py            # Qdrant RAG indexing
│
├── red_team/                 # Red Team Container
│   ├── app.py                # Flask microservice (:8001)
│   ├── supervisor.py         # Red Team Supervisor
│   ├── requirements.txt
│   └── agents/
│       ├── recon_agent.py    # Asset discovery, fingerprinting [Phase 2]
│       ├── web_agent.py      # SQLi, XSS, CSRF, SSRF [Phase 2]
│       ├── api_agent.py      # JWT, BOLA, rate limiting [Phase 2]
│       └── exploit_agent.py  # Safe PoC validation [Phase 2]
│
├── blue_team/                # Blue Team Container
│   ├── app.py                # Flask microservice (:8002)
│   ├── supervisor.py         # Blue Team Supervisor (parallel SAST + dep)
│   ├── requirements.txt
│   ├── agents/
│   │   ├── sast_agent.py     # Semgrep + Bandit
│   │   ├── dependency_agent.py  # Trivy + pip-audit
│   │   ├── fix_agent.py      # LLM root cause + remediation
│   │   └── compliance_agent.py  # OWASP Top 10 mapping
│   ├── tools/
│   │   ├── semgrep_tool.py
│   │   ├── bandit_tool.py
│   │   └── trivy_tool.py
│   └── models/
│       └── model_router.py   # Groq + Ollama router
│
├── verifier/                 # Verification + Reflection + Consensus
│   ├── app.py                # Flask microservice (:8003)
│   ├── verifier.py           # Filter → Dedup → Reflect → Consensus
│   ├── requirements.txt
│   └── models/
│       └── model_router.py
│
├── reporter/                 # Report Generator + Dashboard Engine
│   ├── app.py                # Flask microservice (:8004)
│   ├── pdf_report.py         # ReportLab PDF generation
│   ├── requirements.txt
│   └── db/                   # MongoDB helpers (scans, findings)
│
├── frontend/
│   ├── templates/
│   │   ├── base.html         # Shared layout + navbar
│   │   ├── auth/
│   │   │   ├── login.html
│   │   │   └── register.html
│   │   ├── dashboard/
│   │   │   └── index.html    # Scan history + severity stats
│   │   └── scans/
│   │       ├── new.html      # ZIP upload + GitHub URL form
│   │       └── detail.html   # Live progress + findings + PDF download
│   └── static/
│       ├── css/main.css      # Dark cybersecurity design system
│       └── js/main.js        # Auth guards, API helpers
│
├── docker/
│   ├── docker-compose.yml    # All 11 services
│   ├── backend.Dockerfile
│   ├── orchestrator.Dockerfile
│   ├── blue_team.Dockerfile  # Includes semgrep, bandit, trivy
│   ├── red_team.Dockerfile
│   ├── verifier.Dockerfile
│   ├── reporter.Dockerfile
│   ├── nginx.Dockerfile
│   └── nginx.conf
│
├── .env.example              # Template — copy to .env
├── requirements.txt          # Full reference (all services combined)
└── project-description.md   # Full system design document
```

---

## Environment Setup

**Step 1 — Copy the env template:**

```powershell
copy .env.example .env
```

**Step 2 — Fill in your keys** (open `.env` and set):

```env
SECRET_KEY=<random-string>
JWT_SECRET_KEY=<random-string>
GROQ_API_KEY=<your-groq-key-from-console.groq.com>
```

Everything else (service URLs, database URIs) is pre-configured for Docker networking and works out of the box.

---

## Running the Platform

### Start everything

```powershell
cd docker
docker compose up --build
```

First run takes longer:
- Python packages are downloaded and installed per container
- `qwen2.5-coder:7b` (~4GB) is pulled into Ollama automatically via `ollama-init`

### Start specific services only

```powershell
# Core only (backend + databases)
docker compose up --build backend mongo redis

# Full stack without Red Team (Phase 1)
docker compose up --build backend orchestrator blue-team verifier reporter mongo redis qdrant ollama
```

### Stop everything

```powershell
docker compose down
```

### Stop and wipe all data (fresh start)

```powershell
docker compose down -v
```

---

## Accessing the Platform

| URL | Description |
|---|---|
| `http://localhost` | Main entry point via Nginx (port 80) |
| `http://localhost:5000` | Backend direct access |
| `http://localhost:8000` | Orchestrator health check |
| `http://localhost:8001` | Red Team health check |
| `http://localhost:8002` | Blue Team health check |
| `http://localhost:8003` | Verifier health check |
| `http://localhost:8004` | Reporter health check |
| `http://localhost:6333` | Qdrant dashboard |
| `http://localhost:11434` | Ollama API |

### First time

1. Go to `http://localhost:5000/register`
2. Create an account (username, email, password ≥ 8 chars)
3. You are redirected to the dashboard
4. Click **+ New Scan** to start your first scan

---

## API Reference

### Authentication

| Method | Endpoint | Body | Description |
|---|---|---|---|
| `POST` | `/api/auth/register` | `{username, email, password}` | Create account |
| `POST` | `/api/auth/login` | `{email, password}` | Get JWT token |
| `GET` | `/api/auth/me` | — | Current user info |

### Scans

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/scans/` | List all scans for current user |
| `GET` | `/api/scans/<id>` | Get scan details + findings |
| `POST` | `/api/scans/upload` | Upload ZIP file for scanning |
| `POST` | `/api/scans/github` | Scan a GitHub repository URL |

### Reports

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/reports/<scan_id>/pdf` | Download PDF report |

All endpoints except `/register` and `/login` require:
```
Authorization: Bearer <jwt_token>
```

### WebSocket Events

| Event | Direction | Payload |
|---|---|---|
| `scan_progress` | Server → Client | `{scan_id, progress, message}` |
| `scan_complete` | Server → Client | `{scan_id, findings_count, compliance_score}` |
| `scan_error` | Server → Client | `{scan_id, error}` |

---

## Agent Pipeline

Each scan runs through this LangGraph pipeline in the Orchestrator:

```
1. detect        Detect tech stack from project files
       ↓
2. scan          Dispatch Blue Team + Red Team in parallel (HTTP)
       ↓
3. verify        Send all raw findings to Verifier
                  │
                  ├─ Filter        (drop < 45% confidence)
                  ├─ Deduplicate   (merge same vuln + location)
                  ├─ Reflect       (LLM peer-reviews uncertain findings)
                  └─ Consensus     (adjust severity by confidence)
       ↓
4. finalize      Save to MongoDB + index to Qdrant + emit completion
```

### Confidence Scoring

Each finding carries a `confidence` score (0.0 – 1.0):

| Score | Meaning |
|---|---|
| ≥ 0.90 | High confidence — tool + LLM both agree |
| 0.72 – 0.89 | Accepted without LLM reflection |
| 0.45 – 0.71 | LLM peer-review required before acceptance |
| < 0.45 | Dropped — too uncertain |

---

## Security Tools

### Blue Team (active — Phase 1)

| Tool | Language | What it finds |
|---|---|---|
| **Semgrep** | All | Injections, insecure patterns, hardcoded secrets, SSRF, XSS |
| **Bandit** | Python | Dangerous functions, crypto misuse, SQL injection, pickle |
| **Trivy** | All | CVEs in packages (npm, pip, gem, go, cargo, etc.) |
| **pip-audit** | Python | Known CVEs in `requirements.txt` |

### Red Team (Phase 2)

| Agent | Tools Planned | What it will find |
|---|---|---|
| **Recon Agent** | Nmap, WhatWeb, Amass, FFUF | Asset discovery, service fingerprinting |
| **Web Agent** | SQLMap, XSStrike, Nuclei | SQLi, XSS, CSRF, SSRF, auth bypass |
| **API Agent** | Custom fuzzer, JWT toolkit | BOLA, weak JWT secrets, rate limit bypass |
| **Exploit Agent** | Sandbox PoC runner | Safe exploit validation, attack chain mapping |

---

## LLM Strategy

The platform uses a **Centralized Model Router** — no single giant model per agent:

```
Task                    →  Model                →  Provider
─────────────────────────────────────────────────────────────
Root cause analysis     →  llama3-70b-8192      →  Groq (cloud)
Fix recommendations     →  llama3-70b-8192      →  Groq (cloud)
False-positive review   →  llama3-8b-8192       →  Groq (fast)
Code-level analysis     →  qwen2.5-coder:7b     →  Ollama (local GPU)
```

**Why this setup:**
- No VRAM bottleneck — local GPU handles code, cloud handles reasoning
- Groq gives ~500 tokens/sec — fast enough for real-time enrichment
- Qwen2.5-Coder is purpose-built for code security tasks
- Swappable — each model is configured via `.env`, zero code changes

---

## Development Roadmap

### Phase 1 — MVP ✅ (Current)
- [x] JWT authentication
- [x] ZIP upload + GitHub clone
- [x] Multi-container agent architecture (Docker Compose)
- [x] Blue Team: SAST + Dependency scanning
- [x] AI enrichment (root cause + fix recommendations)
- [x] Verification + Reflection + Consensus layer
- [x] OWASP Top 10 compliance scoring
- [x] Real-time WebSocket progress dashboard
- [x] PDF report generation
- [x] Qdrant RAG indexing
- [x] Nginx reverse proxy

### Phase 2 — Dynamic Analysis
- [ ] Red Team agents activated (Recon, Web, API)
- [ ] Live target scanning (with scope controls)
- [ ] API security testing (JWT, BOLA, rate limits)
- [ ] Advanced RAG (cross-scan attack path similarity)
- [ ] Celery/Redis task queue for distributed scanning
- [ ] Separate worker containers per security tool

### Phase 3 — Autonomous Reasoning
- [ ] Attack chain generation and validation
- [ ] Reflective AI with self-correction loops
- [ ] Consensus architecture (multi-model voting)
- [ ] Docker Swarm / Kubernetes deployment
- [ ] Exploit Agent (sandboxed PoC validation)
- [ ] Scheduled recurring scans
- [ ] Team collaboration and role management

---

## Troubleshooting

### Backend won't start

```powershell
docker logs tc-backend
```

Common causes:

| Error | Fix |
|---|---|
| `No module named 'backend'` | Use `python -m backend.app` in CMD (already set) |
| `ModuleNotFoundError: qdrant_client` | Remove qdrant imports from extensions.py (already done) |
| `gevent AssertionError` | `use_reloader=False` is required with gevent (already set) |

### Ollama keeps stopping

```powershell
docker logs tc-ollama
```

- Verify GPU: `nvidia-smi` must show your GPU on the host
- In Docker Desktop → Settings → Resources → GPU — must be enabled
- GTX 1650 has 4GB VRAM — `qwen2.5-coder:7b` needs ~4GB; if OOM, try `:3b`

### GROQ_API_KEY warning

The warning `"GROQ_API_KEY" variable is not set` is harmless — Docker Compose shows it during YAML parsing, but the key is correctly passed to containers via `env_file: ../.env`. Containers will have the key at runtime.

### Port already in use

```powershell
# Find what's using the port
netstat -ano | findstr :5000

# Or change the port in docker-compose.yml
ports:
  - "5001:5000"   # use 5001 externally
```

### Fresh database reset

```powershell
cd docker
docker compose down -v    # removes all volumes (wipes all data)
docker compose up --build
```

### Check all container health

```powershell
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
```

---

## Contributing

This project follows a **domain-agent architecture** — each agent domain lives in its own container with its own dependencies. When adding new agents:

1. Add agent logic inside the correct team container (`blue_team/agents/` or `red_team/agents/`)
2. Wire it into the team supervisor
3. No changes needed to the backend or orchestrator for new agent types

---

## License

MIT License — see `LICENSE` for details.

---

*Built with Flask, LangGraph, MongoDB, Redis, Qdrant, Ollama, Groq, Semgrep, Bandit, Trivy, Docker.*
