# pcap-analyzer

Take a pcap + context (JSON) → summarize it with zeek & tshark → have an LLM (Claude / local) analyze it.


<img src="./img/pcap-analyzer-demo.gif"></img>
## Setup
```bash
brew install zeek wireshark      # zeek + tshark
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
export ANTHROPIC_API_KEY=...     # for claude
# for local (OpenAI-compatible): LOCAL_LLM_URL=http://localhost:11434/v1 LOCAL_LLM_MODEL=llama3.1
.venv/bin/uvicorn app.main:app --reload
```

## Docker
```bash
cp .env.example .env             # set ANTHROPIC_API_KEY
docker compose up -d --build     # http://localhost:8000
docker compose logs -f
```
The image is based on `zeek/zeek:lts` and adds tshark + Python. `./data` (SQLite DB + uploaded pcaps) is
bind-mounted to `/data`, so existing data is reused. Run a single container/process — the job queue lives
in memory. A local LLM on the host is reachable via `http://host.docker.internal:11434/v1` (the default).

## Users & teams
Everything except the login page requires an account.
- On the first start an **admin** is created from `ADMIN_USERNAME` / `ADMIN_PASSWORD`. If `ADMIN_PASSWORD` is empty,
  a random password is generated and printed once in the logs (`docker compose logs | grep "generated password"`).
- The admin creates **teams** and **users** (UI: Admin → Users / Teams). A user can be in several teams.
- Every **analysis belongs to a team**. Members see only their teams' analyses; admins see everything.
  Analyses created before teams existed are moved to a `Default` team.
- Browser: session cookie (HttpOnly, SameSite=Lax; set `SESSION_COOKIE_SECURE=1` behind HTTPS).
  API clients: HTTP Basic, e.g. `curl -u alice:password ...`.
- Passwords are hashed with scrypt; repeated failed logins are throttled (5 per 15 min per username / IP).

## UI
Start the server and open `http://localhost:8000`. No build step and no CDN dependencies.

- **Overview:** all analyses, capture counts, active jobs
- **Analysis → Overview:** KPIs of the latest capture (change vs. previous capture + sparkline) and
  trend charts across captures (DNS unanswered rate, DNS RTT p95, connections, retransmissions)
- **Captures:** timeline; time between submissions, live status/progress
- **Capture detail:** Analytics (traffic time series, DNS query scatter, DNS server answer rate,
  response codes, conn_state, top hosts/ports, HTTP status/hosts/URIs, TLS versions/SNI/validation, zeek notices,
  TCP warnings/RTT), AI analysis + follow-up questions, commands, raw report, submitted data (incl. estimated cost)
- Hover/keyboard tooltips and a **Table** view on every chart; light/dark theme

## Usage
Each **analysis** works like a project; multiple pcaps (**runs**) are submitted to it at different times.
Runs are queued, the API returns `202` immediately, and progress is polled afterwards.

```bash
# all requests need credentials: session cookie (browser) or HTTP Basic (-u user:password)
# 1) Create an analysis (default_metadata is optional — if set, runs don't need to send metadata;
#    team_id can be omitted if you belong to exactly one team)
curl -u alice:password -X POST localhost:8000/analyses -H 'content-type: application/json' \
  -d "{\"name\": \"DNS issue\", \"default_metadata\": $(cat metadata.json)}"

# 2) Submit a pcap → 202 + run id
curl -u alice:password -X POST localhost:8000/analyses/1/runs \
  -F pcap=@dns.pcap \
  -F "metadata=<metadata.json" \
  -F provider=claude          # or local; -F dry_run=true → skip the LLM
                              # -F compare_previous=false → don't compare with earlier captures

# 3) Progress
curl -u alice:password localhost:8000/runs/1               # status, stage, progress, queue_position, report, result
curl -u alice:password -N localhost:8000/runs/1/events     # SSE: live progress, a `done` event at the end

# 4) Timeline: what was submitted when, and how much time passed in between
curl -u alice:password localhost:8000/analyses/1

# 5) Follow-up question on a finished Claude run
curl -u alice:password -X POST localhost:8000/runs/1/followups -H 'content-type: application/json' \
  -d '{"question": "Which DNS servers never answered?"}'
```

| Endpoint | Description |
|---|---|
| `POST /analyses` | Create an analysis |
| `GET /analyses` | List (run count, last submission, active jobs) |
| `GET /analyses/{id}` | Analysis + runs (`submitted_at`, `since_previous_seconds`, status) |
| `PATCH /analyses/{id}` | Update name / description / default_metadata (partial) |
| `DELETE /analyses/{id}` | Delete the analysis, its runs and pcap files |
| `POST /analyses/{id}/runs` | Submit a pcap and queue it (202) |
| `GET /runs/{id}` | Run detail: progress, report, result, error, chart statistics (`stats`) |
| `GET /runs/{id}/events` | SSE progress stream |
| `POST /tool-calls/{id}/approve` | Approve a command proposal; can be edited with `{"command": "..."}`, `note` is passed to Claude |
| `POST /tool-calls/{id}/reject` | Reject a command proposal (`note` optional) |
| `GET /capabilities` | Whether zeek / tshark are installed on the server |
| `POST /runs/{id}/retry` | Re-queue a failed or cancelled run |
| `POST /runs/{id}/cancel` | Cancel a run (or the follow-up being answered; the finished analysis is kept) |
| `POST /runs/{id}/followups` | Ask a follow-up question about a finished Claude run (continues the same conversation) |
| `POST /auth/login`, `POST /auth/logout`, `GET /auth/me`, `POST /auth/password` | Session login, current user, change own password |
| `GET/POST /admin/users`, `PATCH /admin/users/{id}` | Admin: list / create / update users (teams, admin, active, password reset) |
| `GET/POST /admin/teams`, `PATCH/DELETE /admin/teams/{id}` | Admin: list / create / rename / set members / delete teams |

**Approved extra commands (Claude):** during the analysis, Claude can propose a `tshark` command on the pcap
when the summary isn't enough to answer something. The run moves to `awaiting_approval`; you see the command in the UI
(or via the API), optionally edit it, and approve it — or reject it with a note. Once every proposal has been decided,
the approved commands are run, their output is given to Claude and the analysis continues. At most `MAX_TOOL_CALLS` (5)
commands per run; only allowlisted tshark flags (`-Y -R -2 -T -e -E -z -t -O -c -d -j -J -q -n -V -x -l -P -S -Q`) are accepted,
options that write files / capture live traffic / run scripts are rejected, and `-r` is added by the system.
This feature is disabled if tshark isn't installed. An analysis can be set to **auto-approve** valid commands
(Settings → "Auto-approve Claude's commands"); the Commands tab still records what ran and who approved it.

**Follow-up questions:** on a finished Claude run, ask more questions in the AI analysis tab. Claude continues the same
conversation (it may propose commands again, with a separate limit per question); the original report is kept.

**Cost:** every Claude turn's token usage and an estimated USD cost are stored per run and per follow-up and shown in the UI
(per capture, per analysis, per team for admins). Prices come from a built-in table; override with `MODEL_PRICES_JSON`.

**Uploads & retention:** uploads are capped at `MAX_UPLOAD_MB` (500). With `PCAP_RETENTION_DAYS` > 0, uploaded pcaps of
finished runs older than that are deleted hourly; results, reports and charts are kept.

**Comparison with earlier captures:** by default, the report and assessment of the last `HISTORY_RUNS` (3)
completed runs in the same analysis are given to the LLM as context; the result then includes a
"Changes vs. previous captures" section. The runs used are listed in the `context_run_ids` field.

Stages / progress: `queued 0` → `zeek 10` → `tshark 40` → `llm 60` → `llm_writing 60–95` (estimated) → `done 100` / `failed`.
If Claude proposes a command, `awaiting_approval` (waiting for approval) and `tool` (command running) come in between.

Environment variables: `DATA_DIR` (default `./data` — sqlite + pcaps), `WORKER_COUNT` (default 2), `HISTORY_RUNS` (default 3),
`REPORT_LANGUAGE` (language of the LLM report, default `English`), `ADMIN_USERNAME`, `ADMIN_PASSWORD`, `MAX_UPLOAD_MB` (500), `PCAP_RETENTION_DAYS` (0 = keep), `SESSION_TTL_HOURS` (168), `SESSION_COOKIE_SECURE` (0), `MODEL_PRICES_JSON`, `MAX_TOOL_CALLS` (5), `TOOL_TIMEOUT_SECONDS` (120),
`TOOL_MAX_OUTPUT_CHARS` (20000), `CLAUDE_MODEL`, `LOCAL_LLM_URL`, `LOCAL_LLM_MODEL`.

## Layout
- `app/models.py`  – payload models, IP → role/name labeling
- `app/parsers.py` – zeek (conn/weird/dns/tunnel) + tshark (RTT, TCP warnings, protocol breakdown); text report for the LLM + `stats` JSON for charts
- `app/llm.py`     – prompts + Claude / local LLM clients
- `app/db.py`      – SQLite schema, migrations and queries (users, teams, sessions, analyses, runs, tool_calls, followups)
- `app/worker.py`  – queue + worker threads, progress, pause/resume for approval, recovery after restart
- `app/tools.py`   – the tshark command Claude can propose: tool schema, argument allowlist, safe execution
- `app/auth.py`    – password hashing, sessions, HTTP Basic, login throttling, team-based access checks, first admin
- `app/routes_auth.py`, `app/routes_admin.py` – login/account endpoints, admin user/team management
- `app/main.py`    – FastAPI endpoints (analyses, runs, follow-ups, approvals, cancel, uploads, retention)
- `app/static/`    – UI: `index.html` (shell), `app.js` (pages, routing, live progress), `charts.js` (dependency-free SVG charts), `style.css`
