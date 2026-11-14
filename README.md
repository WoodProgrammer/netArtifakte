# pcap-analyzer

Take a pcap + context (JSON) → summarize it with zeek & tshark → have an LLM (Claude / local) analyze it.

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

## UI
Start the server and open `http://localhost:8000`. No build step and no CDN dependencies.

- **Overview:** all analyses, capture counts, active jobs
- **Analysis → Overview:** KPIs of the latest capture (change vs. previous capture + sparkline) and
  trend charts across captures (DNS unanswered rate, DNS RTT p95, connections, retransmissions)
- **Captures:** timeline; time between submissions, live status/progress
- **Capture detail:** Analytics (traffic time series, DNS query scatter, DNS server answer rate,
  response codes, conn_state, top hosts/ports, TCP warnings/RTT), AI analysis, commands, raw report, submitted data
- Hover/keyboard tooltips and a **Table** view on every chart; light/dark theme

## Usage
Each **analysis** works like a project; multiple pcaps (**runs**) are submitted to it at different times.
Runs are queued, the API returns `202` immediately, and progress is polled afterwards.

```bash
# 1) Create an analysis (default_metadata is optional — if set, runs don't need to send metadata)
curl -X POST localhost:8000/analyses -H 'content-type: application/json' \
  -d "{\"name\": \"DNS issue\", \"default_metadata\": $(cat metadata.json)}"

# 2) Submit a pcap → 202 + run id
curl -X POST localhost:8000/analyses/1/runs \
  -F pcap=@dns.pcap \
  -F "metadata=<metadata.json" \
  -F provider=claude          # or local; -F dry_run=true → skip the LLM
                              # -F compare_previous=false → don't compare with earlier captures

# 3) Progress
curl localhost:8000/runs/1               # status, stage, progress, queue_position, report, result
curl -N localhost:8000/runs/1/events     # SSE: live progress, a `done` event at the end

# 4) Timeline: what was submitted when, and how much time passed in between
curl localhost:8000/analyses/1
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
| `POST /runs/{id}/retry` | Re-queue a failed run |

**Approved extra commands (Claude):** during the analysis, Claude can propose a `tshark` command on the pcap
when the summary isn't enough to answer something. The run moves to `awaiting_approval`; you see the command in the UI
(or via the API), optionally edit it, and approve it — or reject it with a note. Once every proposal has been decided,
the approved commands are run, their output is given to Claude and the analysis continues. At most `MAX_TOOL_CALLS` (5)
commands per run; only allowlisted tshark flags (`-Y -R -2 -T -e -E -z -t -O -c -d -j -J -q -n -V -x -l -P -S -Q`) are accepted,
options that write files / capture live traffic / run scripts are rejected, and `-r` is added by the system.
This feature is disabled if tshark isn't installed.

**Comparison with earlier captures:** by default, the report and assessment of the last `HISTORY_RUNS` (3)
completed runs in the same analysis are given to the LLM as context; the result then includes a
"Changes vs. previous captures" section. The runs used are listed in the `context_run_ids` field.

Stages / progress: `queued 0` → `zeek 10` → `tshark 40` → `llm 60` → `llm_writing 60–95` (estimated) → `done 100` / `failed`.
If Claude proposes a command, `awaiting_approval` (waiting for approval) and `tool` (command running) come in between.

Environment variables: `DATA_DIR` (default `./data` — sqlite + pcaps), `WORKER_COUNT` (default 2), `HISTORY_RUNS` (default 3),
`REPORT_LANGUAGE` (language of the LLM report, default `English`), `MAX_TOOL_CALLS` (5), `TOOL_TIMEOUT_SECONDS` (120),
`TOOL_MAX_OUTPUT_CHARS` (20000), `CLAUDE_MODEL`, `LOCAL_LLM_URL`, `LOCAL_LLM_MODEL`.

## Layout
- `app/models.py`  – payload models, IP → role/name labeling
- `app/parsers.py` – zeek (conn/weird/dns/tunnel) + tshark (RTT, TCP warnings, protocol breakdown); text report for the LLM + `stats` JSON for charts
- `app/llm.py`     – prompts + Claude / local LLM clients
- `app/db.py`      – SQLite schema and queries (analyses, runs, tool_calls)
- `app/worker.py`  – queue + worker threads, progress, pause/resume for approval, recovery after restart
- `app/tools.py`   – the tshark command Claude can propose: tool schema, argument allowlist, safe execution
- `app/main.py`    – FastAPI endpoints
- `app/static/`    – UI: `index.html` (shell), `app.js` (pages, routing, live progress), `charts.js` (dependency-free SVG charts), `style.css`
