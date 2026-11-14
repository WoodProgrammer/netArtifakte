"""API: create analyses (projects) and submit pcaps to them; jobs are processed asynchronously from a queue."""
import asyncio
import hashlib
import json
import logging
import os
import uuid
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path
from typing import Literal

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import ValidationError

from . import db, tools
from .models import AnalysisCreate, AnalysisUpdate, CaptureMeta, ToolDecision
from .worker import JobQueue

logging.basicConfig(level=logging.INFO)

jobs = JobQueue(workers=int(os.getenv("WORKER_COUNT", "2")))
TERMINAL = {"done", "failed"}


@asynccontextmanager
async def lifespan(_: FastAPI):
    db.init()
    jobs.start()
    yield
    jobs.stop()


app = FastAPI(title="pcap-analyzer", lifespan=lifespan)
STATIC_DIR = Path(__file__).parent / "static"


app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/", include_in_schema=False)
def index():
    return FileResponse(STATIC_DIR / "index.html")


# ---------------------------------------------------------------- serialization
def _seconds_between(a: str | None, b: str | None) -> float | None:
    if not a or not b:
        return None
    return (datetime.fromisoformat(b) - datetime.fromisoformat(a)).total_seconds()


def _run_out(run: dict, *, detail: bool = False) -> dict:
    out = {
        "id": run["id"],
        "analysis_id": run["analysis_id"],
        "status": run["status"],
        "stage": run["stage"],
        "progress": run["progress"],
        "provider": run["provider"],
        "dry_run": bool(run["dry_run"]),
        "compare_previous": bool(run["compare_previous"]),
        "context_run_ids": json.loads(run["context_run_ids"]) if run["context_run_ids"] else [],
        "metadata": json.loads(run["metadata"]),
        "pcap": {"filename": run["pcap_filename"], "size": run["pcap_size"],
                 "sha256": run["pcap_sha256"]},
        "error": run["error"],
        "submitted_at": run["created_at"],
        "started_at": run["started_at"],
        "finished_at": run["finished_at"],
        "wait_seconds": _seconds_between(run["created_at"], run["started_at"]),
        "duration_seconds": _seconds_between(run["started_at"], run["finished_at"]),
    }
    if run["status"] == "queued" and (pos := db.queue_position(run["id"])):
        out["queue_position"] = pos  # 0 means a worker just picked it up
    if detail:
        out["report"] = run["report"]
        out["result"] = run["result"]
        out["stats"] = json.loads(run["stats"]) if run["stats"] else None
        out["tool_calls"] = [_tool_call_out(c, run["pcap_filename"]) for c in db.list_tool_calls(run["id"])]
        out["pending_approvals"] = sum(c["status"] == "pending" for c in out["tool_calls"])
    else:
        out["pending_approvals"] = run["pending_approvals"]
        out["tool_call_count"] = run["tool_call_count"]
        out["has_result"] = bool(run["has_result"])
        out["totals"] = json.loads(run["totals"]) if run["totals"] else None
        out["capture"] = {"start": run["capture_start"], "end": run["capture_end"]}
    return out


def _tool_call_out(c: dict, filename: str) -> dict:
    args = json.loads(c["args"])
    final = json.loads(c["final_args"]) if c["final_args"] else None
    return {
        "id": c["id"],
        "run_id": c["run_id"],
        "tool": c["tool"],
        "status": c["status"],
        "purpose": c["purpose"],
        "args": args,
        "command": tools.display_command(args, filename),
        "edited_command": tools.display_command(final, filename) if final else None,
        "user_note": c["user_note"],
        "output": c["output"],
        "exit_code": c["exit_code"],
        "duration": c["duration"],
        "created_at": c["created_at"],
        "decided_at": c["decided_at"],
        "finished_at": c["finished_at"],
    }


def _analysis_out(a: dict) -> dict:
    return {
        "id": a["id"],
        "name": a["name"],
        "description": a["description"],
        "created_at": a["created_at"],
        "default_metadata": json.loads(a["default_metadata"]) if a.get("default_metadata") else None,
    }


def _get_analysis_or_404(analysis_id: int) -> dict:
    a = db.get_analysis(analysis_id)
    if not a:
        raise HTTPException(404, "analysis not found")
    return a


def _get_run_or_404(run_id: int) -> dict:
    r = db.get_run(run_id)
    if not r:
        raise HTTPException(404, "run not found")
    return r


# ---------------------------------------------------------------- analyses
@app.post("/analyses", status_code=201)
def create_analysis(body: AnalysisCreate):
    default = body.default_metadata.model_dump() if body.default_metadata else None
    analysis_id = db.create_analysis(body.name, body.description, default)
    return _analysis_out(db.get_analysis(analysis_id))


@app.get("/analyses")
def list_analyses():
    return [{**a, "active_runs": a["active_runs"] or 0, "awaiting_runs": a["awaiting_runs"] or 0}
            for a in db.list_analyses()]


@app.get("/analyses/{analysis_id}")
def get_analysis(analysis_id: int):
    """Analysis + its runs in time order (what was submitted when, and the gaps between them)."""
    a = _get_analysis_or_404(analysis_id)
    runs, prev = [], None
    for r in db.list_runs(analysis_id):
        item = _run_out(r)
        item["since_previous_seconds"] = _seconds_between(prev, r["created_at"])
        prev = r["created_at"]
        runs.append(item)
    return {**_analysis_out(a), "runs": runs}


@app.patch("/analyses/{analysis_id}")
def update_analysis(analysis_id: int, body: AnalysisUpdate):
    """Update only the fields sent (existing runs are not affected)."""
    _get_analysis_or_404(analysis_id)
    fields = body.model_dump(include=body.model_fields_set)
    if fields.get("name") is not None and not fields["name"].strip():
        raise HTTPException(422, "name cannot be empty")
    if "name" in fields and fields["name"] is None:
        del fields["name"]
    db.update_analysis(analysis_id, **fields)
    return _analysis_out(db.get_analysis(analysis_id))


@app.delete("/analyses/{analysis_id}", status_code=204)
def delete_analysis(analysis_id: int):
    _get_analysis_or_404(analysis_id)
    for p in db.delete_analysis(analysis_id):
        db.pcap_file(p).unlink(missing_ok=True)


# ---------------------------------------------------------------- runs
def _save_upload(upload: UploadFile) -> tuple[Path, int, str]:
    path = db.PCAP_DIR / f"{uuid.uuid4().hex}.pcap"
    sha, size = hashlib.sha256(), 0
    with path.open("wb") as f:
        while chunk := upload.file.read(1024 * 1024):
            sha.update(chunk)
            size += len(chunk)
            f.write(chunk)
    return path, size, sha.hexdigest()


@app.post("/analyses/{analysis_id}/runs", status_code=202)
def submit_run(
    analysis_id: int,
    pcap: UploadFile = File(...),
    metadata: str | None = Form(None, description="JSON; if empty, the analysis's default_metadata is used"),
    provider: Literal["claude", "local"] = Form("claude"),
    dry_run: bool = Form(False, description="if true, skips the LLM and only produces the parse output"),
    compare_previous: bool = Form(True, description="compare with earlier runs in the same analysis"),
):
    """Store the pcap, queue it and return immediately (202). Progress: GET /runs/{id} or /runs/{id}/events."""
    a = _get_analysis_or_404(analysis_id)
    raw = metadata or a["default_metadata"]
    if not raw:
        raise HTTPException(422, "no metadata was sent and the analysis has no default_metadata")
    try:
        meta = CaptureMeta.model_validate_json(raw)
    except ValidationError as e:
        raise HTTPException(422, f"invalid metadata: {e}")
    if provider == "claude" and not dry_run and not os.getenv("ANTHROPIC_API_KEY"):
        raise HTTPException(400, "ANTHROPIC_API_KEY is not set")

    path, size, sha = _save_upload(pcap)
    if size == 0:
        path.unlink(missing_ok=True)
        raise HTTPException(422, "pcap file is empty")
    run_id = db.create_run(
        analysis_id, provider=provider, dry_run=dry_run, compare_previous=compare_previous,
        metadata=meta.model_dump_json(),
        pcap_filename=pcap.filename or "upload.pcap", pcap_size=size, pcap_sha256=sha,
        pcap_path=str(path),
    )
    jobs.submit(run_id)
    return {**_run_out(db.get_run(run_id) | {"has_result": 0, "totals": None, "capture_start": None,
                                              "capture_end": None, "pending_approvals": 0, "tool_call_count": 0}),
            "links": {"self": f"/runs/{run_id}", "events": f"/runs/{run_id}/events"}}


@app.get("/runs/{run_id}")
def get_run(run_id: int):
    return _run_out(_get_run_or_404(run_id), detail=True)


@app.post("/runs/{run_id}/retry", status_code=202)
def retry_run(run_id: int):
    r = _get_run_or_404(run_id)
    if r["status"] != "failed":
        raise HTTPException(409, "only failed runs can be retried")
    db.reset_run(run_id)
    jobs.submit(run_id)
    return _run_out(db.get_run(run_id), detail=True)


@app.get("/capabilities")
def capabilities():
    """Tools installed on the server (for UI warnings)."""
    import shutil
    return {"zeek": shutil.which("zeek") is not None, "tshark": tools.available(),
            "max_tool_calls": tools.MAX_TOOL_CALLS}


# ---------------------------------------------------------------- command approvals
def _decide(call_id: int, approve: bool, body: ToolDecision) -> dict:
    c = db.get_tool_call(call_id)
    if not c:
        raise HTTPException(404, "command proposal not found")
    run = db.get_run(c["run_id"])
    if c["status"] != "pending" or run["status"] != "awaiting_approval":
        raise HTTPException(409, "a decision has already been made for this proposal")
    final_args = None
    if approve and body.command is not None and body.command.strip():
        try:
            args = tools.split_command(body.command)
            tools.validate_args(args)
        except tools.CommandError as e:
            raise HTTPException(422, f"invalid command: {e}")
        if args != json.loads(c["args"]):
            final_args = args
    note = (body.note or "").strip() or None
    if not db.decide_tool_call(call_id, "approved" if approve else "rejected", final_args, note):
        raise HTTPException(409, "a decision has already been made for this proposal")
    if db.resume_if_decided(run["id"]):
        jobs.submit(run["id"])  # every proposal has been decided → run the commands and continue the analysis
    return _run_out(db.get_run(run["id"]), detail=True)


@app.post("/tool-calls/{call_id}/approve")
def approve_tool_call(call_id: int, body: ToolDecision | None = None):
    """Approve the command (optionally edited via `command`). If no other proposals are pending, the analysis continues."""
    return _decide(call_id, True, body or ToolDecision())


@app.post("/tool-calls/{call_id}/reject")
def reject_tool_call(call_id: int, body: ToolDecision | None = None):
    """Reject the command; Claude continues with the data it has. `note` is passed to Claude."""
    return _decide(call_id, False, body or ToolDecision())


@app.get("/runs/{run_id}/events")
async def run_events(run_id: int, request: Request):
    """Server-Sent Events: a `progress` event whenever status/progress changes, a `done` event at the end."""
    _get_run_or_404(run_id)

    async def stream():
        last = None
        while not await request.is_disconnected():
            r = await asyncio.to_thread(db.get_run, run_id)
            if r is None:
                yield "event: error\ndata: {\"detail\": \"run was deleted\"}\n\n"
                return
            state = (r["status"], r["stage"], r["progress"])
            if state != last:
                last = state
                payload = {"status": r["status"], "stage": r["stage"], "progress": r["progress"]}
                if r["status"] == "queued":
                    payload["queue_position"] = await asyncio.to_thread(db.queue_position, run_id)
                if r["status"] == "awaiting_approval":
                    calls = await asyncio.to_thread(db.list_tool_calls, run_id)
                    payload["pending_approvals"] = sum(c["status"] == "pending" for c in calls)
                if r["status"] in TERMINAL:
                    payload["error"] = r["error"]
                    yield f"event: done\ndata: {json.dumps(payload)}\n\n"
                    return
                yield f"event: progress\ndata: {json.dumps(payload)}\n\n"
            await asyncio.sleep(1)

    return StreamingResponse(stream(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache"})
