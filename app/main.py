"""API: create analyses (projects) and submit pcaps to them; jobs are processed asynchronously from a queue.

Every endpoint except login and the static UI requires a logged-in user (session cookie or HTTP Basic).
Users only see analyses of their own teams; admins see everything.
"""
import asyncio
import hashlib
import json
import logging
import os
import shutil
import threading
import uuid
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path
from typing import Literal

from fastapi import Depends, FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import ValidationError

from . import auth, db, tools
from .auth import User, current_user
from .models import AnalysisCreate, AnalysisUpdate, CaptureMeta, FollowupCreate, ToolDecision
from .routes_admin import router as admin_router
from .routes_auth import router as auth_router
from .worker import JobQueue

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("pcap-analyzer")

jobs = JobQueue(workers=int(os.getenv("WORKER_COUNT", "2")))
TERMINAL = set(db.TERMINAL_STATUSES)
MAX_UPLOAD_BYTES = int(float(os.getenv("MAX_UPLOAD_MB", "500")) * 1024 * 1024)
PCAP_RETENTION_DAYS = int(os.getenv("PCAP_RETENTION_DAYS", "0"))  # 0 = keep pcaps forever


def _retention_loop(stop: threading.Event) -> None:
    """Delete uploaded pcaps of finished runs older than PCAP_RETENTION_DAYS (results are kept)."""
    while not stop.is_set():
        try:
            for r in db.runs_with_expired_pcaps(PCAP_RETENTION_DAYS):
                db.pcap_file(r["pcap_path"]).unlink(missing_ok=True)
                db.update_run(r["id"], pcap_deleted=1)
                log.info("retention: deleted pcap of run %s", r["id"])
            db.purge_expired_sessions()
        except Exception:  # noqa: BLE001
            log.exception("retention pass failed")
        stop.wait(3600)


@asynccontextmanager
async def lifespan(_: FastAPI):
    db.init()
    auth.bootstrap_admin()
    jobs.start()
    stop = threading.Event()
    if PCAP_RETENTION_DAYS > 0:
        threading.Thread(target=_retention_loop, args=(stop,), name="retention", daemon=True).start()
    yield
    stop.set()
    jobs.stop()


app = FastAPI(title="pcap-analyzer", lifespan=lifespan)
app.include_router(auth_router)
app.include_router(admin_router)
STATIC_DIR = Path(__file__).parent / "static"
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.middleware("http")
async def reject_oversized_uploads(request: Request, call_next):
    """Fail fast on uploads whose declared size is over the limit (before the body is read)."""
    length = request.headers.get("content-length")
    if request.method == "POST" and length and length.isdigit() and int(length) > MAX_UPLOAD_BYTES + 1024 * 1024:
        return JSONResponse({"detail": f"upload too large (limit {MAX_UPLOAD_BYTES // (1024 * 1024)} MB)"}, 413)
    return await call_next(request)


@app.get("/", include_in_schema=False)
def index():
    return FileResponse(STATIC_DIR / "index.html")


# ---------------------------------------------------------------- serialization
def _seconds_between(a: str | None, b: str | None) -> float | None:
    if not a or not b:
        return None
    return (datetime.fromisoformat(b) - datetime.fromisoformat(a)).total_seconds()


def _usage(raw: str | None) -> dict | None:
    return json.loads(raw) if raw else None


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
                 "sha256": run["pcap_sha256"], "deleted": bool(run["pcap_deleted"])},
        "submitted_by": run["submitted_by_name"],
        "usage": _usage(run["usage"]),
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
        out["followups"] = [_followup_out(f) for f in db.list_followups(run["id"])]
        out["active_followup_id"] = run["active_followup_id"]
        out["cancel_requested"] = bool(run["cancel_requested"])
        out["can_follow_up"] = run["status"] == "done" and run["provider"] == "claude"
    else:
        out["pending_approvals"] = run["pending_approvals"]
        out["tool_call_count"] = run["tool_call_count"]
        out["followup_count"] = run["followup_count"]
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
        "followup_id": c["followup_id"],
        "tool": c["tool"],
        "status": c["status"],
        "purpose": c["purpose"],
        "args": args,
        "command": tools.display_command(args, filename),
        "edited_command": tools.display_command(final, filename) if final else None,
        "user_note": c["user_note"],
        # approved/executed with no deciding user = auto-approved by the analysis setting
        "decided_by": c["decided_by_name"] or ("auto" if c["decided_at"] and c["status"] in ("approved", "executed") else None),
        "output": c["output"],
        "exit_code": c["exit_code"],
        "duration": c["duration"],
        "created_at": c["created_at"],
        "decided_at": c["decided_at"],
        "finished_at": c["finished_at"],
    }


def _followup_out(f: dict) -> dict:
    return {"id": f["id"], "question": f["question"], "answer": f["answer"], "status": f["status"],
            "error": f["error"], "asked_by": f["user_name"], "usage": _usage(f["usage"]),
            "created_at": f["created_at"], "finished_at": f["finished_at"]}


def _analysis_out(a: dict) -> dict:
    return {
        "id": a["id"],
        "name": a["name"],
        "description": a["description"],
        "created_at": a["created_at"],
        "created_by": a.get("created_by_name"),
        "team_id": a["team_id"],
        "team_name": a.get("team_name"),
        "auto_approve": bool(a["auto_approve"]),
        "default_metadata": json.loads(a["default_metadata"]) if a.get("default_metadata") else None,
    }


def _blank_list_fields(run: dict) -> dict:
    return run | {"has_result": 0, "totals": None, "capture_start": None, "capture_end": None,
                  "pending_approvals": 0, "tool_call_count": 0, "followup_count": 0}


# ---------------------------------------------------------------- analyses
@app.post("/analyses", status_code=201)
def create_analysis(body: AnalysisCreate, user: User = Depends(current_user)):
    team_id = body.team_id
    if team_id is None:
        if len(user.team_ids) != 1:
            raise HTTPException(422, "team_id is required (you belong to more than one team, or to none)")
        team_id = user.team_ids[0]
    if not db.get_team(team_id) or not user.can_access_team(team_id):
        raise HTTPException(403, "you are not a member of this team")
    default = body.default_metadata.model_dump() if body.default_metadata else None
    analysis_id = db.create_analysis(body.name, body.description, default, team_id=team_id,
                                     created_by=user.id, auto_approve=body.auto_approve)
    return _analysis_out(db.get_analysis(analysis_id))


@app.get("/analyses")
def list_analyses(user: User = Depends(current_user)):
    return [{**a, "cost_usd": round(a["cost_usd"] or 0, 4)} for a in db.list_analyses(user.visible_team_ids)]


@app.get("/analyses/{analysis_id}")
def get_analysis(analysis_id: int, user: User = Depends(current_user)):
    """Analysis + its runs in time order (what was submitted when, and the gaps between them)."""
    a = auth.analysis_for(user, analysis_id)
    runs, prev, cost = [], None, 0.0
    for r in db.list_runs(analysis_id):
        item = _run_out(r)
        item["since_previous_seconds"] = _seconds_between(prev, r["created_at"])
        prev = r["created_at"]
        cost += (item["usage"] or {}).get("cost_usd", 0)
        runs.append(item)
    return {**_analysis_out(a), "cost_usd": round(cost, 4), "runs": runs}


@app.patch("/analyses/{analysis_id}")
def update_analysis(analysis_id: int, body: AnalysisUpdate, user: User = Depends(current_user)):
    """Update only the fields sent (existing runs are not affected)."""
    auth.analysis_for(user, analysis_id)
    fields = body.model_dump(include=body.model_fields_set)
    if fields.get("name") is not None and not fields["name"].strip():
        raise HTTPException(422, "name cannot be empty")
    for key in ("name", "team_id", "auto_approve"):
        if key in fields and fields[key] is None:
            del fields[key]
    if "team_id" in fields and (not db.get_team(fields["team_id"]) or not user.can_access_team(fields["team_id"])):
        raise HTTPException(403, "you are not a member of the target team")
    db.update_analysis(analysis_id, **fields)
    return _analysis_out(db.get_analysis(analysis_id))


@app.delete("/analyses/{analysis_id}", status_code=204)
def delete_analysis(analysis_id: int, user: User = Depends(current_user)):
    auth.analysis_for(user, analysis_id)
    for p in db.delete_analysis(analysis_id):
        db.pcap_file(p).unlink(missing_ok=True)


# ---------------------------------------------------------------- runs
def _save_upload(upload: UploadFile) -> tuple[Path, int, str]:
    path = db.PCAP_DIR / f"{uuid.uuid4().hex}.pcap"
    sha, size = hashlib.sha256(), 0
    with path.open("wb") as f:
        while chunk := upload.file.read(1024 * 1024):
            size += len(chunk)
            if size > MAX_UPLOAD_BYTES:
                f.close()
                path.unlink(missing_ok=True)
                raise HTTPException(413, f"upload too large (limit {MAX_UPLOAD_BYTES // (1024 * 1024)} MB)")
            sha.update(chunk)
            f.write(chunk)
    return path, size, sha.hexdigest()


def _require_api_key() -> None:
    if not os.getenv("ANTHROPIC_API_KEY"):
        raise HTTPException(400, "ANTHROPIC_API_KEY is not set")


@app.post("/analyses/{analysis_id}/runs", status_code=202)
def submit_run(
    analysis_id: int,
    pcap: UploadFile = File(...),
    metadata: str | None = Form(None, description="JSON; if empty, the analysis's default_metadata is used"),
    provider: Literal["claude", "local"] = Form("claude"),
    dry_run: bool = Form(False, description="if true, skips the LLM and only produces the parse output"),
    compare_previous: bool = Form(True, description="compare with earlier runs in the same analysis"),
    user: User = Depends(current_user),
):
    """Store the pcap, queue it and return immediately (202). Progress: GET /runs/{id} or /runs/{id}/events."""
    a = auth.analysis_for(user, analysis_id)
    raw = metadata or a["default_metadata"]
    if not raw:
        raise HTTPException(422, "no metadata was sent and the analysis has no default_metadata")
    try:
        meta = CaptureMeta.model_validate_json(raw)
    except ValidationError as e:
        raise HTTPException(422, f"invalid metadata: {e}")
    if provider == "claude" and not dry_run:
        _require_api_key()

    path, size, sha = _save_upload(pcap)
    if size == 0:
        path.unlink(missing_ok=True)
        raise HTTPException(422, "pcap file is empty")
    run_id = db.create_run(
        analysis_id, provider=provider, dry_run=dry_run, compare_previous=compare_previous,
        metadata=meta.model_dump_json(), pcap_filename=pcap.filename or "upload.pcap", pcap_size=size,
        pcap_sha256=sha, pcap_path=str(path), submitted_by=user.id,
    )
    jobs.submit(run_id)
    return {**_run_out(_blank_list_fields(db.get_run(run_id))),
            "links": {"self": f"/runs/{run_id}", "events": f"/runs/{run_id}/events"}}


@app.get("/runs/{run_id}")
def get_run(run_id: int, user: User = Depends(current_user)):
    return _run_out(auth.run_for(user, run_id), detail=True)


@app.post("/runs/{run_id}/retry", status_code=202)
def retry_run(run_id: int, user: User = Depends(current_user)):
    r = auth.run_for(user, run_id)
    if r["status"] not in ("failed", "cancelled"):
        raise HTTPException(409, "only failed or cancelled runs can be retried")
    if r["pcap_deleted"]:
        raise HTTPException(409, "the pcap of this run was deleted by the retention policy")
    db.reset_run(run_id)
    jobs.submit(run_id)
    return _run_out(db.get_run(run_id), detail=True)


@app.post("/runs/{run_id}/cancel")
def cancel_run(run_id: int, user: User = Depends(current_user)):
    """Queued / awaiting-approval runs stop immediately; a running one stops at its next checkpoint."""
    r = auth.run_for(user, run_id)
    # Cancelling a follow-up keeps the finished analysis; otherwise the run itself is cancelled.
    result = db.request_cancel_followup(run_id) if r["active_followup_id"] else db.request_cancel(run_id)
    if result is None:
        raise HTTPException(409, f"run is not active (status: {r['status']})")
    return _run_out(db.get_run(run_id), detail=True)


@app.post("/runs/{run_id}/followups", status_code=202)
def ask_followup(run_id: int, body: FollowupCreate, user: User = Depends(current_user)):
    """Ask Claude a follow-up question about a finished analysis; it continues the same conversation."""
    r = auth.run_for(user, run_id)
    if r["provider"] != "claude":
        raise HTTPException(409, "follow-up questions are only supported for Claude runs")
    if r["status"] != "done":
        raise HTTPException(409, "the run must be finished before asking a follow-up question")
    _require_api_key()
    followup_id = db.create_followup(run_id, user.id, body.question.strip())
    if not db.start_followup(run_id, followup_id):
        db.update_followup(followup_id, status="failed", error="run became busy", finished_at=db.now())
        raise HTTPException(409, "the run is busy; try again in a moment")
    jobs.submit(run_id)
    return _run_out(db.get_run(run_id), detail=True)


@app.get("/capabilities")
def capabilities(_: User = Depends(current_user)):
    """Tools installed on the server and limits (for UI hints)."""
    return {"zeek": shutil.which("zeek") is not None, "tshark": tools.available(),
            "max_tool_calls": tools.MAX_TOOL_CALLS, "max_upload_mb": MAX_UPLOAD_BYTES // (1024 * 1024),
            "pcap_retention_days": PCAP_RETENTION_DAYS}


# ---------------------------------------------------------------- command approvals
def _decide(call_id: int, approve: bool, body: ToolDecision, user: User) -> dict:
    c = db.get_tool_call(call_id)
    if not c:
        raise HTTPException(404, "command proposal not found")
    run = auth.run_for(user, c["run_id"])
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
    if not db.decide_tool_call(call_id, "approved" if approve else "rejected", final_args, note, user.id):
        raise HTTPException(409, "a decision has already been made for this proposal")
    if db.resume_if_decided(run["id"]):
        jobs.submit(run["id"])  # every proposal has been decided → run the commands and continue the analysis
    return _run_out(db.get_run(run["id"]), detail=True)


@app.post("/tool-calls/{call_id}/approve")
def approve_tool_call(call_id: int, body: ToolDecision | None = None, user: User = Depends(current_user)):
    """Approve the command (optionally edited via `command`). If no other proposals are pending, the analysis continues."""
    return _decide(call_id, True, body or ToolDecision(), user)


@app.post("/tool-calls/{call_id}/reject")
def reject_tool_call(call_id: int, body: ToolDecision | None = None, user: User = Depends(current_user)):
    """Reject the command; Claude continues with the data it has. `note` is passed to Claude."""
    return _decide(call_id, False, body or ToolDecision(), user)


@app.get("/runs/{run_id}/events")
async def run_events(run_id: int, request: Request, user: User = Depends(current_user)):
    """Server-Sent Events: a `progress` event whenever status/progress changes, a `done` event at the end."""
    auth.run_for(user, run_id)

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
                payload = {"status": r["status"], "stage": r["stage"], "progress": r["progress"],
                           "followup_id": r["active_followup_id"]}
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
