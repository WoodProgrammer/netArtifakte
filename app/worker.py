"""Background queue: parses runs and sends them to the LLM.

The DB is the source of truth; the in-memory queue only carries run ids. If the server
restarts, `queued`/`running` runs are read from the DB and queued again.

If Claude proposes a tshark command (tool_use), the run moves to `awaiting_approval` and the
worker thread is released. Once the user has decided on every proposal, the run is queued
again; the worker runs the approved commands, gives the results to Claude and continues the analysis.
"""
import json
import logging
import os
import queue
import tempfile
import threading
from pathlib import Path

from . import db, tools
from .llm import analyze, build_history, build_prompt, claude_turn, system_prompt
from .models import CaptureMeta
from .parsers import build_report

log = logging.getLogger("pcap-analyzer.worker")

# LLM stage progress: 60 → 95, estimated from generated characters / expected length.
LLM_START, LLM_END = 60, 95
EXPECTED_ANSWER_CHARS = int(os.getenv("EXPECTED_ANSWER_CHARS", "6000"))
# Number of earlier runs given to the LLM for comparison.
HISTORY_RUNS = int(os.getenv("HISTORY_RUNS", "3"))
# Maximum number of Claude turns per run (infinite-loop guard).
MAX_TURNS = tools.MAX_TOOL_CALLS + 4


class Paused(Exception):
    """The run is waiting for user approval; the worker releases it."""


def process(run_id: int) -> None:
    if not db.claim_run(run_id):
        return  # deleted, taken by another worker, or not queued
    run = db.get_run(run_id)
    resuming = run["conversation"] is not None and run["report"] is not None

    last = {"stage": run["stage"], "progress": run["progress"]}

    def set_progress(stage: str, progress: int) -> None:
        if (stage, progress) != (last["stage"], last["progress"]):  # avoid redundant DB writes
            last.update(stage=stage, progress=progress)
            db.update_run(run_id, stage=stage, progress=progress)

    try:
        meta = CaptureMeta.model_validate_json(run["metadata"])
        if resuming:
            report = run["report"]
        else:
            db.update_run(run_id, stage="zeek", progress=5, started_at=db.now())
            last.update(stage="zeek", progress=5)
            with tempfile.TemporaryDirectory() as tmp:
                report, stats = build_report(db.pcap_file(run["pcap_path"]), Path(tmp), meta, on_stage=set_progress)
            db.update_run(run_id, report=report, stats=json.dumps(stats))

        if run["dry_run"]:
            db.update_run(run_id, status="done", stage="done", progress=100, finished_at=db.now())
            return

        if run["provider"] == "claude":
            answer = _claude_phase(db.get_run(run_id), meta, report, set_progress)
        else:
            history = _history(run)
            set_progress("llm", LLM_START)
            answer = analyze(run["provider"], meta, report, history=history)

        db.update_run(run_id, result=answer, status="done", stage="done", progress=100,
                      finished_at=db.now())
    except Paused:
        db.update_run(run_id, status="awaiting_approval", stage="awaiting_approval")
        log.info("run %s is waiting for user approval", run_id)
    except Exception as e:  # noqa: BLE001 — the error is stored on the run; the worker keeps going
        log.exception("run %s failed", run_id)
        db.update_run(run_id, status="failed", stage="failed", error=f"{type(e).__name__}: {e}",
                      finished_at=db.now())


def _history(run: dict) -> str:
    if not (run["compare_previous"] and HISTORY_RUNS > 0):
        return ""
    previous = db.previous_runs(run["analysis_id"], run["id"], HISTORY_RUNS)
    if not previous:
        return ""
    db.update_run(run["id"], context_run_ids=json.dumps([r["id"] for r in previous]))
    return build_history(previous, run["created_at"])


# ---------------------------------------------------------------- Claude + approved commands
def _claude_phase(run: dict, meta: CaptureMeta, report: str, set_progress) -> str:
    run_id = run["id"]

    if run["conversation"]:
        conv = json.loads(run["conversation"])
        last_msg = conv["messages"][-1]
        if last_msg["role"] == "assistant":
            # Resuming after approval: append the results for the last turn's tool_use blocks.
            conv["messages"].append({"role": "user", "content": _tool_results(run, last_msg, set_progress)})
            _save(run_id, conv)
    else:
        # The system prompt and tool list must stay fixed for the whole conversation (if they change,
        # the earlier history becomes invalid), so both are stored with the conversation.
        tools_enabled = tools.available()
        conv = {"tools_enabled": tools_enabled, "system": system_prompt(tools_enabled),
                "messages": [{"role": "user", "content": build_prompt(meta, report, _history(run))}]}
        _save(run_id, conv)

    written = {"chars": 0}
    for _ in range(MAX_TURNS):
        base = written["chars"]
        set_progress("llm", LLM_START + int(min(base / EXPECTED_ANSWER_CHARS, 1.0) * (LLM_END - LLM_START)))

        def on_progress(chars: int) -> None:
            written["chars"] = base + chars
            frac = min(written["chars"] / EXPECTED_ANSWER_CHARS, 1.0)
            set_progress("llm_writing", LLM_START + int(frac * (LLM_END - LLM_START)))

        # Conversations stored before `system` was saved fall back to the current prompt.
        msg = claude_turn(conv["messages"], conv["tools_enabled"], on_progress, system=conv.get("system"))
        if msg.stop_reason == "refusal":
            raise RuntimeError("Claude declined the request.")
        if msg.stop_reason == "max_tokens":
            # tool input may have been cut off mid-way; running it isn't safe
            raise RuntimeError("Claude's response hit the max_tokens limit.")

        # Assistant content (including thinking blocks) is stored and sent back completely unchanged.
        assistant = {"role": "assistant", "content": msg.to_dict(mode="json")["content"]}
        conv["messages"].append(assistant)
        _save(run_id, conv)

        if msg.stop_reason == "pause_turn":
            continue
        if msg.stop_reason != "tool_use":
            return "".join(b.text for b in msg.content if b.type == "text")

        # Command proposals: stop if any of them need user approval.
        conv["messages"].append({"role": "user", "content": _tool_results(db.get_run(run_id), assistant, set_progress)})
        _save(run_id, conv)
    raise RuntimeError(f"Claude did not finish the report within {MAX_TURNS} turns.")


def _save(run_id: int, conv: dict) -> None:
    db.update_run(run_id, conversation=json.dumps(conv))


def _tool_results(run: dict, assistant: dict, set_progress) -> list[dict]:
    """Produce a tool_result for every tool_use in the assistant message.

    - Registers proposals not seen yet (ones that fail validation or exceed the limit are answered automatically).
    - Raises Paused if any proposal is waiting for the user's decision.
    - Runs the approved ones.
    Results are returned in tool_use order, in a single user message.
    """
    run_id = run["id"]
    uses = [b for b in assistant["content"] if b.get("type") == "tool_use"]
    known = {c["tool_use_id"]: c for c in db.list_tool_calls(run_id)}
    used = sum(c["status"] not in ("invalid", "limit") for c in known.values())

    for b in uses:
        if b["id"] in known:
            continue
        raw = b.get("input") or {}
        args = raw.get("args") if isinstance(raw.get("args"), list) else []
        purpose = raw.get("purpose") if isinstance(raw.get("purpose"), str) else ""
        if b.get("name") != tools.TOOL_NAME:
            status, out = "invalid", f"Unknown tool: {b.get('name')}"
        elif used >= tools.MAX_TOOL_CALLS:
            status, out = "limit", (f"Command limit ({tools.MAX_TOOL_CALLS}) reached; this command was not run. "
                                    "Don't propose more commands; finish the report with the data you have.")
        else:
            try:
                tools.parse_input(raw)
                status, out = "pending", None
                used += 1
            except tools.CommandError as e:
                status, out = "invalid", f"Command failed validation and was not run: {e}"
        db.create_tool_call(run_id, tool_use_id=b["id"], tool=b.get("name", ""), args=args,
                            purpose=purpose, status=status, output=out)

    calls = {c["tool_use_id"]: c for c in db.list_tool_calls(run_id)}
    if any(calls[b["id"]]["status"] == "pending" for b in uses):
        raise Paused()

    results = []
    approved = [b for b in uses if calls[b["id"]]["status"] == "approved"]
    for b in uses:
        c = calls[b["id"]]
        if c["status"] == "approved":
            set_progress("tool", LLM_START)
            args = json.loads(c["final_args"] or c["args"])
            log.info("run %s: running command (%d/%d): %s", run_id, approved.index(b) + 1, len(approved), args)
            res = tools.run_tshark(db.pcap_file(run["pcap_path"]), args)
            db.update_tool_call(c["id"], status="executed", output=res["output"], exit_code=res["exit_code"],
                                duration=res["duration"], finished_at=db.now())
            c = db.get_tool_call(c["id"])
        results.append(_result_block(b["id"], c, run["pcap_filename"]))
    return results


def _result_block(tool_use_id: str, c: dict, filename: str) -> dict:
    note = f"\nUser note: {c['user_note']}" if c.get("user_note") else ""
    if c["status"] == "executed":
        args = json.loads(c["final_args"] or c["args"])
        head = f"Command run: {tools.display_command(args, filename)}"
        if c["final_args"]:
            head += f"\n(The user edited the command. You proposed: {tools.display_command(json.loads(c['args']), filename)})"
        body = f"{head}{note}\nexit code: {c['exit_code']} · duration: {c['duration']} s\n\n{c['output']}"
        return {"type": "tool_result", "tool_use_id": tool_use_id, "content": body,
                "is_error": c["exit_code"] != 0}
    if c["status"] == "rejected":
        body = ("The user declined to run this command." + note +
                "\nContinue without it, using the data you have.")
    else:  # invalid | limit
        body = c["output"] or "The command was not run."
    return {"type": "tool_result", "tool_use_id": tool_use_id, "content": body, "is_error": True}


# ---------------------------------------------------------------- stats backfill
def backfill_stats() -> None:
    """Compute only the stats for older runs (no LLM call)."""
    for run_id in db.runs_missing_stats():
        run = db.get_run(run_id)
        path = db.pcap_file(run["pcap_path"])
        if not path.exists():
            continue
        try:
            meta = CaptureMeta.model_validate_json(run["metadata"])
            with tempfile.TemporaryDirectory() as tmp:
                _, stats = build_report(path, Path(tmp), meta)
            db.update_run(run_id, stats=json.dumps(stats))
            log.info("stats backfilled for run %s", run_id)
        except Exception:  # noqa: BLE001
            log.exception("stats backfill failed for run %s", run_id)


class JobQueue:
    def __init__(self, workers: int):
        self.workers = workers
        self._q: queue.Queue[int | None] = queue.Queue()
        self._threads: list[threading.Thread] = []

    def start(self) -> None:
        pending = db.recover_pending()
        for run_id in pending:
            self._q.put(run_id)
        for i in range(self.workers):
            t = threading.Thread(target=self._loop, name=f"worker-{i}", daemon=True)
            t.start()
            self._threads.append(t)
        threading.Thread(target=backfill_stats, name="stats-backfill", daemon=True).start()
        log.info("%d workers started, re-queued runs: %d", self.workers, len(pending))

    def submit(self, run_id: int) -> None:
        self._q.put(run_id)

    def stop(self, timeout: float = 5) -> None:
        for _ in self._threads:
            self._q.put(None)
        for t in self._threads:
            t.join(timeout)

    def _loop(self) -> None:
        while (run_id := self._q.get()) is not None:
            process(run_id)
